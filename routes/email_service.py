"""
routes/email_service.py
-----------------------
Best-effort status-update emails for citizen certificate requests.

Two ways to send, picked automatically:

1. Brevo HTTPS API  — used when BREVO_API_KEY is set. Goes over port 443,
   so it works on Render's FREE tier, which blocks outbound SMTP ports
   25/465/587 (that block is why Gmail SMTP hangs there).
2. Gmail SMTP       — used otherwise (works locally and on Render paid
   instances).

Environment variables
  Gmail SMTP:
    GMAIL_SENDER_EMAIL         the real Gmail address you send from
    GMAIL_SENDER_APP_PASSWORD  16-char Gmail app password (spaces are OK)
  Brevo (optional):
    BREVO_API_KEY              API key from Brevo
    BREVO_SENDER_EMAIL         a sender verified in Brevo (falls back to
                               GMAIL_SENDER_EMAIL if not set)
    BREVO_SENDER_NAME          display name (default "Local Civil Registry")
  Logos (optional):
    EMAIL_LOGO_BASE_URL        public URL where scc.png and lcr.jpg are hosted
                               (default https://civil-registry-scc.vercel.app,
                               i.e. the files in the frontend's public/ folder)

CHANGED (timeouts): every network call now has a timeout. Before,
smtplib.SMTP(...) had none, so on a host that silently drops SMTP traffic
the request just hung until the web worker was killed — which surfaced as
a 500 on PATCH /api/requests/<id>/status.

CHANGED (logos): status-update emails are now sent as HTML with the
SCC (scc.png) and Local Civil Registry (lcr.jpg) logos in the header. The
plain-text version is still included as a fallback for mail clients that
don't show HTML. The logos must be publicly reachable, so both files live
in the frontend's public/ folder and are loaded from EMAIL_LOGO_BASE_URL.
"""

import json
import os
import smtplib
import socket
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage
from html import escape as _html_escape

# Whitespace is trimmed on both values, and spaces are stripped from the app
# password (Gmail shows it as four groups of four, "abcd efgh ijkl mnop",
# but SMTP login only accepts the 16 characters without spaces).
GMAIL_SENDER_EMAIL = (os.environ.get("GMAIL_SENDER_EMAIL") or "").strip()
GMAIL_SENDER_APP_PASSWORD = (os.environ.get("GMAIL_SENDER_APP_PASSWORD") or "").replace(" ", "").strip()
SMTP_HOST = (os.environ.get("SMTP_HOST") or "smtp.gmail.com").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT") or 587)

BREVO_API_KEY = (os.environ.get("BREVO_API_KEY") or "").strip()
BREVO_SENDER_EMAIL = (os.environ.get("BREVO_SENDER_EMAIL") or GMAIL_SENDER_EMAIL).strip()
BREVO_SENDER_NAME = (os.environ.get("BREVO_SENDER_NAME") or "Local Civil Registry").strip()
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

# Seconds. Keep these small so a blocked/unreachable server fails fast.
SMTP_TIMEOUT_SECONDS = 10
HTTP_TIMEOUT_SECONDS = 10

# Where the logo images are served from. Email clients can't read files
# from your project folder, so these must be public https URLs. scc.png and
# lcr.jpg sit in the frontend's public/ folder, which Vercel serves from
# the site root.
EMAIL_LOGO_BASE_URL = (
    os.environ.get("EMAIL_LOGO_BASE_URL") or "https://civil-registry-scc.vercel.app"
).strip().rstrip("/")
SCC_LOGO_URL = f"{EMAIL_LOGO_BASE_URL}/scc.png"
LCR_LOGO_URL = f"{EMAIL_LOGO_BASE_URL}/lcr.jpg"


def _build_html_email(subject, body):
    """Wraps the message in a simple branded HTML layout with both logos.

    Everything the caller supplied is HTML-escaped, so a note typed by staff
    (e.g. containing < or &) can't break the layout. Uses table layout and
    inline styles because that's what mail clients render reliably.
    """
    safe_subject = _html_escape(subject or "")
    safe_body = _html_escape(body or "").replace("\n", "<br>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_subject}</title>
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f1f5f9;padding:24px 12px;">
  <tr>
    <td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:560px;background-color:#ffffff;border:1px solid #e2e8f0;border-radius:12px;">
        <tr>
          <td align="center" style="padding:28px 24px 8px 24px;">
            <img src="{SCC_LOGO_URL}" alt="San Carlos City" height="72" style="display:inline-block;border:0;height:72px;width:auto;margin:0 8px;">
            <img src="{LCR_LOGO_URL}" alt="Local Civil Registry" height="72" style="display:inline-block;border:0;height:72px;width:auto;margin:0 8px;">
          </td>
        </tr>
        <tr>
          <td align="center" style="padding:4px 24px 16px 24px;font-family:Arial,Helvetica,sans-serif;">
            <div style="font-size:16px;font-weight:bold;color:#0f172a;">Local Civil Registry</div>
            <div style="font-size:13px;color:#64748b;">San Carlos City</div>
          </td>
        </tr>
        <tr>
          <td style="padding:0 24px;">
            <div style="border-top:1px solid #e2e8f0;font-size:0;line-height:0;">&nbsp;</div>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 28px 8px 28px;font-family:Arial,Helvetica,sans-serif;">
            <h2 style="margin:0 0 12px 0;font-size:18px;color:#0f172a;">{safe_subject}</h2>
            <p style="margin:0;font-size:15px;line-height:1.6;color:#334155;">{safe_body}</p>
          </td>
        </tr>
        <tr>
          <td style="padding:20px 28px 28px 28px;font-family:Arial,Helvetica,sans-serif;">
            <p style="margin:0;font-size:12px;line-height:1.5;color:#94a3b8;">This is an automated message from the Local Civil Registry, San Carlos City.</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>"""


def _send_via_brevo(to_email, subject, body):
    """Send through Brevo's HTTPS API. Returns True/False, never raises."""
    if "@" not in BREVO_SENDER_EMAIL:
        print(
            "[email_service] BREVO_API_KEY is set but BREVO_SENDER_EMAIL "
            f"(or GMAIL_SENDER_EMAIL) is not a valid address (got: {BREVO_SENDER_EMAIL!r}) "
            "— skipping email notification."
        )
        return False

    payload = json.dumps({
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": _build_html_email(subject, body),
        "textContent": body,
    }).encode("utf-8")

    req = urllib.request.Request(
        BREVO_API_URL,
        data=payload,
        method="POST",
        headers={
            "api-key": BREVO_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            ok = 200 <= resp.status < 300
        if ok:
            print(f"[email_service] Status-update email sent to {to_email} (Brevo)")
        else:
            print(f"[email_service] Brevo returned unexpected status {resp.status} for {to_email}")
        return ok
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        print(f"[email_service] Brevo rejected the email to {to_email}: HTTP {e.code} {detail}")
        return False
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        print(f"[email_service] Could not reach Brevo (timeout/network): {e}")
        return False
    except Exception as e:
        print(f"[email_service] Unexpected error sending via Brevo to {to_email}: {e}")
        return False


def _send_via_gmail_smtp(to_email, subject, body):
    """Send through Gmail SMTP. Returns True/False, never raises."""
    if not GMAIL_SENDER_EMAIL:
        print("[email_service] GMAIL_SENDER_EMAIL not set — skipping email notification.")
        return False

    # Catch the misconfiguration where the app password (with spaces) was
    # pasted into GMAIL_SENDER_EMAIL instead of a real address.
    if "@" not in GMAIL_SENDER_EMAIL:
        print(
            "[email_service] GMAIL_SENDER_EMAIL does not look like an email "
            f"address (got: {GMAIL_SENDER_EMAIL!r}). Set it to the real Gmail "
            "address you're sending from, and put the app password in "
            "GMAIL_SENDER_APP_PASSWORD instead — skipping email notification."
        )
        return False

    if not GMAIL_SENDER_APP_PASSWORD:
        print("[email_service] GMAIL_SENDER_APP_PASSWORD not set — skipping email notification.")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = GMAIL_SENDER_EMAIL
    msg["To"] = to_email
    msg.set_content(body)
    msg.add_alternative(_build_html_email(subject, body), subtype="html")

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
            server.starttls(context=context)
            server.login(GMAIL_SENDER_EMAIL, GMAIL_SENDER_APP_PASSWORD)
            server.send_message(msg)
        print(f"[email_service] Status-update email sent to {to_email}")
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(
            "[email_service] Gmail rejected the login. Check GMAIL_SENDER_EMAIL / "
            f"GMAIL_SENDER_APP_PASSWORD (needs a Google app password, 2-Step Verification on): {e}"
        )
        return False
    except (socket.timeout, TimeoutError, ConnectionError, OSError) as e:
        print(
            f"[email_service] Could not connect to {SMTP_HOST}:{SMTP_PORT} within "
            f"{SMTP_TIMEOUT_SECONDS}s ({e}). If this runs on Render's free tier, outbound "
            "SMTP ports 25/465/587 are blocked — set BREVO_API_KEY to send over HTTPS "
            "instead, or upgrade the instance."
        )
        return False
    except Exception as e:
        print(f"[email_service] Failed to send status-update email to {to_email}: {e}")
        return False


def send_status_update_email(to_email, subject, body):
    """
    Sends an email (HTML with logos, plus a plain-text fallback) to `to_email`.

    Returns True on success, False otherwise. Never raises — treat this
    as best-effort so a status update still succeeds even if email
    sending fails or isn't configured.
    """
    if not to_email:
        print("[email_service] No requester_email on file for this request — skipping email notification.")
        return False

    try:
        if BREVO_API_KEY:
            return _send_via_brevo(to_email, subject, body)
        return _send_via_gmail_smtp(to_email, subject, body)
    except Exception as e:
        # Belt and braces: nothing above should raise, but this function's
        # contract is that it never does.
        print(f"[email_service] Unexpected error: {e}")
        return False