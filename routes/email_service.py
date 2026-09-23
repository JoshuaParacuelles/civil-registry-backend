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

CHANGED: every network call now has a timeout. Before, smtplib.SMTP(...)
had none, so on a host that silently drops SMTP traffic the request just
hung until the web worker was killed — which surfaced as a 500 on
PATCH /api/requests/<id>/status.
"""

import json
import os
import smtplib
import socket
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage

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
    Sends a plain-text email to `to_email`.

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