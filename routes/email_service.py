"""
email_service.py - Local Civil Registry, San Carlos City

Sends status-notification emails with the header logos rendered correctly
in Gmail, Outlook, etc.

TWO IMAGE MODES (set EMAIL_IMAGE_MODE in your .env):

  cid  (default) Logos are embedded inside the email itself. Works even when
                 your website is offline or you are testing on localhost.
                 Put the files in  backend/static/email/  (scc.png, lcr.jpg).

  url            Logos are loaded from your public website. Needs
                 PUBLIC_ASSET_URL=https://your-app.vercel.app and the images
                 placed in the frontend's public/ folder (NOT src/assets/,
                 because Vite renames those with a hash on every build).

REQUIRED .env VALUES:
  SMTP_HOST=smtp.gmail.com
  SMTP_PORT=587
  SMTP_USER=youraddress@gmail.com
  SMTP_PASSWORD=your-16-char-google-app-password
  EMAIL_FROM=youraddress@gmail.com            (optional, defaults to SMTP_USER)
  EMAIL_FROM_NAME=Local Civil Registry        (optional)
  EMAIL_IMAGE_MODE=cid                        (or url)
  PUBLIC_ASSET_URL=https://your-app.vercel.app  (only for url mode)

QUICK TEST (run from the backend/ folder):
  python routes/email_service.py someone@example.com
"""

import logging
import os
import smtplib
import sys
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from html import escape
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- config ---
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", "") or SMTP_USER
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "Local Civil Registry - San Carlos City")

EMAIL_IMAGE_MODE = os.getenv("EMAIL_IMAGE_MODE", "cid").strip().lower()
PUBLIC_ASSET_URL = os.getenv("PUBLIC_ASSET_URL", "").strip().rstrip("/")

# backend/static/email/
ASSET_DIR = Path(__file__).resolve().parent.parent / "static" / "email"

# (content-id, file name, alt text)
LOGOS = [
    ("scc_logo", "scc.png", "City of San Carlos seal"),
    ("lcr_logo", "lcr.jpg", "Local Civil Registry"),
]

STATUS_COLORS = {
    "pending review": "#b45309",
    "pending": "#b45309",
    "processing": "#1d4ed8",
    "approved": "#15803d",
    "ready for pickup": "#15803d",
    "released": "#15803d",
    "rejected": "#b91c1c",
    "declined": "#b91c1c",
}
DEFAULT_STATUS_COLOR = "#1e3a8a"


# ---------------------------------------------------------------- images ---
def _resolve_logos():
    """
    Returns (logos, attachments)
      logos:       [{"src": ..., "alt": ...}]  used to build <img> tags
      attachments: [(cid, Path)]               files to embed (cid mode only)
    Logos that cannot be found are skipped, so you never get a broken-image icon.
    """
    logos, attachments = [], []

    for cid, filename, alt in LOGOS:
        if EMAIL_IMAGE_MODE == "url":
            if not PUBLIC_ASSET_URL:
                logger.warning("EMAIL_IMAGE_MODE=url but PUBLIC_ASSET_URL is not set; skipping logos.")
                break
            logos.append({"src": f"{PUBLIC_ASSET_URL}/{filename}", "alt": alt})
        else:  # cid
            path = ASSET_DIR / filename
            if not path.is_file():
                logger.warning("Email logo not found: %s (skipped)", path)
                continue
            logos.append({"src": f"cid:{cid}", "alt": alt})
            attachments.append((cid, path))

    return logos, attachments


def _attach_inline_image(msg, cid, path):
    img = MIMEImage(path.read_bytes())
    img.add_header("Content-ID", f"<{cid}>")
    img.add_header("Content-Disposition", "inline", filename=path.name)
    msg.attach(img)


# -------------------------------------------------------------- template ---
def build_status_email(control_no, status, request_type="Marriage Certificate",
                       recipient_name=None, remarks=None):
    """Returns (subject, plain_text, html, attachments)."""
    control_no_h = escape(str(control_no))
    status_h = escape(str(status))
    type_h = escape(str(request_type))
    color = STATUS_COLORS.get(str(status).strip().lower(), DEFAULT_STATUS_COLOR)

    greeting = f"Dear {escape(recipient_name)}," if recipient_name else "Hello,"
    remarks_html = ""
    remarks_text = ""
    if remarks:
        remarks_html = (
            '<p style="margin:16px 0 0;padding:12px 14px;background:#f3f4f6;'
            'border-radius:6px;font-size:14px;color:#374151;">'
            f"<strong>Remarks:</strong> {escape(remarks)}</p>"
        )
        remarks_text = f"\nRemarks: {remarks}\n"

    logos, attachments = _resolve_logos()
    logo_cells = "".join(
        f'<td style="padding:0 8px;"><img src="{l["src"]}" alt="{escape(l["alt"])}" '
        f'width="80" height="80" style="display:block;border:0;width:80px;height:80px;'
        f'object-fit:contain;"></td>'
        for l in logos
    )
    logo_row = (
        f'<table role="presentation" align="center" cellpadding="0" cellspacing="0" '
        f'style="margin:0 auto 12px;"><tr>{logo_cells}</tr></table>'
        if logo_cells else ""
    )

    subject = f"{request_type} Request - {status}"

    html = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 0;">
    <tr><td align="center">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0"
             style="max-width:600px;width:100%;background:#ffffff;border-radius:10px;padding:28px;">
        <tr><td align="center">
          {logo_row}
          <div style="font-size:20px;font-weight:bold;color:#111827;">Local Civil Registry</div>
          <div style="font-size:14px;color:#6b7280;margin-top:2px;">San Carlos City</div>
          <hr style="border:0;border-top:1px solid #e5e7eb;margin:20px 0;">
        </td></tr>
        <tr><td style="color:#111827;font-size:16px;line-height:1.5;">
          <h2 style="margin:0 0 14px;font-size:22px;">{type_h} Request &mdash; {status_h}</h2>
          <p style="margin:0 0 10px;">{greeting}</p>
          <p style="margin:0;">Your {type_h.lower()} request
             (Control No: <strong>{control_no_h}</strong>) is now:
             <span style="display:inline-block;padding:3px 10px;border-radius:12px;
                          background:{color};color:#ffffff;font-size:14px;font-weight:bold;">{status_h}</span>
          </p>
          {remarks_html}
          <p style="margin:24px 0 0;font-size:12px;color:#9ca3af;">
            This is an automated message from the Local Civil Registry, San Carlos City.
            Please do not reply to this email.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    text = (
        f"{'Dear ' + recipient_name + ',' if recipient_name else 'Hello,'}\n\n"
        f"Your {request_type.lower()} request (Control No: {control_no}) is now: {status}.\n"
        f"{remarks_text}\n"
        "This is an automated message from the Local Civil Registry, San Carlos City."
    )

    return subject, text, html, attachments


# --------------------------------------------------------------- sending ---
def send_email(to_email, subject, text, html, attachments=None):
    """Low-level sender. Returns True on success, False on failure."""
    if not (SMTP_USER and SMTP_PASSWORD):
        logger.error("SMTP_USER / SMTP_PASSWORD are not configured.")
        return False
    if not to_email:
        logger.error("No recipient email address given.")
        return False

    # multipart/related  ->  holds the HTML body + the inline images
    #   multipart/alternative -> plain text + HTML versions
    msg = MIMEMultipart("related")
    msg["Subject"] = subject
    msg["From"] = formataddr((EMAIL_FROM_NAME, EMAIL_FROM))
    msg["To"] = to_email

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(text, "plain", "utf-8"))
    alt.attach(MIMEText(html, "html", "utf-8"))
    msg.attach(alt)

    for cid, path in (attachments or []):
        _attach_inline_image(msg, cid, path)

    try:
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
            server.starttls()
        with server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, [to_email], msg.as_string())
        logger.info("Email sent to %s (%s)", to_email, subject)
        return True
    except Exception:
        logger.exception("Failed to send email to %s", to_email)
        return False


def send_status_email(to_email, control_no, status, request_type="Marriage Certificate",
                      recipient_name=None, remarks=None):
    """
    Main function your routes should call, e.g.

        from routes.email_service import send_status_email
        send_status_email(citizen_email, "MR-20260923-00019", "Pending Review")
    """
    subject, text, html, attachments = build_status_email(
        control_no, status, request_type, recipient_name, remarks
    )
    return send_email(to_email, subject, text, html, attachments)


# ------------------------------------------------------------- self-test ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Usage: python routes/email_service.py recipient@example.com")
        sys.exit(1)
    ok = send_status_email(sys.argv[1], "MR-20260923-00019", "Pending Review")
    print("Sent!" if ok else "Failed - check the log above.")