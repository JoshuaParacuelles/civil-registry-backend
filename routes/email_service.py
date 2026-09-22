"""
email_service.py
-----------------
Sends status-update emails directly to the citizen/requester's Gmail
address (collected on the public request form as `requester_email`,
stored on the civil_registry_request row).

Uses Gmail's SMTP relay. Configure these in your .env:

    GMAIL_SENDER_EMAIL=your-office-account@gmail.com
    GMAIL_SENDER_APP_PASSWORD=xxxxxxxxxxxxxxxx

GMAIL_SENDER_APP_PASSWORD must be a Gmail "App Password" (Google
Account -> Security -> 2-Step Verification -> App passwords), not the
account's normal login password — Gmail rejects SMTP logins with the
regular password when 2FA is enabled.

If these env vars aren't set, or the requester has no email on file,
sending is skipped and logged — it never raises, so a missing/broken
email configuration can't break the status-update endpoint itself.
"""

import os
import smtplib
import ssl
from email.message import EmailMessage

GMAIL_SENDER_EMAIL = os.environ.get("GMAIL_SENDER_EMAIL")
GMAIL_SENDER_APP_PASSWORD = os.environ.get("GMAIL_SENDER_APP_PASSWORD")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


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

    if not GMAIL_SENDER_EMAIL or not GMAIL_SENDER_APP_PASSWORD:
        print("[email_service] GMAIL_SENDER_EMAIL / GMAIL_SENDER_APP_PASSWORD not set — skipping email notification.")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = GMAIL_SENDER_EMAIL
    msg["To"] = to_email
    msg.set_content(body)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(GMAIL_SENDER_EMAIL, GMAIL_SENDER_APP_PASSWORD)
            server.send_message(msg)
        print(f"[email_service] Status-update email sent to {to_email}")
        return True
    except Exception as e:
        print(f"[email_service] Failed to send status-update email to {to_email}: {e}")
        return False