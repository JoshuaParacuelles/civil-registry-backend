import os
import smtplib
import ssl
from email.message import EmailMessage

# CHANGED: trim whitespace on both values, and strip spaces out of the app
# password specifically. Gmail displays app passwords as four groups of
# four characters separated by spaces (e.g. "abcd efgh ijkl mnop"), and
# it's easy to paste that straight into an env var including the spaces.
# Gmail's SMTP login only accepts the 16 characters with no spaces, so this
# makes the code tolerant of either form. This does NOT fix a missing or
# wrong value — GMAIL_SENDER_EMAIL still has to be an actual email address,
# and GMAIL_SENDER_APP_PASSWORD still has to be set — it just removes one
# common copy-paste failure mode once those values are entered correctly.
GMAIL_SENDER_EMAIL = (os.environ.get("GMAIL_SENDER_EMAIL") or "").strip()
GMAIL_SENDER_APP_PASSWORD = (os.environ.get("GMAIL_SENDER_APP_PASSWORD") or "").replace(" ", "").strip()
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

    if not GMAIL_SENDER_EMAIL:
        print("[email_service] GMAIL_SENDER_EMAIL not set — skipping email notification.")
        return False

    # CHANGED: catch the specific misconfiguration seen on this project's
    # Render dashboard — an app password (with spaces, 19 chars) sitting in
    # GMAIL_SENDER_EMAIL instead of a real address. This can't be "fixed"
    # here (there's no real address to fall back to), but a clear log line
    # makes the actual problem obvious instead of failing lower down with a
    # confusing SMTP authentication error.
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
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(GMAIL_SENDER_EMAIL, GMAIL_SENDER_APP_PASSWORD)
            server.send_message(msg)
        print(f"[email_service] Status-update email sent to {to_email}")
        return True
    except Exception as e:
        print(f"[email_service] Failed to send status-update email to {to_email}: {e}")
        return False