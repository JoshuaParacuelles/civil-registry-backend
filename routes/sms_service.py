"""
routes/sms_service.py
-----------------------
Sends status-update SMS notifications directly to the citizen/requester's
mobile number (collected on the public request form as
`requester_telephone`, stored on the civil_registry_request row), using
the Semaphore SMS API (https://semaphore.co) — the standard SMS gateway
for Philippine-based services.

Configure this in your .env / Render environment variables:

    SEMAPHORE_API_KEY=your-semaphore-api-key
    SEMAPHORE_SENDER_NAME=YourApprovedName   # optional — only set this if
                                              # you have a registered/approved
                                              # sender name on your Semaphore
                                              # account. Omit it to use
                                              # Semaphore's default sender.

If SEMAPHORE_API_KEY isn't set, or the requester has no usable phone
number on file, sending is skipped and logged — it never raises, so a
missing/broken SMS configuration can't break the status-update endpoint
itself (same contract as email_service.send_status_update_email).

Requires the `requests` package (add to requirements.txt if not already
present).
"""

import os
import re

import requests

SEMAPHORE_API_KEY = os.environ.get("SEMAPHORE_API_KEY")
SEMAPHORE_SENDER_NAME = os.environ.get("SEMAPHORE_SENDER_NAME")  # optional
SEMAPHORE_URL = "https://api.semaphore.co/api/v4/messages"


def _normalize_ph_number(raw_number):
    """
    Semaphore accepts PH mobile numbers as 09XXXXXXXXX or 639XXXXXXXXX.
    Strips spaces/dashes/parentheses and normalizes whatever format was
    saved from the request form (local "09..." or already-international
    "639...", or a bare "9..." without the leading 0) into the
    "639XXXXXXXXX" form Semaphore expects. Returns None if the result
    doesn't look like a valid PH mobile number.
    """
    if not raw_number:
        return None
    digits = re.sub(r"[^\d]", "", str(raw_number))
    if digits.startswith("0") and len(digits) == 11:
        digits = "63" + digits[1:]
    elif digits.startswith("63") and len(digits) == 12:
        pass
    elif digits.startswith("9") and len(digits) == 10:
        digits = "63" + digits
    else:
        return None
    return digits


def send_status_update_sms(to_number, message):
    """
    Sends a plain-text SMS to `to_number` via Semaphore.

    Returns True on success (Semaphore accepted the message for sending),
    False otherwise. Never raises — treat this as best-effort so a status
    update still succeeds even if SMS sending fails or isn't configured.
    """
    number = _normalize_ph_number(to_number)

    if not number:
        print("[sms_service] No usable requester_telephone on file for this request — skipping SMS notification.")
        return False

    if not SEMAPHORE_API_KEY:
        print("[sms_service] SEMAPHORE_API_KEY not set — skipping SMS notification.")
        return False

    payload = {
        "apikey": SEMAPHORE_API_KEY,
        "number": number,
        "message": message,
    }
    if SEMAPHORE_SENDER_NAME:
        payload["sendername"] = SEMAPHORE_SENDER_NAME

    try:
        resp = requests.post(SEMAPHORE_URL, data=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # Semaphore returns a list of message objects on success, e.g.
        # [{"message_id": 123, "status": "Pending", ...}]. Any response
        # with a message_id is treated as accepted for sending.
        if isinstance(data, list) and data and data[0].get("message_id"):
            print(f"[sms_service] Status-update SMS queued for {number} (message_id={data[0].get('message_id')})")
            return True
        print(f"[sms_service] Unexpected Semaphore response for {number}: {data}")
        return False
    except Exception as e:
        print(f"[sms_service] Failed to send status-update SMS to {number}: {e}")
        return False