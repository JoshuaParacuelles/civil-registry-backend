"""
routes/citizen_requests.py
---------------------------
Session-gated management of citizen certificate requests
(civil_registry_request table). This blueprint belongs to the MAIN app
(the one with /api/session, /api/logout, is_admin()/get_user_permissions())
— NOT to backend/request.py, which is a separate, unauthenticated Flask
process serving the public request website. That app keeps only the
public GET /api/track/<control_no> lookup; everything requiring staff
login lives here.

Uses is_admin(username) directly (same helper app.py's /api/session
already imports from auth.Rolemanagement) rather than a decorator, to
avoid depending on a require_admin() helper that may not exist yet.
Swap _staff_required() below for a proper permission-based decorator
once one is available.

Status updates email the citizen at the address they gave on the request
form (`requester_email`) via email_service.send_status_update_email.
No row is written to `notification` for a status update, so the admin
bell stays quiet for these.

Only Pending Review, Being Processed, and Completed are selectable
statuses (REJECTED remains available as a separate terminal state).

CHANGED (fix for HTTP 500 on PATCH /api/requests/<id>/status):
  * The email / audit-log steps used to run inline, one after the
    other, inside the same try/except that returns a 500. If any of them
    hung (Render's free tier blocks outbound SMTP ports 25/465/587, so
    smtplib waited on a connection that never came, until the gunicorn
    worker was killed) or raised (e.g. record_action throwing), the
    citizen-facing update looked like it failed even though the DB row
    had already been saved.
  * Email now runs in a worker thread with a hard timeout
    (NOTIFY_TIMEOUT_SECONDS). A timeout or exception there just counts
    as "not sent" — it can never turn into a 500.
  * The audit-log write is wrapped separately so a logging problem can't
    fail the request either.
  * The DB update has its own try/except, so if the save itself fails
    the response says so clearly (and the real traceback is printed to
    the server log) instead of a generic error.
  * Fixed has_signature in the detail endpoint: it used to read
    signature_path AFTER popping it, so it was always False.

CHANGED (notify-channel selection):
  * The frontend's "Notify requester via" control sends `notify_via` in
    the PATCH body; the endpoint reads it and only notifies when the
    channel was actually selected.
  * The response's `message` (what the admin's success/notice toast
    displays) includes the actual email address that was notified.

CHANGED (SMS removed — email only):
  * Semaphore SMS is a paid, prepaid service, so SMS notifications have
    been dropped. sms_service.py is no longer imported or used here (the
    file can be deleted, along with the SEMAPHORE_API_KEY /
    SEMAPHORE_SENDER_NAME environment variables).
  * `notify_via` now only accepts "email" or "none". Anything else —
    including "sms" / "both" from an older cached frontend, or a missing
    value — falls back to "email".
  * The response no longer contains `sms_sent` or `notified_phone`.
  * The requester's phone number is still stored, listed and returned
    everywhere else exactly as before; it just isn't texted.
"""

import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, request, jsonify, session

from supabase_client import supabase
from auth.Rolemanagement import is_admin, get_user_permissions
from .email_service import send_status_update_email
from logs.Audits import record_action

citizen_requests_bp = Blueprint("citizen_requests_bp", __name__)

REQUEST_TABLE = "civil_registry_request"

STATUS_ORDER = ["PENDING", "PROCESSING", "COMPLETED"]
STATUS_LABELS = {
    "PENDING": "Pending Review",
    "PROCESSING": "Being Processed",
    "COMPLETED": "Completed",
    "REJECTED": "Rejected",
}
ALL_STATUSES = list(STATUS_LABELS.keys())

# Valid values for the "notify_via" field the frontend sends. Anything
# else (including a missing/old client, or a stale "sms"/"both" value)
# falls back to "email".
VALID_NOTIFY_VIA = {"email", "none"}

# Permission key the frontend checks via hasAccess("citizen_requests").
# An admin (is_admin() == True) always passes regardless of this list.
REQUIRED_PERMISSION = "citizen_requests"

# Max time (seconds) to wait for the email before giving up on it. Keep
# this comfortably below your gunicorn --timeout (30s by default) so the
# request always finishes and returns JSON.
NOTIFY_TIMEOUT_SECONDS = 15


def get_user():
    return session.get("username", "System")


def _staff_required(fn):
    """Mirrors the is_admin()/get_user_permissions() check already used
    inline in app.py's /api/session and /api/current-user routes. Allows
    an admin unconditionally, or a non-admin whose permission list
    includes REQUIRED_PERMISSION — matching how PermissionContext.jsx's
    hasAccess() decides what to show on the frontend."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        username = session.get("username")
        if not username:
            return jsonify({"error": "Not logged in"}), 401
        if is_admin(username):
            return fn(*args, **kwargs)
        perms = get_user_permissions(username) or []
        if REQUIRED_PERMISSION in perms or "*" in perms:
            return fn(*args, **kwargs)
        return jsonify({"error": "Forbidden"}), 403
    return wrapper


def who(kind, r):
    if kind == "marriage":
        return f"{r.get('husband_fullname')} & {r.get('wife_maiden_name')}"
    p = "child" if kind == "birth" else "deceased"
    return f"{r.get(p + '_firstname') or ''} {r.get(p + '_surname') or ''}".strip()


def _send_email_notification(to_email, subject, body):
    """Send the status-update email in a worker thread, with a hard timeout.

    send_status_update_email already treats a missing/empty recipient as
    "skip, don't send" and simply returns False.

    Returns a plain boolean. NEVER raises: a timeout or an exception is
    logged and counted as "not sent", so it can't break the status update.
    """
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(
        send_status_update_email,
        to_email=to_email,
        subject=subject,
        body=body,
    )

    sent = False
    try:
        sent = bool(future.result(timeout=NOTIFY_TIMEOUT_SECONDS))
    except FuturesTimeout:
        print(
            f"[citizen_requests] email notification did not finish within "
            f"{NOTIFY_TIMEOUT_SECONDS}s — giving up on it (status update is unaffected)."
        )
    except Exception as e:
        print(f"[citizen_requests] email notification raised: {e}")
        traceback.print_exc()

    # Don't block on a worker that's still stuck on a dead connection.
    executor.shutdown(wait=False)
    return sent


def _safe_record_action(*args, **kwargs):
    """Audit logging is nice-to-have; it must never fail the request."""
    try:
        record_action(*args, **kwargs)
    except Exception as e:
        print(f"[citizen_requests] record_action failed (ignored): {e}")
        traceback.print_exc()


@citizen_requests_bp.route("/api/requests", methods=["GET"])
@_staff_required
def list_citizen_requests():
    record_type = request.args.get("type", "").strip().lower()
    status = request.args.get("status", "").strip().upper()
    search = request.args.get("search", "").strip()
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)

    try:
        query = supabase.table(REQUEST_TABLE).select(
            "id, record_type, control_no, status, num_copies, purposes, "
            "requester_name, requester_relationship, requester_telephone, "
            "created_at, updated_at, "
            "child_firstname, child_surname, "
            "deceased_firstname, deceased_surname, "
            "husband_fullname, wife_maiden_name",
            count="exact",
        )

        if record_type in ("birth", "death", "marriage"):
            query = query.eq("record_type", record_type)
        if status in ALL_STATUSES:
            query = query.eq("status", status)
        if search:
            safe = search.replace(",", " ").replace("(", " ").replace(")", " ")
            query = query.or_(
                f"control_no.ilike.%{safe}%,requester_name.ilike.%{safe}%,"
                f"child_firstname.ilike.%{safe}%,child_surname.ilike.%{safe}%,"
                f"deceased_firstname.ilike.%{safe}%,deceased_surname.ilike.%{safe}%,"
                f"husband_fullname.ilike.%{safe}%,wife_maiden_name.ilike.%{safe}%"
            )

        res = (
            query.order("created_at", desc=True)
            .order("id", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )

        rows = res.data or []
        for r in rows:
            kind = (r.get("record_type") or "birth").lower()
            r["who"] = who(kind, r)
            st = (r.get("status") or "PENDING").upper()
            r["status_label"] = STATUS_LABELS.get(st, st)

        return jsonify({"total": res.count or 0, "requests": rows})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@citizen_requests_bp.route("/api/requests/<int:record_id>", methods=["GET"])
@_staff_required
def get_citizen_request_detail(record_id):
    try:
        rows = supabase.table(REQUEST_TABLE).select("*").eq("id", record_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Request not found"}), 404
        row = rows[0]

        # Read signature_path BEFORE popping it (it used to be read after,
        # which meant has_signature was always False).
        has_signature = bool(row.get("signature_path"))
        row.pop("signature_path", None)

        kind = (row.get("record_type") or "birth").lower()
        row["who"] = who(kind, row)
        st = (row.get("status") or "PENDING").upper()
        row["status_label"] = STATUS_LABELS.get(st, st)
        row["has_signature"] = has_signature
        return jsonify(row)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@citizen_requests_bp.route("/api/requests/<int:record_id>/status", methods=["PATCH"])
@_staff_required
def update_citizen_request_status(record_id):
    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or "").strip().upper()
    note = (data.get("note") or "").strip() or None

    # Whether the admin wants the requester emailed. Only "email" or
    # "none" are valid now; missing/unrecognized values (including a
    # stale "sms" or "both" from an older cached frontend) fall back to
    # "email".
    notify_via = (data.get("notify_via") or "").strip().lower()
    if notify_via not in VALID_NOTIFY_VIA:
        notify_via = "email"

    if new_status not in ALL_STATUSES:
        return jsonify({"error": f"Invalid status. Must be one of: {', '.join(ALL_STATUSES)}"}), 400

    try:
        rows = supabase.table(REQUEST_TABLE).select("*").eq("id", record_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Request not found"}), 404
        row = rows[0]
        kind = (row.get("record_type") or "birth").lower()
        old_status = (row.get("status") or "PENDING").upper()

        if old_status == new_status:
            return jsonify({"error": f"Request is already {STATUS_LABELS.get(new_status, new_status)}."}), 400

        # ── 1. Save the new status. This is the only step that can fail
        #       the request; everything after it is best-effort. ──
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            supabase.table(REQUEST_TABLE).update({
                "status": new_status,
                "updated_at": now_iso,
            }).eq("id", record_id).execute()
        except Exception as db_err:
            print(f"[citizen_requests] Could not save status for request {record_id}: {db_err}")
            traceback.print_exc()
            return jsonify({"error": f"Could not save the new status: {db_err}"}), 500

        status_label = STATUS_LABELS.get(new_status, new_status)
        message = f"Your {kind} certificate request (Control No: {row.get('control_no')}) is now: {status_label}."
        if note:
            message += f" Note: {note}"

        # ── 2. Email, in a worker thread, with a hard timeout. Never raises. ──
        requester_email = row.get("requester_email")

        if notify_via == "none":
            email_sent = False
        else:
            email_sent = _send_email_notification(
                to_email=requester_email,
                subject=f"{kind.title()} Certificate Request — {status_label}",
                body=message,
            )

        if email_sent:
            notify_status_message = f"Status updated. Citizen notified by email ({requester_email})."
        elif notify_via == "none":
            notify_status_message = "Status updated. No notification was sent (none selected)."
        elif not requester_email:
            notify_status_message = "Status updated, but no email address is on file for this request — citizen was not notified."
        else:
            notify_status_message = "Status updated, but the email notification failed to send. Check server logs."

        # ── 3. Audit log (best-effort). ──
        _safe_record_action(
            "REQUEST_STATUS_UPDATE",
            f"Updated {kind} request {row.get('control_no')} from {old_status} to {new_status}",
            username=get_user(),
            meta={
                "record_id": record_id,
                "control_no": row.get("control_no"),
                "old_status": old_status,
                "new_status": new_status,
                "note": note,
                "notify_via": notify_via,
                "email_sent": email_sent,
            },
            ip=request.remote_addr,
        )

        return jsonify({
            "ok": True,
            "record_id": record_id,
            "control_no": row.get("control_no"),
            "old_status": old_status,
            "status": new_status,
            "status_label": status_label,
            "updated_at": now_iso,
            "notify_via": notify_via,
            "email_sent": email_sent,
            "notified_email": requester_email if email_sent else None,
            "message": notify_status_message,
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500