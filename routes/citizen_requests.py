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
form (`requester_email`) via email_service.send_status_update_email, and
text them at `requester_telephone` via sms_service.send_status_update_sms.
No row is written to `notification` for a status update, so the admin
bell stays quiet for these.

Only Pending Review, Being Processed, and Completed are selectable
statuses (REJECTED remains available as a separate terminal state).

CHANGED (fix for HTTP 500 on PATCH /api/requests/<id>/status):
  * The email / SMS / audit-log steps used to run inline, one after the
    other, inside the same try/except that returns a 500. If any of them
    hung (Render's free tier blocks outbound SMTP ports 25/465/587, so
    smtplib waited on a connection that never came, until the gunicorn
    worker was killed) or raised (e.g. sms_service or record_action
    throwing), the citizen-facing update looked like it failed even
    though the DB row had already been saved.
  * Email and SMS now run in parallel worker threads with a hard overall
    timeout (NOTIFY_TIMEOUT_SECONDS). A timeout or exception in either
    just counts as "not sent" — it can never turn into a 500.
  * The audit-log write is wrapped separately so a logging problem can't
    fail the request either.
  * The DB update has its own try/except, so if the save itself fails
    the response says so clearly (and the real traceback is printed to
    the server log) instead of a generic error.
  * Fixed has_signature in the detail endpoint: it used to read
    signature_path AFTER popping it, so it was always False.

CHANGED (fix: notify-channel selection was never actually applied):
  * The frontend's "Notify requester via" control already sends
    `notify_via` ("email" | "sms" | "both" | "none") in the PATCH body,
    but this endpoint used to ignore it completely and always attempted
    BOTH email and SMS regardless of what was picked — so the toggle in
    the UI didn't do anything server-side, and the success message never
    said which address/number was actually used.
  * `notify_via` is now read from the request body (defaulting to
    "both" for older clients that don't send it) and used to decide
    which channel(s) actually get a `to_email`/`to_number` — the
    channel(s) not selected are skipped rather than silently sent
    anyway.
  * The response's `message` (what the admin's success/notice toast
    displays) now includes the actual email address and/or phone number
    that was notified, e.g. "Citizen notified by SMS (09106616369)."
    instead of a generic "Citizen notified by SMS." with no identifying
    text/number. The JSON response also now includes `notify_via`,
    `notified_email`, and `notified_phone` for anything else that wants
    the raw values.
"""

import time
import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, request, jsonify, session

from supabase_client import supabase
from auth.Rolemanagement import is_admin, get_user_permissions
from .email_service import send_status_update_email
from .sms_service import send_status_update_sms
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

# Valid values for the "notify_via" field the frontend's channel toggle
# sends. Anything else (including a missing/old client that doesn't send
# it at all) falls back to "both", matching the previous behavior.
VALID_NOTIFY_VIA = {"email", "sms", "both", "none"}

# Permission key the frontend checks via hasAccess("citizen_requests").
# An admin (is_admin() == True) always passes regardless of this list.
REQUIRED_PERMISSION = "citizen_requests"

# Max total time (seconds) to wait for email + SMS together before giving
# up on them. Keep this comfortably below your gunicorn --timeout (30s by
# default) so the request always finishes and returns JSON.
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


def _send_notifications(to_email, subject, body, to_number, sms_message):
    """Send the email and SMS in parallel, with a hard overall timeout.

    Pass `to_email=None` and/or `to_number=None` to skip that channel
    entirely (used when notify_via didn't select it) — both
    send_status_update_email and send_status_update_sms already treat a
    missing/empty recipient as "skip, don't send" and simply return
    False, so this is safe without changing either of those functions.

    Returns (email_sent, sms_sent) as plain booleans. NEVER raises: a
    timeout or an exception in either channel is logged and counted as
    "not sent", so it can't break the status update.
    """
    executor = ThreadPoolExecutor(max_workers=2)
    futures = {
        "email": executor.submit(
            send_status_update_email,
            to_email=to_email,
            subject=subject,
            body=body,
        ),
        "sms": executor.submit(
            send_status_update_sms,
            to_number=to_number,
            message=sms_message,
        ),
    }

    results = {"email": False, "sms": False}
    deadline = time.monotonic() + NOTIFY_TIMEOUT_SECONDS

    for name, fut in futures.items():
        remaining = max(0.0, deadline - time.monotonic())
        try:
            results[name] = bool(fut.result(timeout=remaining))
        except FuturesTimeout:
            print(
                f"[citizen_requests] {name} notification did not finish within "
                f"{NOTIFY_TIMEOUT_SECONDS}s — giving up on it (status update is unaffected)."
            )
        except Exception as e:
            print(f"[citizen_requests] {name} notification raised: {e}")
            traceback.print_exc()

    # Don't block on a worker that's still stuck on a dead connection.
    executor.shutdown(wait=False)
    return results["email"], results["sms"]


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

    # Which channel(s) the admin picked in the "Notify requester via"
    # control. Missing/unrecognized values fall back to "both", which is
    # what this endpoint always did before that control existed.
    notify_via = (data.get("notify_via") or "").strip().lower()
    if notify_via not in VALID_NOTIFY_VIA:
        notify_via = "both"

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

        # ── 2. Email + SMS, in parallel, with a hard timeout. Never raises.
        #       Only the channel(s) selected via notify_via get an actual
        #       recipient — the other(s) get None, which both send
        #       functions already treat as "skip, nothing to send". ──
        requester_email = row.get("requester_email")
        requester_phone = row.get("requester_telephone")

        send_to_email = requester_email if notify_via in ("email", "both") else None
        send_to_phone = requester_phone if notify_via in ("sms", "both") else None

        if notify_via == "none":
            email_sent, sms_sent = False, False
        else:
            email_sent, sms_sent = _send_notifications(
                to_email=send_to_email,
                subject=f"{kind.title()} Certificate Request — {status_label}",
                body=message,
                to_number=send_to_phone,
                sms_message=message,
            )

        notified_via = []
        if email_sent:
            notified_via.append(f"email ({requester_email})")
        if sms_sent:
            notified_via.append(f"SMS ({requester_phone})")

        if notified_via:
            notify_status_message = f"Status updated. Citizen notified by {' and '.join(notified_via)}."
        elif notify_via == "none":
            notify_status_message = "Status updated. No notification was sent (none selected)."
        elif not requester_email and not requester_phone:
            notify_status_message = "Status updated, but no email or phone number is on file for this request — citizen was not notified."
        else:
            notify_status_message = "Status updated, but the notification (email/SMS) failed to send. Check server logs."

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
                "sms_sent": sms_sent,
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
            "sms_sent": sms_sent,
            "notified_email": requester_email if email_sent else None,
            "notified_phone": requester_phone if sms_sent else None,
            "message": notify_status_message,
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500