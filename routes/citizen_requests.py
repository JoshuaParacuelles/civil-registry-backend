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

CHANGED: a status update ("PROCESSING", "READY_FOR_PICKUP",
"COMPLETED", etc.) used to call push_notification(...) into the shared
`notification` table, which showed up in the ADMIN bell in Home.jsx.
That's backwards — the admin is the one performing the update and
doesn't need to be notified about their own action, and the citizen
(who has no login) never saw it at all. Status updates now instead
email the citizen directly at the Gmail address they gave on the
request form (`requester_email`), via email_service.send_status_update_email.
No row is written to `notification` for a status update anymore, so
the admin bell stays quiet for these.

CHANGED (SMS): status updates now ALSO text the citizen at the mobile
number they gave on the request form (`requester_telephone`), via
sms_service.send_status_update_sms (Semaphore). Email and SMS are both
best-effort and independent of each other — one failing/being
unconfigured never blocks the other or the status update itself (the
DB row is already committed before either is attempted).
"""

from functools import wraps
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, session

from supabase_client import supabase
from auth.Rolemanagement import is_admin, get_user_permissions
from .email_service import send_status_update_email
from .sms_service import send_status_update_sms
from logs.Audits import record_action

citizen_requests_bp = Blueprint("citizen_requests_bp", __name__)

REQUEST_TABLE = "civil_registry_request"

STATUS_ORDER = ["PENDING", "PROCESSING", "READY_FOR_PICKUP", "COMPLETED"]
STATUS_LABELS = {
    "PENDING": "Pending Review",
    "PROCESSING": "Being Processed",
    "READY_FOR_PICKUP": "Ready for Pickup",
    "COMPLETED": "Completed",
    "REJECTED": "Rejected",
}
ALL_STATUSES = list(STATUS_LABELS.keys())

# Permission key the frontend checks via hasAccess("citizen_requests").
# An admin (is_admin() == True) always passes regardless of this list.
REQUIRED_PERMISSION = "citizen_requests"


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
        return jsonify({"error": str(e)}), 500


@citizen_requests_bp.route("/api/requests/<int:record_id>", methods=["GET"])
@_staff_required
def get_citizen_request_detail(record_id):
    try:
        rows = supabase.table(REQUEST_TABLE).select("*").eq("id", record_id).limit(1).execute().data
        if not rows:
            return jsonify({"error": "Request not found"}), 404
        row = rows[0]
        row.pop("signature_path", None)
        kind = (row.get("record_type") or "birth").lower()
        row["who"] = who(kind, row)
        st = (row.get("status") or "PENDING").upper()
        row["status_label"] = STATUS_LABELS.get(st, st)
        row["has_signature"] = bool(rows[0].get("signature_path"))
        return jsonify(row)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@citizen_requests_bp.route("/api/requests/<int:record_id>/status", methods=["PATCH"])
@_staff_required
def update_citizen_request_status(record_id):
    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or "").strip().upper()
    note = (data.get("note") or "").strip() or None

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

        now_iso = datetime.now(timezone.utc).isoformat()
        supabase.table(REQUEST_TABLE).update({
            "status": new_status,
            "updated_at": now_iso,
        }).eq("id", record_id).execute()

        who_name = who(kind, row)
        status_label = STATUS_LABELS.get(new_status, new_status)
        message = f"Your {kind} certificate request (Control No: {row.get('control_no')}) is now: {status_label}."
        if note:
            message += f" Note: {note}"

        # Email: best-effort, sent to the Gmail address the citizen gave
        # on the request form. A failed/unconfigured email never blocks
        # the status update itself (the DB row above is already
        # committed), but we DO capture the real True/False result here
        # so the response and audit log reflect what actually happened.
        requester_email = row.get("requester_email")
        email_sent = send_status_update_email(
            to_email=requester_email,
            subject=f"{kind.title()} Certificate Request — {status_label}",
            body=message,
        )

        # SMS: same best-effort contract as email, sent to the mobile
        # number the citizen gave on the request form, via Semaphore.
        requester_phone = row.get("requester_telephone")
        sms_sent = send_status_update_sms(
            to_number=requester_phone,
            message=message,
        )

        notified_via = []
        if email_sent:
            notified_via.append("email")
        if sms_sent:
            notified_via.append("SMS")

        if notified_via:
            notify_status_message = f"Status updated. Citizen notified by {' and '.join(notified_via)}."
        elif not requester_email and not requester_phone:
            notify_status_message = "Status updated, but no email or phone number is on file for this request — citizen was not notified."
        else:
            notify_status_message = "Status updated, but the notification (email/SMS) failed to send. Check server logs."

        record_action(
            "REQUEST_STATUS_UPDATE",
            f"Updated {kind} request {row.get('control_no')} from {old_status} to {new_status}",
            username=get_user(),
            meta={
                "record_id": record_id,
                "control_no": row.get("control_no"),
                "old_status": old_status,
                "new_status": new_status,
                "note": note,
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
            "email_sent": email_sent,
            "sms_sent": sms_sent,
            "message": notify_status_message,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500