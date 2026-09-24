"""
routes/notification.py
-----------------------
Notification system (admin bell + SSE stream), backed by Supabase.

Table used (see notification_schema.sql):
    id, record_type ('birth'|'death'|'marriage'), record_id,
    control_no, title, message, request_snapshot jsonb,
    is_read, created_at, read_at, read_by

NOTE: this module only handles the IN-APP notifications (bell icon / live
stream). It does NOT send emails or SMS. Those are sent from
routes/email_service.py and routes/sms_service.py, called by
routes/citizen_requests.py.

CHANGES IN THIS VERSION (behavior is otherwise identical):
  1. Boolean filters now go through _bool_filter() ("true"/"false" strings),
     the same convention used in birth/marriage/death routes, instead of
     passing raw Python bools into .eq().
  2. push_notification() no longer RAISES on a bad record_type. It logs and
     returns None. Callers invoke it after the transaction is already saved,
     so raising turned a notification problem into a 500 for the user.
  3. Optional login protection (NOTIFICATIONS_REQUIRE_LOGIN=1). Off by
     default so nothing breaks until the frontend sends cookies.
  4. SSE CORS origin is configurable (SSE_ALLOW_ORIGIN) instead of a
     hardcoded "*". Default is still "*" so current behavior is unchanged.
  5. mark_read rejects booleans in the ids list.

ENV VARIABLES (all optional):
  NOTIFICATIONS_REQUIRE_LOGIN=1   require session["username"] on every route
  SSE_ALLOW_ORIGIN=https://your-app.vercel.app   lock the SSE stream to your site
"""

import json
import logging
import os
import queue
import threading
import time
from datetime import datetime, timezone

from flask import Blueprint, Response, current_app, jsonify, request, session

from supabase_client import supabase

notifications_bp = Blueprint("notifications", __name__)

_module_logger = logging.getLogger(__name__)

VALID_RECORD_TYPES = ("birth", "death", "marriage")

# ─── SSE subscriber registry (pure in-memory, no DB involved) ────────────────
_lock:        threading.Lock   = threading.Lock()
_subscribers: set[queue.Queue] = set()


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _log_error(msg: str, *args) -> None:
    try:
        current_app.logger.error(msg, *args)
    except RuntimeError:  # outside an app context
        _module_logger.error(msg, *args)


def _bool_filter(value: bool) -> str:
    """PostgREST-safe lowercase boolean for .eq() filters."""
    return "true" if value else "false"


def _broadcast(payload: dict) -> None:
    """Push a JSON payload to every live SSE subscriber."""
    data = f"data: {json.dumps(payload)}\n\n"
    with _lock:
        dead: set[queue.Queue] = set()
        for q in _subscribers:
            try:
                q.put_nowait(data)
            except queue.Full:
                dead.add(q)
        if dead:
            _subscribers.difference_update(dead)


def _broadcast_keepalive() -> None:
    """Send an SSE comment keepalive to all subscribers."""
    msg = ": keepalive\n\n"
    with _lock:
        dead: set[queue.Queue] = set()
        for q in _subscribers:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.add(q)
        if dead:
            _subscribers.difference_update(dead)


def _relative_time(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = int((datetime.now(timezone.utc) - dt).total_seconds())
    if diff < 60:
        return "Just now"
    if diff < 3600:
        return f"{diff // 60}m ago"
    if diff < 86400:
        return f"{diff // 3600}h ago"
    return f"{diff // 86400}d ago"


def _coerce_datetime(value):
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, datetime) and value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def _parse_snapshot(raw) -> dict | None:
    """Supabase returns jsonb already parsed, but stay defensive."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None
    return None


def _row_to_payload(row: dict) -> dict:
    """Map a DB row from the `notification` table to the API payload shape."""
    created  = _coerce_datetime(row.get("created_at"))
    read_at  = _coerce_datetime(row.get("read_at"))
    snapshot = _parse_snapshot(row.get("request_snapshot"))

    return {
        "id":          row["id"],
        "record_type": (row.get("record_type") or "").lower(),
        "record_id":   row.get("record_id"),
        "control_no":  row.get("control_no"),
        "title":       row.get("title", ""),
        "msg":         row.get("message", ""),
        "snapshot":    snapshot,
        "is_read":     bool(row.get("is_read", False)),
        "unread":      not bool(row.get("is_read", False)),
        "time":        _relative_time(created) if created else "Unknown",
        "created_at":  created.isoformat() if created else None,
        "read_at":     read_at.isoformat() if read_at else None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# OPTIONAL LOGIN GUARD
#
# Off by default. Turn on with NOTIFICATIONS_REQUIRE_LOGIN=1 once your
# frontend sends cookies with these requests:
#   fetch(url, { credentials: "include" })
#   new EventSource(url, { withCredentials: true })
# and the backend CORS config allows credentials for your frontend origin.
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.before_request
def _require_login():
    if os.getenv("NOTIFICATIONS_REQUIRE_LOGIN", "0") != "1":
        return None
    if request.method == "OPTIONS":
        return None
    if session.get("username"):
        return None
    return jsonify({"success": False, "error": "Authentication required"}), 401


# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND KEEPALIVE THREAD
# ══════════════════════════════════════════════════════════════════════════════

_keepalive_started = False
_keepalive_lock    = threading.Lock()


def _start_keepalive_thread(app):
    """Call once after app startup. Safe to call multiple times."""
    global _keepalive_started
    with _keepalive_lock:
        if _keepalive_started:
            return
        _keepalive_started = True

    def _loop():
        while True:
            time.sleep(25)
            try:
                _broadcast_keepalive()
            except Exception:
                pass

    t = threading.Thread(target=_loop, daemon=True, name="sse-keepalive")
    t.start()


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC HELPER — import and call from birth / death / marriage routes
# ══════════════════════════════════════════════════════════════════════════════

def push_notification(
    *args,
    record_type:      str | None = None,   # "birth" | "death" | "marriage"
    record_id:        int | None = None,
    control_no:       str | None = None,
    title:            str | None = None,
    message:          str = "",
    notif_type:       str | None = None,   # legacy alias for record_type
    request_snapshot: dict | None = None,
    **kwargs,
) -> int | None:
    """
    Insert a row into `notification` and broadcast it via SSE.

    Never raises: a notification failure must not break the transaction that
    triggered it. Returns the new notification id, or None on failure.

    Tolerant of legacy call shapes: a leftover positional `connection` arg is
    ignored via *args, and `notif_type=` works as an alias for `record_type=`.

    Usage:
        from routes.notification import push_notification

        push_notification(
            record_type="birth",
            record_id=record_id,
            control_no=control_no,
            title="Birth Certificate Issued",
            message="Birth certificate issued for 'Juan Dela Cruz'",
        )
    """
    record_type = (record_type or notif_type or "").lower()
    if record_type not in VALID_RECORD_TYPES:
        _log_error(
            "push_notification skipped: record_type must be one of %s, got %r",
            VALID_RECORD_TYPES, record_type,
        )
        return None

    if not title:
        title = (message[:60] if message else "Notification")

    try:
        resp = supabase.table("notification").insert({
            "record_type":      record_type,
            "record_id":        record_id,
            "control_no":       control_no,
            "title":            title,
            "message":          message,
            "request_snapshot": request_snapshot,
        }).execute()

        row        = resp.data[0] if resp.data else {}
        new_id     = row.get("id")
        created_at = row.get("created_at") or datetime.now(timezone.utc).isoformat()

        _broadcast({
            "id":          new_id,
            "record_type": record_type,
            "record_id":   record_id,
            "control_no":  control_no,
            "title":       title,
            "msg":         message,
            "snapshot":    request_snapshot,
            "is_read":     False,
            "unread":      True,
            "time":        "Just now",
            "created_at":  created_at,
            "read_at":     None,
        })
        return new_id

    except Exception as exc:
        _log_error("push_notification error: %s", exc)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 1 — GET /api/notifications
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications", methods=["GET"])
def get_notifications():
    record_type = request.args.get("type", "").lower()
    unread_only = request.args.get("unread", "0") == "1"
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        limit = 50

    try:
        unread_resp  = supabase.table("notification").select("id", count="exact") \
            .eq("is_read", _bool_filter(False)).execute()
        unread_count = unread_resp.count or 0

        q = supabase.table("notification").select(
            "id, record_type, record_id, control_no, title, message, "
            "request_snapshot, is_read, created_at, read_at"
        )
        if record_type in VALID_RECORD_TYPES:
            q = q.eq("record_type", record_type)
        if unread_only:
            q = q.eq("is_read", _bool_filter(False))
        rows = q.order("created_at", desc=True).limit(limit).execute().data or []

        return jsonify({
            "success":       True,
            "unread_count":  unread_count,
            "notifications": [_row_to_payload(r) for r in rows],
        })

    except Exception as exc:
        _log_error("GET /api/notifications error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 1b — GET /api/notifications/unread-count
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/unread-count", methods=["GET"])
def get_unread_count():
    try:
        resp = supabase.table("notification").select("id", count="exact") \
            .eq("is_read", _bool_filter(False)).execute()
        return jsonify({"success": True, "unread_count": resp.count or 0})
    except Exception as exc:
        _log_error("GET /api/notifications/unread-count error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 2 — POST /api/notifications/read
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/read", methods=["POST"])
def mark_read():
    body = request.get_json(silent=True) or {}
    ids  = body.get("ids")

    if ids is None:
        return jsonify({"success": False, "error": "Missing 'ids' in body"}), 400

    now = datetime.now(timezone.utc).isoformat()

    try:
        if ids == "all":
            resp = supabase.table("notification").update(
                {"is_read": True, "read_at": now}
            ).eq("is_read", _bool_filter(False)).execute()
        elif isinstance(ids, list) and len(ids) > 0:
            if not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
                return jsonify({"success": False, "error": "ids must be a list of ints"}), 400
            resp = supabase.table("notification").update(
                {"is_read": True, "read_at": now}
            ).in_("id", ids).eq("is_read", _bool_filter(False)).execute()
        else:
            return jsonify({
                "success": False,
                "error":   "ids must be 'all' or a non-empty list of ints",
            }), 400

        updated = len(resp.data or [])

        _broadcast({"event": "read", "ids": ids, "read_at": now})

        return jsonify({"success": True, "updated": updated})

    except Exception as exc:
        _log_error("POST /api/notifications/read error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 3 — GET /api/notifications/summary
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/summary", methods=["GET"])
def get_summary():
    try:
        result = {}
        total  = 0

        for rtype in VALID_RECORD_TYPES:
            unread_resp = supabase.table("notification").select("id", count="exact") \
                .eq("record_type", rtype).eq("is_read", _bool_filter(False)).execute()
            unread = unread_resp.count or 0
            total += unread

            recent_resp = supabase.table("notification").select(
                "id, record_type, record_id, control_no, title, message, "
                "request_snapshot, is_read, created_at, read_at"
            ).eq("record_type", rtype).eq("is_read", _bool_filter(False)) \
             .order("created_at", desc=True).limit(5).execute()

            result[rtype] = {
                "unread": unread,
                "recent": [_row_to_payload(r) for r in (recent_resp.data or [])],
            }

        return jsonify({"success": True, "total_unread": total, "by_type": result})

    except Exception as exc:
        _log_error("GET /api/notifications/summary error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 4 — GET /api/notifications/<notif_id>
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/<int:notif_id>", methods=["GET"])
def get_notification_detail(notif_id: int):
    auto_read = request.args.get("mark_read", "0") == "1"

    try:
        rows = supabase.table("notification").select(
            "id, record_type, record_id, control_no, title, message, "
            "request_snapshot, is_read, created_at, read_at"
        ).eq("id", notif_id).limit(1).execute().data or []

        if not rows:
            return jsonify({"success": False, "error": "Notification not found"}), 404

        notif = rows[0]

        if auto_read and not notif.get("is_read"):
            now = datetime.now(timezone.utc).isoformat()
            supabase.table("notification").update(
                {"is_read": True, "read_at": now}
            ).eq("id", notif_id).execute()
            notif["is_read"] = True
            notif["read_at"] = now

        return jsonify({"success": True, "notification": _row_to_payload(notif)})

    except Exception as exc:
        _log_error("GET /api/notifications/%s error: %s", notif_id, exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 5 — GET /api/notifications/records/<notif_id>
#
# CAUTION: this looks up notification.record_id in birth_records /
# death_records / marriage_records. If notifications created for ONLINE
# REQUESTS store the id of a civil_registry_request row in record_id, this
# will return the wrong record (or none). Check what citizen_requests.py
# passes as record_id.
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/records/<int:notif_id>", methods=["GET"])
def get_linked_record(notif_id: int):
    try:
        rows = supabase.table("notification").select(
            "id, record_type, record_id, control_no"
        ).eq("id", notif_id).limit(1).execute().data or []

        if not rows:
            return jsonify({"success": False, "error": "Notification not found"}), 404

        notif       = rows[0]
        record_type = (notif.get("record_type") or "").lower()
        record_id   = notif.get("record_id")

        table_map = {
            "birth":    "birth_records",
            "death":    "death_records",
            "marriage": "marriage_records",
        }
        table  = table_map.get(record_type)
        record = None

        if table and record_id:
            recs = supabase.table(table).select("*").eq("id", record_id).limit(1).execute().data or []
            record = recs[0] if recs else None
            if record:
                # keep this endpoint light: drop the big PDF blobs
                record.pop("pdf_data", None)   # birth
                record.pop("pdf_file", None)   # death

        return jsonify({
            "success":     True,
            "record_type": record_type,
            "record_id":   record_id,
            "control_no":  notif.get("control_no"),
            "record":      record,
        })

    except Exception as exc:
        _log_error("GET /api/notifications/records/%s error: %s", notif_id, exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 6 — DELETE /api/notifications/<notif_id>
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/<int:notif_id>", methods=["DELETE"])
def delete_notification(notif_id: int):
    try:
        resp    = supabase.table("notification").delete().eq("id", notif_id).execute()
        deleted = resp.data or []

        if not deleted:
            return jsonify({"success": False, "error": "Notification not found"}), 404

        _broadcast({"event": "deleted", "id": notif_id})
        return jsonify({"success": True, "deleted": notif_id})

    except Exception as exc:
        _log_error("DELETE /api/notifications/%s error: %s", notif_id, exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 7 — GET /api/notifications/stream  (SSE)
#
# Note: subscribers live in this process's memory. That works with ONE
# worker process (or threads). With several gunicorn workers, or on a
# serverless host, a notification created in one worker will not reach
# streams connected to another. Use `gunicorn --workers 1 --threads 8`
# (or gevent), or move to Supabase Realtime for multi-worker setups.
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/stream")
def sse_stream():
    try:
        _start_keepalive_thread(current_app._get_current_object())
    except Exception:
        pass

    client_q: queue.Queue = queue.Queue(maxsize=200)

    with _lock:
        _subscribers.add(client_q)

    def generate():
        yield f"data: {json.dumps({'event': 'connected'})}\n\n"
        try:
            while True:
                try:
                    msg = client_q.get(timeout=25)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _lock:
                _subscribers.discard(client_q)

    allow_origin = os.getenv("SSE_ALLOW_ORIGIN", "*")
    headers = {
        "Cache-Control":               "no-cache",
        "X-Accel-Buffering":           "no",
        "Access-Control-Allow-Origin": allow_origin,
        "Connection":                  "keep-alive",
    }
    if allow_origin != "*":
        # browsers only send cookies to a specific origin, never to "*"
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"

    return Response(generate(), mimetype="text/event-stream", headers=headers)