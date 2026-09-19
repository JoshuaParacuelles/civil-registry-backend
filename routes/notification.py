"""
routes/notification.py
-----------------------
Notification system, converted from MySQL to Supabase.

Table used (see notification_schema.sql):
    id, record_type ('birth'|'death'|'marriage'), record_id,
    control_no, title, message, request_snapshot jsonb,
    is_read, created_at, read_at, read_by

CHANGE FROM DEATH/MARRIAGE CONVERSION PATTERN:
    push_notification() used to take a MySQL `conn` as its first arg and
    require `title`. Callers (birth.py in particular) were already calling
    it with a stray `connection` positional arg, no `title`, and an extra
    `notif_type=` kwarg that never existed in the old signature — that call
    path would have raised TypeError the moment it actually ran. The new
    signature below absorbs all of that via *args/**kwargs so nothing
    breaks, but the call sites in birth.py have been cleaned up to the
    correct form; consider doing the same anywhere else this is called.
"""

import json
import queue
import threading
import time
from datetime import datetime, timezone

from flask import Blueprint, Response, current_app, jsonify, request

from supabase_client import supabase  # NOTE: adjust import if your Supabase client lives elsewhere

notifications_bp = Blueprint("notifications", __name__)

# ─── SSE subscriber registry (unchanged — pure in-memory, no DB involved) ────
_lock:        threading.Lock   = threading.Lock()
_subscribers: set[queue.Queue] = set()


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════════════════════

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
    """Send SSE comment keepalive to all subscribers (no event emitted on client)."""
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
    """Supabase returns jsonb columns already parsed as dicts, but stay defensive."""
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
# BACKGROUND KEEPALIVE THREAD
# Sends SSE keepalive pings every 25s so proxies don't close idle connections.
# (The old MySQL "gone away" ping is gone — Supabase's REST client doesn't
# hold a long-lived connection that can go stale like that.)
# ══════════════════════════════════════════════════════════════════════════════

_keepalive_started = False
_keepalive_lock    = threading.Lock()


def _start_keepalive_thread(app):
    """Call once after app startup. Safe to call multiple times — idempotent."""
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
    notif_type:       str | None = None,    # legacy alias some call sites used instead of record_type
    request_snapshot: dict | None = None,
    **kwargs,
) -> int | None:
    """
    Insert a row into `notification` (Supabase) and broadcast it via SSE instantly.

    Tolerant of legacy call shapes: a leftover positional `connection` arg
    (from the MySQL days) is silently ignored via *args, and `notif_type=`
    is accepted as an alias for `record_type=`.

    Usage:
        from routes.notification import push_notification

        push_notification(
            record_type="birth",
            record_id=record_id,
            control_no=control_no,
            title="New Request",
            message="A new birth request was submitted.",
            request_snapshot={"requestor_name": "Juan Dela Cruz", ...},
        )
    """
    record_type = (record_type or notif_type or "").lower()
    if record_type not in ("birth", "death", "marriage"):
        raise ValueError(f"record_type must be birth/death/marriage, got: {record_type!r}")

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

        payload = {
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
        }
        _broadcast(payload)
        return new_id

    except Exception as exc:
        try:
            current_app.logger.error("push_notification error: %s", exc)
        except RuntimeError:
            print(f"[notifications] push_notification error: {exc}")
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
        unread_resp  = supabase.table("notification").select("id", count="exact").eq("is_read", False).execute()
        unread_count = unread_resp.count or 0

        q = supabase.table("notification").select(
            "id, record_type, record_id, control_no, title, message, request_snapshot, is_read, created_at, read_at"
        )
        if record_type in ("birth", "death", "marriage"):
            q = q.eq("record_type", record_type)
        if unread_only:
            q = q.eq("is_read", False)
        rows = q.order("created_at", desc=True).limit(limit).execute().data or []

        return jsonify({
            "success":       True,
            "unread_count":  unread_count,
            "notifications": [_row_to_payload(r) for r in rows],
        })

    except Exception as exc:
        current_app.logger.error("GET /api/notifications error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 1b — GET /api/notifications/unread-count  (lightweight badge poll)
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/unread-count", methods=["GET"])
def get_unread_count():
    try:
        resp = supabase.table("notification").select("id", count="exact").eq("is_read", False).execute()
        return jsonify({"success": True, "unread_count": resp.count or 0})
    except Exception as exc:
        current_app.logger.error("GET /api/notifications/unread-count error: %s", exc)
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
            ).eq("is_read", False).execute()
        elif isinstance(ids, list) and len(ids) > 0:
            if not all(isinstance(i, int) for i in ids):
                return jsonify({"success": False, "error": "ids must be a list of ints"}), 400
            resp = supabase.table("notification").update(
                {"is_read": True, "read_at": now}
            ).in_("id", ids).eq("is_read", False).execute()
        else:
            return jsonify({
                "success": False,
                "error":   "ids must be 'all' or a non-empty list of ints",
            }), 400

        updated = len(resp.data or [])

        _broadcast({"event": "read", "ids": ids, "read_at": now})

        return jsonify({"success": True, "updated": updated})

    except Exception as exc:
        current_app.logger.error("POST /api/notifications/read error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 3 — GET /api/notifications/summary
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/summary", methods=["GET"])
def get_summary():
    try:
        result = {}
        total  = 0

        for rtype in ("birth", "death", "marriage"):
            unread_resp = supabase.table("notification").select(
                "id", count="exact"
            ).eq("record_type", rtype).eq("is_read", False).execute()
            unread = unread_resp.count or 0
            total += unread

            recent_resp = supabase.table("notification").select(
                "id, record_type, record_id, control_no, title, message, request_snapshot, is_read, created_at, read_at"
            ).eq("record_type", rtype).eq("is_read", False).order(
                "created_at", desc=True
            ).limit(5).execute()

            result[rtype] = {
                "unread": unread,
                "recent": [_row_to_payload(r) for r in (recent_resp.data or [])],
            }

        return jsonify({"success": True, "total_unread": total, "by_type": result})

    except Exception as exc:
        current_app.logger.error("GET /api/notifications/summary error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 4 — GET /api/notifications/<notif_id>
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/<int:notif_id>", methods=["GET"])
def get_notification_detail(notif_id: int):
    auto_read = request.args.get("mark_read", "0") == "1"

    try:
        rows = supabase.table("notification").select(
            "id, record_type, record_id, control_no, title, message, request_snapshot, is_read, created_at, read_at"
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
        current_app.logger.error("GET /api/notifications/%s error: %s", notif_id, exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 5 — GET /api/notifications/records/<notif_id>
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

        # FIXED: the old map pointed at "*_requests" tables that never existed
        # in Supabase. These are the real table names from the birth/death/
        # marriage conversions.
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
            if record and "pdf_data" in record:
                record.pop("pdf_data", None)  # keep this endpoint light

        return jsonify({
            "success":     True,
            "record_type": record_type,
            "record_id":   record_id,
            "control_no":  notif.get("control_no"),
            "record":      record,
        })

    except Exception as exc:
        current_app.logger.error("GET /api/notifications/records/%s error: %s", notif_id, exc)
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
        current_app.logger.error("DELETE /api/notifications/%s error: %s", notif_id, exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 7 — GET /api/notifications/stream  (SSE)
# ══════════════════════════════════════════════════════════════════════════════

@notifications_bp.route("/api/notifications/stream")
def sse_stream():
    """
    Server-Sent Events endpoint. Each connected client gets new notifications
    pushed within milliseconds of push_notification() being called.
    """
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

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
            "Connection":                  "keep-alive",
        },
    )