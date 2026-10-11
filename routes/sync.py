"""Offline replay support (idempotent, claim-first).

Every replayed request carries X-Offline-Op-Id. Before the route runs, that id
is CLAIMED in sync_operations. op_id is the primary key, so only one request
can win the claim:

  - claim won                -> the route runs; 2xx marks the row 'applied',
                                anything else releases the claim so a retry works
  - row already 'applied'    -> 200 {"duplicate": true}; the route does NOT run again
  - row still 'processing'   -> 503; the browser retries later
  - stale 'processing' row   -> released after CLAIM_STALE_SECONDS and re-claimed
                                (covers a worker that crashed mid-request)

X-Offline-Created-At carries the real time the user acted (used by now_ph()).
"""
import time
from datetime import datetime, timezone, timedelta

from flask import g, jsonify, request, session

from supabase_client import supabase

TABLE = "sync_operations"
STATUS_PROCESSING = "processing"
STATUS_APPLIED = "applied"
CLAIM_STALE_SECONDS = 300


def _manila_naive(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).replace(tzinfo=None) + timedelta(hours=8)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_duplicate_error(e: Exception) -> bool:
    text = str(e).lower()
    return "23505" in text or "duplicate key" in text or "unique" in text


def _load_claim(op_id: str):
    rows = (
        supabase.table(TABLE)
        .select("op_id, status, claimed_at")
        .eq("op_id", op_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    return rows[0] if rows else None


def _is_stale(row: dict) -> bool:
    try:
        raw = str(row.get("claimed_at") or "").replace("Z", "+00:00")
        claimed = datetime.fromisoformat(raw)
        if claimed.tzinfo is None:
            claimed = claimed.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - claimed).total_seconds() > CLAIM_STALE_SECONDS
    except Exception:
        return False  # unreadable timestamp: never assume stale (protects against duplicates)


def _try_claim(op_id: str, user_id: str):
    """Returns (won, existing_row)."""
    try:
        supabase.table(TABLE).insert({
            "op_id": op_id,
            "status": STATUS_PROCESSING,
            "user_id": user_id,
            "claimed_at": _now_iso(),
        }).execute()
        return True, None
    except Exception as e:
        if not _is_duplicate_error(e):
            raise
    return False, _load_claim(op_id)


def _release_claim(op_id: str) -> None:
    supabase.table(TABLE).delete().eq("op_id", op_id).eq("status", STATUS_PROCESSING).execute()


def _mark_applied(op_id: str, status_code: int) -> None:
    # Retried a few times: if this write fails, the row stays 'processing' and
    # a later retry is blocked until the claim goes stale (see module docstring).
    last = None
    for attempt in range(3):
        try:
            supabase.table(TABLE).update({
                "status": STATUS_APPLIED,
                "status_code": status_code,
                "applied_at": _now_iso(),
            }).eq("op_id", op_id).execute()
            return
        except Exception as e:
            last = e
            time.sleep(0.3 * (attempt + 1))
    raise last


def register_offline_replay(app):
    @app.before_request
    def _offline_before():
        op_id = request.headers.get("X-Offline-Op-Id")
        # Only logged-in users; anyone else falls through to the normal 401.
        if not op_id or "username" not in session or request.method == "OPTIONS":
            return None

        raw_ts = request.headers.get("X-Offline-Created-At")
        if raw_ts and raw_ts.isdigit():
            ms = int(raw_ts)
            now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
            if 0 < ms <= now_ms + 60_000:
                g.offline_created_at = _manila_naive(ms)

        user_id = str(session.get("user_id"))
        try:
            won, row = _try_claim(op_id, user_id)
            if not won and row and row.get("status") == STATUS_PROCESSING and _is_stale(row):
                _release_claim(op_id)
                won, row = _try_claim(op_id, user_id)
        except Exception as e:  # fail closed: the browser keeps the op and retries
            print(f"[OFFLINE] claim failed for {op_id}: {e}", flush=True)
            return jsonify({"error": "Sync check unavailable, retry later"}), 503

        if won:
            g.offline_op_id = op_id
            return None

        if row and row.get("status") == STATUS_APPLIED:
            return jsonify({"success": True, "duplicate": True}), 200

        return jsonify({"error": "This change is already being processed, retry later"}), 503

    @app.after_request
    def _offline_after(resp):
        op_id = getattr(g, "offline_op_id", None)
        if not op_id:
            return resp
        try:
            if 200 <= resp.status_code < 300:
                _mark_applied(op_id, resp.status_code)
            else:
                _release_claim(op_id)
        except Exception as e:
            print(f"[OFFLINE] could not finalise op {op_id}: {e}", flush=True)
        return resp