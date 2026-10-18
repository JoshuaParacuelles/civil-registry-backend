import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, g, jsonify, request, session
from werkzeug.exceptions import HTTPException

from auth.Rolemanagement import get_user_permissions, is_admin
from auth.local_data import load as load_local, save_key
from logs.Audits import mask_identifier, record_action, record_document_event
from security import audit_denial, entity_permission_hook
from supabase_client import supabase

document_bp = Blueprint("document", __name__, url_prefix="/api/documents")

logger = logging.getLogger(__name__)

# Bump this when the response shape changes. Shown in the X-Document-Api
# response header so you can confirm which code is running.
DOCUMENT_API_VERSION = "handled-v4-offline"


@document_bp.errorhandler(Exception)
def _handle_document_bp_error(e):
    # Normal HTTP errors (401, 403, 404, 409, ...) pass through unchanged.
    if isinstance(e, HTTPException):
        return e
    # Anything else is almost always the database being unreachable or a
    # query failing outright. Return a clear 503 instead of a generic 500.
    logger.exception("Unhandled error in Document Tracking route")
    return jsonify({
        "error": "Server or database unavailable. Please try again when the connection returns.",
    }), 503


# Substrings that identify a *transient* socket hiccup rather than a
# real database/query problem.
_TRANSIENT_ERROR_MARKERS = ("10035", "WinError", "WSAEWOULDBLOCK", "temporarily unavailable")

# How many days a document must remain posted before the "Posting Period"
# stage can be completed (Late Registration only).
POSTING_PERIOD_DAYS = 10

STARTER_STAGES = [
    {"stage_order": 1, "label": "Registration",
     "detail": "Assigned personnel processes the submitted registration documents."},
    {"stage_order": 2, "label": "Civil Registrar",
     "detail": "Document is forwarded to the Civil Registrar."},
    {"stage_order": 3, "label": "Posting Period",
     "detail": f"Document is posted for {POSTING_PERIOD_DAYS} days, as required for late registration, before proceeding."},
    {"stage_order": 4, "label": "Records Division",
     "detail": "Document is registered into the Civil Registry Book."},
    {"stage_order": 5, "label": "Assign Registry Number",
     "detail": "Authorized personnel enters and saves the Registry Number."},
    {"stage_order": 6, "label": "Releasing",
     "detail": "Document is released to its destination."},
]

# The four allowed release destinations for the final "Releasing" stage.
RELEASE_DESTINATIONS = ["Owner's Copy", "Hospital", "PSA", "Archive Office"]

STAGE_PERMISSION_KEYS = [
    "document_stage_registration",
    "document_stage_civil_registrar",
    "document_stage_posting_period",
    "document_stage_records_division",
    "document_stage_registry_number",
    "document_stage_releasing",
]

# How long the stage-holder map (role -> username) is cached. Role changes
# can also clear it immediately with invalidate_stage_holder_cache().
STAGE_HOLDER_CACHE_SECONDS = 60

# ─────────────────────────────────────────────────────────────────────────
# Required schema (run once in Supabase before deploying):
#
#   ALTER TABLE document_personnel ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
#   ALTER TABLE documents ADD COLUMN IF NOT EXISTS deleted_handler_id integer
#     REFERENCES document_personnel(id);
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS registry_number text;
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS release_destination text;
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS posting_start_at timestamptz;
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS posting_end_at timestamptz;
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS assigned_handler_id
#     integer REFERENCES document_personnel(id);
#   ALTER TABLE documents ADD COLUMN IF NOT EXISTS archived_at timestamptz;
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS completed_by text;
#
# Recommended indexes:
#
#   CREATE INDEX IF NOT EXISTS idx_stages_doc_order ON document_stages (document_id, stage_order);
#   CREATE INDEX IF NOT EXISTS idx_comments_stage ON document_comments (stage_id);
#   CREATE INDEX IF NOT EXISTS idx_documents_archived ON documents (archived_at);
# ─────────────────────────────────────────────────────────────────────────


def execute_with_retry(query_builder, attempts=3, base_delay=0.2):
    """
    Calls .execute() on a query builder, retrying short transient socket
    errors. Any other error is raised immediately.
    """
    last_err = None
    for attempt in range(attempts):
        try:
            return query_builder.execute()
        except Exception as e:
            last_err = e
            if attempt < attempts - 1 and any(m in str(e) for m in _TRANSIENT_ERROR_MARKERS):
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise last_err


# Maps the lowercase Postgres enum values in documents.status to the
# labels the frontend expects.
STATUS_LABELS = {
    "in_review": "In review",
    "approved": "Approved",
    "changes_requested": "Changes requested",
    "rejected": "Rejected",
}


# ─────────────────────────────────────────────────────────────────────────
# Response + offline cache helpers
# ─────────────────────────────────────────────────────────────────────────

def _respond(rows, offline=False):
    """JSON response. Adds X-Data-Source when the rows came from the local cache."""
    resp = jsonify(rows)
    if offline:
        resp.headers["X-Data-Source"] = "offline-cache"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _doc_cache_key(username, archived):
    return f"{(username or '').lower()}:{'archived' if archived else 'active'}"


def _offline_documents(username, archived):
    cached = load_local().get("documents") or {}
    rows = cached.get(_doc_cache_key(username, archived)) if isinstance(cached, dict) else None
    if rows is None:
        return jsonify({
            "error": "Document Tracking is not available offline yet. Open it once while online first."
        }), 503
    return _respond(rows, offline=True)


def _save_documents_cache(username, archived, documents):
    """Never lets a cache write failure break the live response."""
    try:
        save_key("documents", _doc_cache_key(username, archived), documents)
    except Exception as e:
        logger.exception("Could not save document list to local cache: %s", e)


# ─────────────────────────────────────────────────────────────────────────
# Per-request cache and auth helpers
# ─────────────────────────────────────────────────────────────────────────

def _request_cached(key, factory):
    """Runs factory() at most once per HTTP request and returns its result."""
    cache = g.setdefault("_document_request_cache", {})
    if key not in cache:
        cache[key] = factory()
    return cache[key]


def current_username():
    return session.get("username")


def require_login():
    """Returns an error response tuple if not logged in, else None."""
    if not current_username():
        audit_denial("Document Tracking route requires authentication")
        return jsonify({"error": "Not authenticated"}), 401
    return None


def _current_is_admin():
    return _request_cached("is_admin", lambda: bool(is_admin(current_username())))


def _current_permissions():
    return _request_cached(
        "permissions",
        lambda: set(get_user_permissions(current_username()) or []),
    )


def _current_user_row():
    """The current user's row from `users` (one query per request at most)."""
    def load():
        res = execute_with_retry(
            supabase.table("users")
            .select("id, full_name, username")
            .eq("username", current_username())
            .limit(1)
        )
        return res.data[0] if res.data else None
    return _request_cached("user_row", load)


def _current_author_name():
    row = _current_user_row() or {}
    return row.get("full_name") or row.get("username") or current_username() or "Unknown"


def require_admin():
    """Returns an error response tuple if the current user is NOT an admin, else None."""
    if not _current_is_admin():
        audit_denial("Document Tracking admin privileges required")
        return jsonify({"error": "Admin access required"}), 403
    return None


def block_if_admin():
    """
    Returns an error response tuple if the current user IS an admin, else None.
    Administrators are strictly view-only on working a document.
    """
    if _current_is_admin():
        audit_denial("Administrators are view-only for document processing")
        return jsonify({"error": "Admins have view-only access to Document Tracking"}), 403
    return None


# ─────────────────────────────────────────────────────────────────────────
# Stage permission mapping
# ─────────────────────────────────────────────────────────────────────────

def _stage_permission_for_label(label):
    """
    Maps a stage label to the document_stage_* permission that scopes a role
    to that one stage. Returns None for unknown labels (unrestricted).
    """
    label_lower = (label or "").strip().lower()
    if "registration" in label_lower:
        return "document_stage_registration"
    if "civil registrar" in label_lower:
        return "document_stage_civil_registrar"
    if label_lower == "posting period":
        return "document_stage_posting_period"
    if "records division" in label_lower:
        return "document_stage_records_division"
    if "registry number" in label_lower:
        return "document_stage_registry_number"
    if label_lower == "releasing":
        return "document_stage_releasing"
    return None


def _check_stage_permission(stage):
    """
    Returns an error response tuple if the current user's role does not carry
    the document_stage_* permission for this stage, else None. A "*"
    permission passes every stage.
    """
    required = _stage_permission_for_label(stage.get("label"))
    if not required:
        return None
    perms = _current_permissions()
    if "*" in perms or required in perms:
        return None
    audit_denial("Required document stage permission missing")
    return jsonify({
        "error": "Access denied — your role does not include this Document Tracking stage"
    }), 403


# ─────────────────────────────────────────────────────────────────────────
# Role-based stage handler lookup (Document Tracking Credentials)
# ─────────────────────────────────────────────────────────────────────────

_DOC_CATEGORY_COLUMN_OK = None
_stage_holder_cache = {"value": None, "expires": 0.0}
_stage_holder_lock = threading.Lock()


def _document_category_column_available():
    """True when user_roles.category exists (probed once and cached)."""
    global _DOC_CATEGORY_COLUMN_OK
    if _DOC_CATEGORY_COLUMN_OK is not None:
        return _DOC_CATEGORY_COLUMN_OK
    try:
        execute_with_retry(supabase.table("user_roles").select("category").limit(1))
        _DOC_CATEGORY_COLUMN_OK = True
    except Exception:
        _DOC_CATEGORY_COLUMN_OK = False
    return _DOC_CATEGORY_COLUMN_OK


def _load_stage_handler_usernames():
    """
    Resolves {permission: username} for every stage permission in ONE query
    over user_roles. Skips the Administrator role and the reserved "admin"
    account. Raises on database errors so failures are never cached.
    """
    wanted = set(STAGE_PERMISSION_KEYS)
    query = supabase.table("user_roles").select("username, roles(name, permissions)")
    if _document_category_column_available():
        query = query.eq("category", "document")
    res = execute_with_retry(query)

    result = {}
    for row in (res.data or []):
        if len(result) == len(wanted):
            break
        role = row.get("roles")
        if isinstance(role, list):
            role = role[0] if role else None
        if not role:
            continue
        if (role.get("name") or "") == "Administrator":
            continue
        username = row.get("username")
        if not username or username.lower() == "admin":
            continue
        raw_perms = role.get("permissions")
        if isinstance(raw_perms, str):
            try:
                raw_perms = json.loads(raw_perms)
            except Exception:
                raw_perms = []
        if not raw_perms:
            continue
        for permission in wanted:
            if permission not in result and permission in raw_perms:
                result[permission] = username
    return result


def _stage_holder_map():
    """{permission: username} for all stage permissions, cached briefly."""
    now = time.monotonic()
    with _stage_holder_lock:
        if _stage_holder_cache["value"] is not None and now < _stage_holder_cache["expires"]:
            return _stage_holder_cache["value"]
    try:
        value = _load_stage_handler_usernames()
    except Exception:
        logger.exception("Failed to resolve role-based stage handlers")
        return {}
    with _stage_holder_lock:
        _stage_holder_cache["value"] = value
        _stage_holder_cache["expires"] = time.monotonic() + STAGE_HOLDER_CACHE_SECONDS
    return value


def invalidate_stage_holder_cache():
    """Call after roles change in Role Management so the new holders show at once."""
    with _stage_holder_lock:
        _stage_holder_cache["value"] = None
        _stage_holder_cache["expires"] = 0.0


# ─────────────────────────────────────────────────────────────────────────
# Data helpers
# ─────────────────────────────────────────────────────────────────────────

def _document_has_progress(document_id):
    """True if any stage of this document is already done."""
    res = execute_with_retry(
        supabase.table("document_stages").select("id, done").eq("document_id", document_id)
    )
    return any(s.get("done") for s in (res.data or []))


def _is_active_stage(stage):
    """A stage is active when it is not done, or it has been flagged."""
    return (not stage.get("done")) or bool(stage.get("flag"))


def _is_registry_number_stage(stage):
    return "registry number" in (stage.get("label") or "").lower()


def _is_releasing_stage(stage):
    return (stage.get("label") or "").strip().lower() == "releasing"


def _is_posting_period_stage(stage):
    return (stage.get("label") or "").strip().lower() == "posting period"


def _is_late_registration(doc):
    """True when the document's doc_type mentions "late registration"."""
    return "late registration" in (doc.get("doc_type") or "").strip().lower()


def _parse_timestamp(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _handler_names(handler_ids):
    """
    Batch-resolves document_personnel ids to full names. Soft-deleted people
    are included on purpose so their name can still be shown for recovery.
    """
    handler_ids = [h for h in set(handler_ids) if h]
    if not handler_ids:
        return {}
    res = execute_with_retry(
        supabase.table("document_personnel").select("id, full_name").in_("id", handler_ids)
    )
    return {p["id"]: p["full_name"] for p in (res.data or [])}


def _resolve_stage_handler_name(stage, personnel_names, role_holders):
    """
    The single source of truth for "who is handling this stage".
    Priority:
      1. A user whose role carries this stage's document_stage_* permission.
      2. The personnel assigned to this stage (stage.assigned_handler_id).
      3. None (rendered as "Unassigned" / "Unsigned" by the caller).
    """
    permission = _stage_permission_for_label(stage.get("label"))
    role_username = role_holders.get(permission) if permission else None
    if role_username:
        return role_username
    return personnel_names.get(stage.get("assigned_handler_id"))


def _fetch_stages(document_id):
    """Loads every stage of one document in ONE query, ordered."""
    res = execute_with_retry(
        supabase.table("document_stages")
        .select("*")
        .eq("document_id", document_id)
        .order("stage_order")
    )
    return res.data or []


def _fetch_stages_for_documents(document_ids):
    """Loads every stage for the given documents in ONE query, ordered."""
    document_ids = [d for d in set(document_ids) if d is not None]
    if not document_ids:
        return {}
    res = execute_with_retry(
        supabase.table("document_stages")
        .select("*")
        .in_("document_id", document_ids)
        .order("stage_order")
    )
    by_doc = {}
    for s in (res.data or []):
        by_doc.setdefault(s.get("document_id"), []).append(s)
    return by_doc


def _load_document_context(document_id):
    """
    Two queries total: the document row and its stages.
    Returns (document_row | None, stages, active_stage | None).
    """
    doc_res = execute_with_retry(
        supabase.table("documents").select("*").eq("id", document_id).limit(1)
    )
    if not doc_res.data:
        return None, [], None
    stages = _fetch_stages(document_id)
    active = next((s for s in stages if _is_active_stage(s)), None)
    return doc_res.data[0], stages, active


def _authorize_stage_action(document_id, stage_order, require_active=False):
    """
    Shared guard for stage actions: login, not admin, document exists and is
    not archived, stage exists, role carries the stage permission, and (when
    required) the stage is the active one.

    Returns (error_response, context). On error, context is None.
    context = {"doc": row, "stages": [...], "active": stage | None, "stage": stage}
    """
    err = require_login()
    if err:
        return err, None
    err = block_if_admin()
    if err:
        return err, None

    doc, stages, active = _load_document_context(document_id)
    if not doc:
        return (jsonify({"error": "Document not found"}), 404), None
    if doc.get("archived_at"):
        audit_denial("Stage action attempted on an archived document")
        return (jsonify({
            "error": "This document is in the archive. Restore it before continuing."
        }), 409), None

    stage = next((s for s in stages if s.get("stage_order") == stage_order), None)
    if not stage:
        return (jsonify({"error": "Stage not found"}), 404), None

    err = _check_stage_permission(stage)
    if err:
        return err, None

    if require_active and (not active or active.get("stage_order") != stage_order):
        return (jsonify({"error": "This step is not the current active step."}), 409), None

    return None, {"doc": doc, "stages": stages, "active": active, "stage": stage}


def _shape_comment(row, author):
    return {
        "id": row.get("id"),
        "document_id": row.get("document_id"),
        "stage_id": row.get("stage_id"),
        "author": author,
        "body": row.get("body"),
        "created_at": row.get("created_at"),
    }


def _summarize_document(row, handler_names):
    """Shapes a raw documents row into the shape the frontend expects."""
    handler_id = row.get("assigned_handler_id")
    deleted_handler_id = row.get("deleted_handler_id")
    raw_status = row.get("status")
    status = STATUS_LABELS.get(raw_status, raw_status) or (
        "Rejected" if row.get("rejected") else "In review"
    )
    archived_at = row.get("archived_at")
    return {
        "id": row.get("id"),
        "doc_number": row.get("doc_number"),
        "title": row.get("title") or row.get("name") or "Untitled document",
        "type": row.get("doc_type") or row.get("type") or "—",
        "status": status,
        "owner": handler_names.get(handler_id, "Unassigned"),
        "assigned_handler_id": handler_id,
        "deleted_handler_id": deleted_handler_id,
        "deleted_handler_name": handler_names.get(deleted_handler_id) if deleted_handler_id else None,
        "rejected": bool(row.get("rejected")),
        "archived": bool(archived_at),
        "archived_at": archived_at,
        "handled_by_me": False,
        "updated_at": row.get("updated_at") or row.get("created_at"),
    }


def _active_stage_summaries(stages_by_doc, personnel_names, role_holders):
    """
    For each document, returns the active stage and the name of whoever
    handles it. Documents with every stage done are not included.
    """
    summary = {}
    for doc_id, stages in stages_by_doc.items():
        for s in stages:
            if not _is_active_stage(s):
                continue
            summary[doc_id] = {
                "stage_label": s.get("label"),
                "handler_name": _resolve_stage_handler_name(s, personnel_names, role_holders),
            }
            break
    return summary


def _doc_is_assigned_to(active_info, role_holders, username):
    """True when this username holds the role for the document's active step."""
    if not active_info or not username:
        return False
    permission = _stage_permission_for_label(active_info.get("stage_label"))
    holder = role_holders.get(permission) if permission else None
    return bool(holder) and holder.lower() == username.lower()


def _handled_by_user(stages, username):
    """
    True when this username completed at least one stage of the document.
    Keeps a document visible to the personnel who worked on it, even after
    the active step has moved on to someone else.
    """
    if not username:
        return False
    target = username.lower()
    return any((s.get("completed_by") or "").lower() == target for s in (stages or []))


def _audit_snapshot(doc, stages, active):
    """
    The last known state of a document, captured before it is deleted, so the
    audit entry still says what was removed. Uses only the fields the audit
    trail is allowed to hold.
    """
    handled_by = None
    if active:
        names = _handler_names([active.get("assigned_handler_id")])
        handled_by = _resolve_stage_handler_name(active, names, _stage_holder_map())
    return {
        "status": STATUS_LABELS.get(doc.get("status"))
                  or ("Rejected" if doc.get("rejected") else "In review"),
        "step": active.get("label") if active else "Completed",
        "handled_by": handled_by,
        "document_type": doc.get("doc_type"),
        "doc_number": doc.get("doc_number"),
    }


# ─────────────────────────────────────────────────────────────────────────
# Handler pool (personnel)
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/handlers", methods=["GET"])
def list_handlers():
    err = require_login()
    if err:
        return err
    try:
        res = execute_with_retry(
            supabase.table("document_personnel")
            .select("id, full_name")
            .is_("deleted_at", "null")
        )
    except Exception as e:
        logger.exception("Failed to query handlers")
        return jsonify({"error": f"Database error while loading handlers: {e}"}), 500

    handlers = [{"id": p["id"], "name": p["full_name"]} for p in (res.data or [])]
    handlers.sort(key=lambda h: h["name"].lower())
    return jsonify(handlers)


@document_bp.route("/stage-holders", methods=["GET"])
def list_stage_holders():
    """
    {permission: username} for every stage role currently assigned in
    Role Management (Document Tracking Credentials).
    """
    err = require_login()
    if err:
        return err
    return jsonify(_stage_holder_map())


@document_bp.route("/handlers", methods=["POST"])
def add_handler():
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Name is required"}), 400

    try:
        existing = execute_with_retry(
            supabase.table("document_personnel")
            .select("id")
            .ilike("full_name", name)
            .is_("deleted_at", "null")
            .limit(1)
        )
        if existing.data:
            return jsonify({"error": "This person is already in the list"}), 409

        res = execute_with_retry(
            supabase.table("document_personnel")
            .insert({"full_name": name})
            .select("id, full_name")
        )
    except Exception as e:
        logger.exception("Failed to add handler")
        return jsonify({"error": f"Could not add this person: {e}"}), 500

    if not res.data:
        return jsonify({"error": "Could not add this person"}), 500

    new_person = res.data[0]
    record_action(
        "PERSONNEL_ADDED",
        "Added personnel to the document handler pool",
        resource_type="document_personnel",
        resource_id=new_person["id"],
    )
    return jsonify({"id": new_person["id"], "name": new_person.get("full_name") or name}), 201


@document_bp.route("/handlers/<int:handler_id>", methods=["DELETE"])
def delete_handler(handler_id):
    """
    Soft-deletes a person from the handler pool. Documents and stages they
    were handling are unassigned, and the document remembers them in
    deleted_handler_id so they can be restored.
    """
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    try:
        existing = execute_with_retry(
            supabase.table("document_personnel")
            .select("id")
            .eq("id", handler_id)
            .is_("deleted_at", "null")
            .limit(1)
        )
    except Exception as e:
        logger.exception("Failed to look up handler %s for deletion", handler_id)
        return jsonify({"error": f"Database error while looking up this person: {e}"}), 500

    if not existing.data:
        return jsonify({"error": "Person not found"}), 404

    try:
        execute_with_retry(
            supabase.table("documents")
            .update({"assigned_handler_id": None, "deleted_handler_id": handler_id})
            .eq("assigned_handler_id", handler_id)
        )
        execute_with_retry(
            supabase.table("document_stages")
            .update({"assigned_handler_id": None})
            .eq("assigned_handler_id", handler_id)
        )
        execute_with_retry(
            supabase.table("document_assignments").delete().eq("handler_id", handler_id)
        )
        execute_with_retry(
            supabase.table("document_personnel")
            .update({"deleted_at": "now()"})
            .eq("id", handler_id)
        )
    except Exception as e:
        logger.exception("Failed to delete handler %s", handler_id)
        return jsonify({"error": f"Could not remove this person: {e}"}), 500

    record_action(
        "PERSONNEL_REMOVED",
        "Removed personnel from the document handler pool",
        resource_type="document_personnel",
        resource_id=handler_id,
    )
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────
# Documents: list, create, detail, archive, restore, permanent delete
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("", methods=["GET"])
def list_documents():
    """
    Administrators see every active (or archived) document. Other users see
    documents whose ACTIVE step they hold, plus documents they have completed
    a step on, so their own work stays visible after the step moves on.

    Offline: when the database is unreachable, the last list saved for this
    user and tab (active or archived) is served from local_data.json.
    """
    err = require_login()
    if err:
        return err

    username = current_username()
    admin = _current_is_admin()
    want_archived = request.args.get("archived", "").lower() == "true"

    # Only administrators can see the archive.
    if want_archived and not admin:
        return _respond([])

    try:
        res = execute_with_retry(
            supabase.table("documents").select("*").order("updated_at", desc=True)
        )
        rows = res.data
    except Exception as e:
        logger.exception("Failed to query documents")
        print(f"[DOCUMENTS] DB unavailable, serving local cache: {e}", flush=True)
        return _offline_documents(username, want_archived)

    if rows is None:
        print("[DOCUMENTS] Empty response from DB, serving local cache", flush=True)
        return _offline_documents(username, want_archived)

    # Split active vs. archived on archived_at so each list is always correct.
    rows = [r for r in rows if bool(r.get("archived_at")) == want_archived]

    try:
        stages_by_doc = _fetch_stages_for_documents([r.get("id") for r in rows])

        name_ids = []
        for r in rows:
            name_ids.append(r.get("assigned_handler_id"))
            name_ids.append(r.get("deleted_handler_id"))
        for stages in stages_by_doc.values():
            for s in stages:
                name_ids.append(s.get("assigned_handler_id"))

        personnel_names = _handler_names(name_ids)
        role_holders = _stage_holder_map()

        documents = [_summarize_document(r, personnel_names) for r in rows]

        active = _active_stage_summaries(stages_by_doc, personnel_names, role_holders)
        for doc in documents:
            info = active.get(doc["id"])
            if info:
                doc["owner"] = info["handler_name"] or "Unassigned"
                doc["active_stage"] = info["stage_label"]
            else:
                doc["active_stage"] = None
            doc["handled_by_me"] = _handled_by_user(stages_by_doc.get(doc["id"], []), username)

        # Non-admins: active documents whose current step they hold, or that
        # they have already worked on.
        if not admin:
            documents = [
                d for d in documents
                if d["handled_by_me"]
                or _doc_is_assigned_to(active.get(d["id"]), role_holders, username)
            ]

        logger.info(
            "documents list for %s (archived=%s): %d rows",
            username, want_archived, len(documents),
        )
    except Exception as e:
        logger.exception("Failed to shape document rows")
        print(f"[DOCUMENTS] Shaping failed, serving local cache: {e}", flush=True)
        return _offline_documents(username, want_archived)

    # Save the live result for offline use. Done before responding so the
    # cache always holds the list the user just saw.
    _save_documents_cache(username, want_archived, documents)

    response = jsonify(documents)
    response.headers["X-Document-Api"] = DOCUMENT_API_VERSION
    response.headers["Cache-Control"] = "no-store"
    return response


@document_bp.route("", methods=["POST"])
def create_document():
    """Admin-only. Creates a document and seeds the six starter stages."""
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "").strip()
    doc_type = (body.get("doc_type") or body.get("type") or "").strip()
    doc_number = (body.get("doc_number") or "").strip()

    if not title:
        return jsonify({"error": "Title is required"}), 400
    if not doc_type:
        return jsonify({"error": "Document type is required"}), 400
    if not doc_number:
        return jsonify({"error": "Document number is required"}), 400

    me = _current_user_row()
    if not me:
        return jsonify({"error": "Current user record not found"}), 400

    try:
        existing = execute_with_retry(
            supabase.table("documents").select("id").ilike("doc_number", doc_number).limit(1)
        )
        if existing.data:
            return jsonify({"error": f'"{doc_number}" is already in use by another document'}), 409

        doc_res = execute_with_retry(
            supabase.table("documents")
            .insert({
                "doc_number": doc_number,
                "title": title,
                "doc_type": doc_type,
                "owner_id": me["id"],
                "assigned_handler_id": None,
            })
            .select("*")
        )
    except Exception as e:
        logger.exception("Failed to create document")
        return jsonify({"error": f"Could not create this document: {e}"}), 500

    if not doc_res.data:
        return jsonify({"error": "Could not create this document"}), 500

    new_doc = doc_res.data[0]

    record_document_event(
        "DOCUMENT_CREATED",
        new_doc["id"],
        "Created document",
        new_status="In review",
        document_type=doc_type,
        extra_meta={"doc_number": doc_number},
    )

    try:
        execute_with_retry(
            supabase.table("document_stages").insert([
                {
                    "document_id": new_doc["id"],
                    "stage_order": s["stage_order"],
                    "label": s["label"],
                    "detail": s["detail"],
                    "done": False,
                    "flag": False,
                }
                for s in STARTER_STAGES
            ])
        )
    except Exception as e:
        logger.exception("Document %s created but failed to seed stages", new_doc.get("id"))
        return jsonify({
            **_summarize_document(new_doc, {}),
            "warning": f"Document created, but starter stages could not be added: {e}",
        }), 201

    response = jsonify(_summarize_document(new_doc, {}))
    response.headers["X-Document-Api"] = DOCUMENT_API_VERSION
    return response, 201


@document_bp.route("/<int:document_id>", methods=["GET"])
def get_document_detail(document_id):
    err = require_login()
    if err:
        return err

    try:
        doc_res = execute_with_retry(
            supabase.table("documents").select("*").eq("id", document_id).limit(1)
        )
    except Exception as e:
        logger.exception("Failed to query document %s", document_id)
        return jsonify({"error": f"Database error while loading this document: {e}"}), 500

    if doc_res.data is None:
        return jsonify({"error": "Could not load this document from the database"}), 500
    if not doc_res.data:
        return jsonify({"error": "Document not found"}), 404

    row = doc_res.data[0]

    try:
        stages = _fetch_stages(document_id)

        comments = (
            execute_with_retry(
                supabase.table("document_comments")
                .select("*")
                .eq("document_id", document_id)
                .order("created_at")
            ).data or []
        )

        author_ids = list({c["author_id"] for c in comments if c.get("author_id") is not None})
        authors = {}
        if author_ids:
            users_res = execute_with_retry(
                supabase.table("users").select("id, full_name, username").in_("id", author_ids)
            )
            authors = {
                u["id"]: (u.get("full_name") or u.get("username"))
                for u in (users_res.data or [])
            }

        comments_by_stage = {}
        for c in comments:
            comments_by_stage.setdefault(c["stage_id"], []).append({
                "id": c["id"],
                "author": authors.get(c.get("author_id"), "Unknown"),
                "body": c.get("body"),
                "created_at": c.get("created_at"),
            })

        name_ids = [row.get("assigned_handler_id"), row.get("deleted_handler_id")]
        name_ids += [s.get("assigned_handler_id") for s in stages]
        names = _handler_names(name_ids)
        role_holders = _stage_holder_map()

        for s in stages:
            s["assigned_handler_name"] = _resolve_stage_handler_name(s, names, role_holders)
            s["comments"] = comments_by_stage.get(s["id"], [])

        document = _summarize_document(row, names)
        document["stages"] = stages
        document["handled_by_me"] = _handled_by_user(stages, current_username())
        document["registry_number"] = next(
            (s.get("registry_number") for s in stages
             if _is_registry_number_stage(s) and s.get("registry_number")),
            None,
        )
        document["release_destination"] = next(
            (s.get("release_destination") for s in stages
             if _is_releasing_stage(s) and s.get("release_destination")),
            None,
        )
    except Exception as e:
        logger.exception("Failed to assemble document detail for %s", document_id)
        return jsonify({"error": f"Server error while loading this document: {e}"}), 500

    response = jsonify(document)
    response.headers["X-Document-Api"] = DOCUMENT_API_VERSION
    return response


@document_bp.route("/<int:document_id>/archive", methods=["POST"])
def archive_document(document_id):
    """Admin-only. Moves a document to the archive and pauses its processing."""
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    try:
        res = execute_with_retry(
            supabase.table("documents").select("*").eq("id", document_id).limit(1)
        )
        if not res.data:
            return jsonify({"error": "Document not found"}), 404
        doc = res.data[0]
        if doc.get("archived_at"):
            return jsonify({"error": "This document is already in the archive"}), 409

        execute_with_retry(
            supabase.table("documents")
            .update({"archived_at": "now()"})
            .eq("id", document_id)
        )
    except Exception as e:
        logger.exception("Failed to archive document %s", document_id)
        return jsonify({"error": f"Could not archive this document: {e}"}), 500

    record_document_event(
        "DOCUMENT_ARCHIVED",
        document_id,
        "Moved document to the archive",
        old_status=STATUS_LABELS.get(doc.get("status")),
        new_status="Archived",
        document_type=doc.get("doc_type"),
    )
    return jsonify({"ok": True})


@document_bp.route("/<int:document_id>/restore", methods=["POST"])
def restore_document(document_id):
    """Admin-only. Brings an archived document back to the active list."""
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    try:
        res = execute_with_retry(
            supabase.table("documents").select("*").eq("id", document_id).limit(1)
        )
        if not res.data:
            return jsonify({"error": "Document not found"}), 404
        doc = res.data[0]
        if not doc.get("archived_at"):
            return jsonify({"error": "This document is not in the archive"}), 409

        execute_with_retry(
            supabase.table("documents")
            .update({"archived_at": None})
            .eq("id", document_id)
        )
    except Exception as e:
        logger.exception("Failed to restore document %s", document_id)
        return jsonify({"error": f"Could not restore this document: {e}"}), 500

    record_document_event(
        "DOCUMENT_RESTORED",
        document_id,
        "Restored document from the archive",
        old_status="Archived",
        new_status=STATUS_LABELS.get(doc.get("status")) or "In review",
        document_type=doc.get("doc_type"),
    )
    return jsonify({"ok": True})


@document_bp.route("/<int:document_id>", methods=["DELETE"])
def delete_document(document_id):
    """
    Admin-only. Permanently removes an ARCHIVED document. Child rows
    (stages, comments, assignments) are removed by ON DELETE CASCADE.

    The audit entry is written after the delete succeeds, using a snapshot
    taken beforehand. If the delete fails, a FAILED entry is written instead,
    so the log never records a deletion that did not happen.
    """
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    doc_type = None
    try:
        doc, stages, active = _load_document_context(document_id)
        if not doc:
            return jsonify({"error": "Document not found"}), 404
        if not doc.get("archived_at"):
            return jsonify({
                "error": "Move the document to the archive before deleting it permanently."
            }), 409

        doc_type = doc.get("doc_type")
        snapshot = _audit_snapshot(doc, stages, active)

        execute_with_retry(
            supabase.table("documents").delete().eq("id", document_id)
        )
    except Exception as e:
        logger.exception("Failed to delete document %s", document_id)
        record_document_event(
            "DOCUMENT_DELETED_PERMANENTLY",
            document_id,
            "Permanent delete of document failed",
            status="FAILED",
            document_type=doc_type,
        )
        return jsonify({"error": f"Could not delete this document: {e}"}), 500

    record_document_event(
        "DOCUMENT_DELETED_PERMANENTLY",
        document_id,
        "Permanently deleted archived document",
        old_status=snapshot["status"],
        new_status="Deleted",
        step=snapshot["step"],
        handled_by=snapshot["handled_by"],
        document_type=snapshot["document_type"],
        extra_meta={
            "doc_number": snapshot["doc_number"],
            "stages_removed": len(stages),
        },
    )
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────
# Document-level handler assignment
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/<int:document_id>/assign", methods=["POST"])
def assign_handler(document_id):
    """
    Admin-only. Once any stage is done, reassignment is refused, except for a
    document left unassigned by a personnel deletion.
    """
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    handler_id = body.get("handler_id")
    note = body.get("note")
    if not handler_id:
        return jsonify({"error": "handler_id is required"}), 400

    try:
        doc_lock_check = execute_with_retry(
            supabase.table("documents")
            .select("assigned_handler_id, deleted_handler_id, doc_type")
            .eq("id", document_id)
            .limit(1)
        )
        if not doc_lock_check.data:
            return jsonify({"error": "Document not found"}), 404
        doc_lock_row = doc_lock_check.data[0]
        doc_type = doc_lock_row.get("doc_type")

        left_unassigned_by_deletion = (
            doc_lock_row.get("assigned_handler_id") is None
            and doc_lock_row.get("deleted_handler_id") is not None
        )

        if _document_has_progress(document_id) and not left_unassigned_by_deletion:
            return jsonify({
                "error": "This document has already progressed — the assigned handler can no longer be changed."
            }), 409

        handler_check = execute_with_retry(
            supabase.table("document_personnel")
            .select("id, deleted_at, full_name")
            .eq("id", handler_id)
            .limit(1)
        )
        if not handler_check.data:
            return jsonify({"error": "That person isn't in the handler pool"}), 400

        handler_name = handler_check.data[0].get("full_name")

        if handler_check.data[0].get("deleted_at") is not None:
            doc_check = execute_with_retry(
                supabase.table("documents")
                .select("deleted_handler_id")
                .eq("id", document_id)
                .limit(1)
            )
            doc_row = doc_check.data[0] if doc_check.data else None
            if not doc_row or doc_row.get("deleted_handler_id") != handler_id:
                return jsonify({"error": "That person isn't in the handler pool"}), 400

        me = _current_user_row()
        if not me:
            return jsonify({"error": "Current user record not found"}), 400

        execute_with_retry(
            supabase.table("documents")
            .update({"assigned_handler_id": handler_id, "deleted_handler_id": None})
            .eq("id", document_id)
        )
        execute_with_retry(
            supabase.table("document_assignments").insert({
                "document_id": document_id,
                "handler_id": handler_id,
                "assigned_by_id": me["id"],
                "note": note,
            })
        )
    except Exception as e:
        logger.exception("Failed to assign handler for document %s", document_id)
        return jsonify({"error": f"Could not assign this person: {e}"}), 500

    record_document_event(
        "DOCUMENT_ASSIGNED",
        document_id,
        "Assigned document to a handler",
        handled_by=handler_name,
        document_type=doc_type,
    )
    return jsonify({"ok": True})


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/assign", methods=["POST"])
def assign_stage_handler(document_id, stage_order):
    """Admin-only. Sets or clears (null) the handler of one stage."""
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    handler_id = body.get("handler_id")

    try:
        stage_res = execute_with_retry(
            supabase.table("document_stages")
            .select("id, label")
            .eq("document_id", document_id)
            .eq("stage_order", stage_order)
            .limit(1)
        )
    except Exception as e:
        logger.exception("Failed to load stage %s of document %s", stage_order, document_id)
        return jsonify({"error": f"Database error while loading this step: {e}"}), 500
    if not stage_res.data:
        return jsonify({"error": "Stage not found"}), 404
    stage_id = stage_res.data[0]["id"]
    stage_label = stage_res.data[0].get("label")

    if handler_id in (None, "", 0, "0"):
        handler_id = None
    else:
        try:
            handler_id = int(handler_id)
        except (TypeError, ValueError):
            return jsonify({"error": "That person isn't in the handler pool"}), 400

    handler_name = None
    try:
        if handler_id is not None:
            handler_check = execute_with_retry(
                supabase.table("document_personnel")
                .select("id, full_name")
                .eq("id", handler_id)
                .is_("deleted_at", "null")
                .limit(1)
            )
            if not handler_check.data:
                return jsonify({"error": "That person isn't in the handler pool"}), 400
            handler_name = handler_check.data[0].get("full_name")

        execute_with_retry(
            supabase.table("document_stages")
            .update({"assigned_handler_id": handler_id})
            .eq("id", stage_id)
        )
    except Exception as e:
        logger.exception("Failed to assign stage handler for document %s stage %s", document_id, stage_order)
        return jsonify({"error": f"Could not assign this person to this step: {e}"}), 500

    record_document_event(
        "DOCUMENT_STEP_ASSIGNED",
        document_id,
        "Assigned personnel to a step" if handler_id is not None
        else "Removed personnel from a step",
        step=stage_label,
        handled_by=handler_name,
        extra_meta={"stage_order": stage_order},
    )
    return jsonify({
        "ok": True,
        "stage_order": stage_order,
        "assigned_handler_id": handler_id,
        "assigned_handler_name": handler_name,
    })


# ─────────────────────────────────────────────────────────────────────────
# Stage actions (non-admin, with stage permission)
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/<int:document_id>/stages/<int:stage_order>/complete", methods=["POST"])
def complete_stage(document_id, stage_order):
    """
    Marks the active stage complete. Checks run in memory on data loaded
    once: archive, permission, active step, registry number, release
    destination, and for Late Registration documents only: posting period
    started and elapsed, plus at least one comment.
    """
    err, ctx = _authorize_stage_action(document_id, stage_order, require_active=True)
    if err:
        return err

    doc, stage = ctx["doc"], ctx["stage"]

    if _is_registry_number_stage(stage) and not (stage.get("registry_number") or "").strip():
        return jsonify({"error": "Enter and save the Registry Number before completing this step."}), 409

    if _is_releasing_stage(stage) and not (stage.get("release_destination") or "").strip():
        return jsonify({"error": "Select the release destination before completing this step."}), 409

    if _is_posting_period_stage(stage) and _is_late_registration(doc):
        posting_start_at = stage.get("posting_start_at")
        posting_end_at = stage.get("posting_end_at")
        if not posting_start_at or not posting_end_at:
            return jsonify({"error": "Start the posting period before completing this step."}), 409

        end_dt = _parse_timestamp(posting_end_at)
        if end_dt is None or datetime.now(timezone.utc) < end_dt:
            return jsonify({
                "error": f"The {POSTING_PERIOD_DAYS}-day posting period has not elapsed yet."
            }), 409

        comment_check = execute_with_retry(
            supabase.table("document_comments").select("id").eq("stage_id", stage["id"]).limit(1)
        )
        if not comment_check.data:
            return jsonify({"error": "Add a comment on this step before completing it."}), 409

    # done=False in the filter means a double-submit cannot complete twice.
    res = execute_with_retry(
        supabase.table("document_stages")
        .update({
            "done": True,
            "flag": False,
            "completed_at": "now()",
            "completed_by": current_username(),
        })
        .eq("id", stage["id"])
        .eq("done", False)
        .select("completed_at")
    )
    if not res.data:
        return jsonify({"error": "This step has already been completed."}), 409

    is_release = _is_releasing_stage(stage)
    record_document_event(
        "DOCUMENT_RELEASED" if is_release else "DOCUMENT_STEP_UPDATED",
        document_id,
        "Document released to its destination" if is_release
        else f"Completed step: {stage.get('label')}",
        step=stage.get("label"),
        old_status="Pending",
        new_status="Released" if is_release else "Completed",
        handled_by=current_username(),
        document_type=doc.get("doc_type"),
        extra_meta=(
            {"release_destination": stage.get("release_destination")} if is_release else None
        ),
    )

    return jsonify({"ok": True, "completed_at": res.data[0].get("completed_at")})


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/registry-number", methods=["POST"])
def save_registry_number(document_id, stage_order):
    err, ctx = _authorize_stage_action(document_id, stage_order)
    if err:
        return err

    body = request.get_json(silent=True) or {}
    registry_number = (body.get("registry_number") or "").strip()
    if not registry_number:
        return jsonify({"error": "Registry Number is required"}), 400

    stage = ctx["stage"]
    if not _is_registry_number_stage(stage):
        return jsonify({"error": "This step does not accept a Registry Number"}), 400

    execute_with_retry(
        supabase.table("document_stages")
        .update({"registry_number": registry_number})
        .eq("id", stage["id"])
    )

    record_document_event(
        "REGISTRY_NUMBER_ASSIGNED",
        document_id,
        "Registry number saved",
        step=stage.get("label"),
        new_status="Registry number saved",
        handled_by=current_username(),
        document_type=ctx["doc"].get("doc_type"),
        # Only the masked form is logged. The full number stays in the
        # document record.
        extra_meta={"registry_number_masked": mask_identifier(registry_number)},
    )
    return jsonify({"ok": True, "registry_number": registry_number})


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/release-destination", methods=["POST"])
def save_release_destination(document_id, stage_order):
    err, ctx = _authorize_stage_action(document_id, stage_order)
    if err:
        return err

    body = request.get_json(silent=True) or {}
    destination = (body.get("destination") or "").strip()
    if not destination:
        return jsonify({"error": "A release destination is required"}), 400
    if destination not in RELEASE_DESTINATIONS:
        return jsonify({
            "error": "Release destination must be one of: " + ", ".join(RELEASE_DESTINATIONS)
        }), 400

    stage = ctx["stage"]
    if not _is_releasing_stage(stage):
        return jsonify({"error": "This step does not accept a release destination"}), 400

    execute_with_retry(
        supabase.table("document_stages")
        .update({"release_destination": destination})
        .eq("id", stage["id"])
    )
    # The destination is included in the DOCUMENT_RELEASED entry when the
    # Releasing step is completed, so it is not logged separately here.
    return jsonify({"ok": True, "release_destination": destination})


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/posting-period", methods=["POST"])
def start_posting_period(document_id, stage_order):
    err, ctx = _authorize_stage_action(document_id, stage_order)
    if err:
        return err

    stage = ctx["stage"]
    if not _is_posting_period_stage(stage):
        return jsonify({"error": "This step does not accept a posting period"}), 400
    if stage.get("posting_start_at"):
        return jsonify({"error": "The posting period has already been started for this step"}), 409

    start_at = datetime.now(timezone.utc)
    end_at = start_at + timedelta(days=POSTING_PERIOD_DAYS)

    # The is_null filter means two simultaneous starts cannot both succeed.
    res = execute_with_retry(
        supabase.table("document_stages")
        .update({
            "posting_start_at": start_at.isoformat(),
            "posting_end_at": end_at.isoformat(),
        })
        .eq("id", stage["id"])
        .is_("posting_start_at", "null")
        .select("id")
    )
    if not res.data:
        return jsonify({"error": "The posting period has already been started for this step"}), 409

    record_document_event(
        "DOCUMENT_STEP_UPDATED",
        document_id,
        f"Started the {POSTING_PERIOD_DAYS}-day posting period",
        step=stage.get("label"),
        new_status="Posting",
        handled_by=current_username(),
        document_type=ctx["doc"].get("doc_type"),
        extra_meta={"posting_end_at": end_at.isoformat()},
    )

    return jsonify({
        "ok": True,
        "posting_start_at": start_at.isoformat(),
        "posting_end_at": end_at.isoformat(),
    })


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/flag", methods=["POST"])
def flag_stage(document_id, stage_order):
    err, ctx = _authorize_stage_action(document_id, stage_order)
    if err:
        return err

    body = request.get_json(silent=True) or {}
    note = (body.get("note") or "").strip()
    if not note:
        return jsonify({"error": "A note explaining what needs to change is required"}), 400

    stage = ctx["stage"]
    author = _current_author_name()
    author_id = (_current_user_row() or {}).get("id")
    if author_id is None:
        return jsonify({"error": "Current user record not found"}), 400

    execute_with_retry(
        supabase.table("document_stages")
        .update({"flag": True, "done": False, "completed_at": "now()"})
        .eq("id", stage["id"])
    )
    res = execute_with_retry(
        supabase.table("document_comments").insert({
            "document_id": document_id,
            "stage_id": stage["id"],
            "author_id": author_id,
            "body": note,
        }).select("*")
    )

    record_document_event(
        "DOCUMENT_STEP_UPDATED",
        document_id,
        f"Flagged step for changes: {stage.get('label')}",
        step=stage.get("label"),
        new_status="Changes requested",
        handled_by=current_username(),
        document_type=ctx["doc"].get("doc_type"),
        # The note text is not logged; only its length.
        extra_meta={"note_length": len(note)},
    )

    row = res.data[0] if res.data else {"body": note}
    return jsonify({"ok": True, "comment": _shape_comment(row, author)})


@document_bp.route("/<int:document_id>/reject", methods=["POST"])
def reject_document(document_id):
    err = require_login()
    if err:
        return err
    err = block_if_admin()
    if err:
        return err

    doc, stages, active = _load_document_context(document_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404
    if doc.get("archived_at"):
        return jsonify({
            "error": "This document is in the archive. Restore it before continuing."
        }), 409

    if active:
        err = _check_stage_permission(active)
        if err:
            return err

    execute_with_retry(
        supabase.table("documents").update({"rejected": True}).eq("id", document_id)
    )

    record_document_event(
        "DOCUMENT_REJECTED",
        document_id,
        "Document rejected",
        old_status=STATUS_LABELS.get(doc.get("status")),
        new_status="Rejected",
        step=active.get("label") if active else None,
        handled_by=current_username(),
        document_type=doc.get("doc_type"),
    )
    return jsonify({"ok": True})


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/comments", methods=["POST"])
def add_comment(document_id, stage_order):
    err, ctx = _authorize_stage_action(document_id, stage_order)
    if err:
        return err

    body = request.get_json(silent=True) or {}
    text = (body.get("body") or "").strip()
    if not text:
        return jsonify({"error": "Comment body is required"}), 400

    stage = ctx["stage"]
    author = _current_author_name()
    author_id = (_current_user_row() or {}).get("id")
    if author_id is None:
        return jsonify({"error": "Current user record not found"}), 400

    res = execute_with_retry(
        supabase.table("document_comments").insert({
            "document_id": document_id,
            "stage_id": stage["id"],
            "author_id": author_id,
            "body": text,
        }).select("*")
    )

    record_document_event(
        "DOCUMENT_COMMENT_ADDED",
        document_id,
        f"Added a comment on step: {stage.get('label')}",
        step=stage.get("label"),
        handled_by=current_username(),
        document_type=ctx["doc"].get("doc_type"),
        # The comment text is not logged; only its length.
        extra_meta={"comment_length": len(text)},
    )

    row = res.data[0] if res.data else {"body": text}
    return jsonify(_shape_comment(row, author)), 201


document_bp.before_request(entity_permission_hook("tracking"))