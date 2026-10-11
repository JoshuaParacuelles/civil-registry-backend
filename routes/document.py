import logging
import time
import json
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify, session
from werkzeug.exceptions import HTTPException
from supabase_client import supabase
from auth.Rolemanagement import is_admin, get_user_permissions
from security import audit_denial, entity_permission_hook

document_bp = Blueprint("document", __name__, url_prefix="/api/documents")

logger = logging.getLogger(__name__)

# Bump this when the list response shape changes. Shown in the
# X-Document-Api response header so you can confirm which code is running.
DOCUMENT_API_VERSION = "assigned-v3"


@document_bp.errorhandler(Exception)
def _handle_document_bp_error(e):
    # Normal HTTP errors (401, 403, 404, 409, ...) pass through unchanged.
    if isinstance(e, HTTPException):
        return e
    # Anything else is almost always the database being unreachable or a
    # query failing outright. Return a clear 503 instead of a generic 500
    # so the frontend can show a meaningful message.
    logger.exception("Unhandled error in Document Tracking route")
    return jsonify({
        "error": "Server or database unavailable. Please try again when the connection returns.",
    }), 503


# Substrings that identify a *transient* socket hiccup rather than a
# real database/query problem (e.g. Windows "WinError 10035" when two
# requests race to use the shared supabase httpx client).
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


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────

# Maps the lowercase Postgres enum values in documents.status to the
# labels the frontend expects.
STATUS_LABELS = {
    "in_review": "In review",
    "approved": "Approved",
    "changes_requested": "Changes requested",
    "rejected": "Rejected",
}


def current_username():
    return session.get("username")


def require_login():
    """Returns an error response tuple if not logged in, else None."""
    if not current_username():
        audit_denial("Document Tracking route requires authentication")
        return jsonify({"error": "Not authenticated"}), 401
    return None


def require_admin():
    """Returns an error response tuple if the current user is NOT an admin, else None."""
    if not is_admin(current_username()):
        audit_denial("Document Tracking admin privileges required")
        return jsonify({"error": "Admin access required"}), 403
    return None


def block_if_admin():
    """
    Returns an error response tuple if the current user IS an admin, else None.
    Administrators are strictly view-only on working a document: they never
    complete, flag, reject, or comment on a stage themselves.
    """
    if is_admin(current_username()):
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


def block_if_no_stage_permission(stage):
    """
    Returns an error response tuple if the current user's role does not carry
    the document_stage_* permission for this stage, else None. A "*" permission
    passes every stage.
    """
    required_permission = _stage_permission_for_label(stage.get("label"))
    if not required_permission:
        return None
    perms = get_user_permissions(current_username())
    if "*" in perms or required_permission in perms:
        return None
    audit_denial("Required document stage permission missing")
    return (
        jsonify({
            "error": "Access denied — your role does not include this Document Tracking stage"
        }),
        403,
    )


# ─────────────────────────────────────────────────────────────────────────
# Role-based stage handler lookup (Document Tracking Credentials)
# ─────────────────────────────────────────────────────────────────────────

_DOC_CATEGORY_COLUMN_OK = None


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


def _get_stage_handler_usernames(permissions):
    """
    Resolves {permission: username} for every requested stage permission in
    ONE query over user_roles. Skips the Administrator role and the reserved
    "admin" account. Only Document Tracking Credentials (category="document")
    are considered where that column exists.
    """
    permissions = {p for p in permissions if p}
    if not permissions:
        return {}
    try:
        query = supabase.table("user_roles").select("username, roles(name, permissions)")
        if _document_category_column_available():
            query = query.eq("category", "document")
        res = execute_with_retry(query)
    except Exception:
        logger.exception("Failed to resolve role-based handlers for permissions %s", permissions)
        return {}

    result = {}
    for row in (res.data or []):
        if len(result) == len(permissions):
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
        for permission in permissions:
            if permission in result:
                continue
            if permission in raw_perms:
                result[permission] = username
    return result


# ─────────────────────────────────────────────────────────────────────────
# Data helpers
# ─────────────────────────────────────────────────────────────────────────

def get_user_id(username):
    """Resolves a username to its users.id (used for author/owner/assigned_by)."""
    res = execute_with_retry(
        supabase.table("users").select("id").eq("username", username).limit(1)
    )
    return res.data[0]["id"] if res.data else None


def get_stage(document_id, stage_order):
    """Fetches a single stage row by (document_id, stage_order), or None."""
    res = execute_with_retry(
        supabase.table("document_stages")
        .select("*")
        .eq("document_id", document_id)
        .eq("stage_order", stage_order)
        .limit(1)
    )
    return res.data[0] if res.data else None


def _document_has_progress(document_id):
    """True if any stage of this document is already done."""
    res = execute_with_retry(
        supabase.table("document_stages").select("id, done").eq("document_id", document_id)
    )
    return any(s.get("done") for s in (res.data or []))


def _is_active_stage(stage):
    """A stage is active when it is not done, or it has been flagged."""
    return (not stage.get("done")) or bool(stage.get("flag"))


def _get_active_stage(document_id):
    """Returns the first stage that is neither done nor flagged, or None."""
    res = execute_with_retry(
        supabase.table("document_stages")
        .select("*")
        .eq("document_id", document_id)
        .order("stage_order")
    )
    for s in (res.data or []):
        if _is_active_stage(s):
            return s
    return None


def _is_registry_number_stage(stage):
    return "registry number" in (stage.get("label") or "").lower()


def _is_releasing_stage(stage):
    return (stage.get("label") or "").strip().lower() == "releasing"


def _is_posting_period_stage(stage):
    return (stage.get("label") or "").strip().lower() == "posting period"


def _document_is_late_registration(document_id):
    """
    True when the document's doc_type mentions "late registration". Only
    those documents require the Posting Period window and comment.
    """
    try:
        res = execute_with_retry(
            supabase.table("documents").select("doc_type").eq("id", document_id).limit(1)
        )
    except Exception:
        logger.exception("Failed to check doc_type for document %s", document_id)
        return False
    if not res.data:
        return False
    doc_type = (res.data[0].get("doc_type") or "").strip().lower()
    return "late registration" in doc_type


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
      1. A user whose role carries this stage's document_stage_* permission
         (Document Tracking Credentials).
      2. The personnel assigned to this stage (stage.assigned_handler_id).
      3. None (rendered as "Unassigned" / "Unsigned" by the caller).
    Used by BOTH the list and the detail view so they never disagree.
    """
    permission = _stage_permission_for_label(stage.get("label"))
    role_username = role_holders.get(permission) if permission else None
    if role_username:
        return role_username
    return personnel_names.get(stage.get("assigned_handler_id"))


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


def _active_stage_summaries(stages_by_doc, personnel_names, role_holders):
    """
    For each document, returns the active stage and the name of whoever
    handles it. Documents with every stage done are not included.
    Returns {document_id: {"stage_label": str, "handler_name": str | None}}.
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
    """True when this username holds the role for the document's active step
    (the same person shown as "Currently handling" on that step)."""
    if not active_info or not username:
        return False
    permission = _stage_permission_for_label(active_info.get("stage_label"))
    holder = role_holders.get(permission) if permission else None
    return bool(holder) and holder.lower() == username.lower()


def _summarize_document(row, handler_names):
    """Shapes a raw documents row into the shape the frontend expects."""
    handler_id = row.get("assigned_handler_id")
    deleted_handler_id = row.get("deleted_handler_id")
    raw_status = row.get("status")
    status = STATUS_LABELS.get(raw_status, raw_status) or (
        "Rejected" if row.get("rejected") else "In review"
    )
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
        "updated_at": row.get("updated_at") or row.get("created_at"),
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
    Role Management (Document Tracking Credentials). Saved on the device
    so stage names still show when offline.
    """
    err = require_login()
    if err:
        return err
    return jsonify(_get_stage_handler_usernames(STAGE_PERMISSION_KEYS))


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
        affected = execute_with_retry(
            supabase.table("documents").select("id").eq("assigned_handler_id", handler_id)
        )
        if affected.data:
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

    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────
# Documents: list, create, detail, delete
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("", methods=["GET"])
def list_documents():
    err = require_login()
    if err:
        return err

    username = current_username()

    try:
        res = execute_with_retry(
            supabase.table("documents").select("*").order("updated_at", desc=True)
        )
        rows = res.data
    except Exception as e:
        logger.exception("Failed to query documents")
        return jsonify({"error": f"Database error while loading documents: {e}"}), 500

    if rows is None:
        return jsonify({"error": "Could not load documents from the database"}), 500

    try:
        doc_ids = [r.get("id") for r in rows]

        # Document-level names (kept for deleted-handler info and fallback).
        handler_ids = []
        for r in rows:
            handler_ids.append(r.get("assigned_handler_id"))
            handler_ids.append(r.get("deleted_handler_id"))

        # Stage-level data, loaded once for the whole list.
        stages_by_doc = _fetch_stages_for_documents(doc_ids)
        for stages in stages_by_doc.values():
            for s in stages:
                handler_ids.append(s.get("assigned_handler_id"))

        personnel_names = _handler_names(handler_ids)
        role_holders = _get_stage_handler_usernames(STAGE_PERMISSION_KEYS)

        documents = [_summarize_document(r, personnel_names) for r in rows]

        # Show who handles the ACTIVE stage, not the old document-level handler.
        active = _active_stage_summaries(stages_by_doc, personnel_names, role_holders)
        for doc in documents:
            info = active.get(doc["id"])
            if info:
                doc["owner"] = info["handler_name"] or "Unassigned"
                doc["active_stage"] = info["stage_label"]
            else:
                # Every stage done (or no stages): keep the document-level owner.
                doc["active_stage"] = None

        # Non-admins only see documents whose current step they handle.
        if not is_admin(username):
            documents = [
                d for d in documents
                if _doc_is_assigned_to(active.get(d["id"]), role_holders, username)
            ]

        logger.info(
            "documents list for %s: %d rows, %d with an active stage",
            username,
            len(documents),
            sum(1 for d in documents if d.get("active_stage")),
        )
    except Exception as e:
        logger.exception("Failed to shape document rows")
        return jsonify({"error": f"Server error while processing documents: {e}"}), 500

    response = jsonify(documents)
    response.headers["X-Document-Api"] = DOCUMENT_API_VERSION
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

    owner_id = get_user_id(current_username())
    if not owner_id:
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
                "owner_id": owner_id,
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

    return jsonify(_summarize_document(new_doc, {})), 201


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
        handler_names = _handler_names([row.get("assigned_handler_id"), row.get("deleted_handler_id")])
        document = _summarize_document(row, handler_names)

        stages = (
            execute_with_retry(
                supabase.table("document_stages")
                .select("*")
                .eq("document_id", document_id)
                .order("stage_order")
            ).data or []
        )

        # Personnel names for each stage's own assigned_handler_id, plus the
        # role-based holders. Both resolved through the shared helper so the
        # detail view and the list always agree.
        stage_handler_names = _handler_names([s.get("assigned_handler_id") for s in stages])
        role_holders = _get_stage_handler_usernames(STAGE_PERMISSION_KEYS)

        for s in stages:
            stage_handler_id = s.get("assigned_handler_id")
            s["assigned_handler_id"] = stage_handler_id
            s["assigned_handler_name"] = _resolve_stage_handler_name(
                s, stage_handler_names, role_holders
            )

        comments = (
            execute_with_retry(
                supabase.table("document_comments")
                .select("*")
                .eq("document_id", document_id)
                .order("created_at")
            ).data or []
        )

        author_ids = list({c["author_id"] for c in comments})
        authors = {}
        if author_ids:
            users_res = execute_with_retry(
                supabase.table("users").select("id, full_name, username").in_("id", author_ids)
            )
            authors = {
                u["id"]: (u.get("full_name") or u["username"]) for u in (users_res.data or [])
            }

        comments_by_stage = {}
        for c in comments:
            comments_by_stage.setdefault(c["stage_id"], []).append({
                "id": c["id"],
                "author": authors.get(c["author_id"], "Unknown"),
                "body": c["body"],
                "created_at": c["created_at"],
            })

        for s in stages:
            s["comments"] = comments_by_stage.get(s["id"], [])

        document["stages"] = stages
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

    return jsonify(document)


@document_bp.route("/<int:document_id>", methods=["DELETE"])
def delete_document(document_id):
    """Admin-only. Removes the document and its child rows."""
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    try:
        existing = execute_with_retry(
            supabase.table("documents").select("id").eq("id", document_id).limit(1)
        )
    except Exception as e:
        logger.exception("Failed to look up document %s for deletion", document_id)
        return jsonify({"error": f"Database error while looking up this document: {e}"}), 500

    if not existing.data:
        return jsonify({"error": "Document not found"}), 404

    try:
        execute_with_retry(supabase.table("document_comments").delete().eq("document_id", document_id))
        execute_with_retry(supabase.table("document_assignments").delete().eq("document_id", document_id))
        execute_with_retry(supabase.table("document_stages").delete().eq("document_id", document_id))
        execute_with_retry(supabase.table("documents").delete().eq("id", document_id))
    except Exception as e:
        logger.exception("Failed to delete document %s", document_id)
        return jsonify({"error": f"Could not delete this document: {e}"}), 500

    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────
# Document-level handler assignment
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/<int:document_id>/assign", methods=["POST"])
def assign_handler(document_id):
    """
    Admin-only. Once any stage is done, reassignment is refused, except for a
    document left unassigned by a personnel deletion. A soft-deleted person is
    only assignable as this document's own deleted_handler_id.
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
            .select("assigned_handler_id, deleted_handler_id")
            .eq("id", document_id)
            .limit(1)
        )
        if not doc_lock_check.data:
            return jsonify({"error": "Document not found"}), 404
        doc_lock_row = doc_lock_check.data[0]

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
            .select("id, deleted_at")
            .eq("id", handler_id)
            .limit(1)
        )
        if not handler_check.data:
            return jsonify({"error": "That person isn't in the handler pool"}), 400

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

        assigned_by_id = get_user_id(current_username())
        if not assigned_by_id:
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
                "assigned_by_id": assigned_by_id,
                "note": note,
            })
        )
    except Exception as e:
        logger.exception("Failed to assign handler for document %s", document_id)
        return jsonify({"error": f"Could not assign this person: {e}"}), 500

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

    stage = get_stage(document_id, stage_order)
    if not stage:
        return jsonify({"error": "Stage not found"}), 404

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
            .eq("id", stage["id"])
        )
    except Exception as e:
        logger.exception("Failed to assign stage handler for document %s stage %s", document_id, stage_order)
        return jsonify({"error": f"Could not assign this person to this step: {e}"}), 500

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
    Marks the active stage complete. Enforced in order: current active stage
    only, registry number (Assign Registry Number), release destination
    (Releasing), and for Late Registration documents only: posting period
    started and elapsed, plus at least one comment.
    """
    err = require_login()
    if err:
        return err
    err = block_if_admin()
    if err:
        return err

    stage = get_stage(document_id, stage_order)
    if not stage:
        return jsonify({"error": "Stage not found"}), 404

    err = block_if_no_stage_permission(stage)
    if err:
        return err

    active_stage = _get_active_stage(document_id)
    if not active_stage or active_stage.get("stage_order") != stage_order:
        return jsonify({"error": "This step is not the current active step."}), 409

    if _is_registry_number_stage(stage) and not (stage.get("registry_number") or "").strip():
        return jsonify({"error": "Enter and save the Registry Number before completing this step."}), 409

    if _is_releasing_stage(stage) and not (stage.get("release_destination") or "").strip():
        return jsonify({"error": "Select the release destination before completing this step."}), 409

    if _is_posting_period_stage(stage) and _document_is_late_registration(document_id):
        posting_start_at = stage.get("posting_start_at")
        posting_end_at = stage.get("posting_end_at")
        if not posting_start_at or not posting_end_at:
            return jsonify({"error": "Start the posting period before completing this step."}), 409
        try:
            end_dt = datetime.fromisoformat(str(posting_end_at).replace("Z", "+00:00"))
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            end_dt = None
        if end_dt is None or datetime.now(timezone.utc) < end_dt:
            return jsonify({
                "error": f"The {POSTING_PERIOD_DAYS}-day posting period has not elapsed yet."
            }), 409
        comment_check = execute_with_retry(
            supabase.table("document_comments").select("id").eq("stage_id", stage["id"]).limit(1)
        )
        if not comment_check.data:
            return jsonify({"error": "Add a comment on this step before completing it."}), 409

    execute_with_retry(
        supabase.table("document_stages")
        .update({"done": True, "flag": False, "completed_at": "now()"})
        .eq("id", stage["id"])
    )
    return jsonify({"ok": True})


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/registry-number", methods=["POST"])
def save_registry_number(document_id, stage_order):
    err = require_login()
    if err:
        return err
    err = block_if_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    registry_number = (body.get("registry_number") or "").strip()
    if not registry_number:
        return jsonify({"error": "Registry Number is required"}), 400

    stage = get_stage(document_id, stage_order)
    if not stage:
        return jsonify({"error": "Stage not found"}), 404

    err = block_if_no_stage_permission(stage)
    if err:
        return err

    if not _is_registry_number_stage(stage):
        return jsonify({"error": "This step does not accept a Registry Number"}), 400

    execute_with_retry(
        supabase.table("document_stages")
        .update({"registry_number": registry_number})
        .eq("id", stage["id"])
    )
    return jsonify({"ok": True, "registry_number": registry_number})


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/release-destination", methods=["POST"])
def save_release_destination(document_id, stage_order):
    err = require_login()
    if err:
        return err
    err = block_if_admin()
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

    stage = get_stage(document_id, stage_order)
    if not stage:
        return jsonify({"error": "Stage not found"}), 404

    err = block_if_no_stage_permission(stage)
    if err:
        return err

    if not _is_releasing_stage(stage):
        return jsonify({"error": "This step does not accept a release destination"}), 400

    execute_with_retry(
        supabase.table("document_stages")
        .update({"release_destination": destination})
        .eq("id", stage["id"])
    )
    return jsonify({"ok": True, "release_destination": destination})


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/posting-period", methods=["POST"])
def start_posting_period(document_id, stage_order):
    err = require_login()
    if err:
        return err
    err = block_if_admin()
    if err:
        return err

    stage = get_stage(document_id, stage_order)
    if not stage:
        return jsonify({"error": "Stage not found"}), 404

    err = block_if_no_stage_permission(stage)
    if err:
        return err

    if not _is_posting_period_stage(stage):
        return jsonify({"error": "This step does not accept a posting period"}), 400
    if stage.get("posting_start_at"):
        return jsonify({"error": "The posting period has already been started for this step"}), 409

    start_at = datetime.now(timezone.utc)
    end_at = start_at + timedelta(days=POSTING_PERIOD_DAYS)

    execute_with_retry(
        supabase.table("document_stages")
        .update({
            "posting_start_at": start_at.isoformat(),
            "posting_end_at": end_at.isoformat(),
        })
        .eq("id", stage["id"])
    )
    return jsonify({
        "ok": True,
        "posting_start_at": start_at.isoformat(),
        "posting_end_at": end_at.isoformat(),
    })


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/flag", methods=["POST"])
def flag_stage(document_id, stage_order):
    err = require_login()
    if err:
        return err
    err = block_if_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    note = (body.get("note") or "").strip()
    if not note:
        return jsonify({"error": "A note explaining what needs to change is required"}), 400

    stage = get_stage(document_id, stage_order)
    if not stage:
        return jsonify({"error": "Stage not found"}), 404

    err = block_if_no_stage_permission(stage)
    if err:
        return err

    author_id = get_user_id(current_username())
    if not author_id:
        return jsonify({"error": "Current user record not found"}), 400

    execute_with_retry(
        supabase.table("document_stages")
        .update({"flag": True, "done": False, "completed_at": "now()"})
        .eq("id", stage["id"])
    )
    execute_with_retry(
        supabase.table("document_comments").insert({
            "document_id": document_id,
            "stage_id": stage["id"],
            "author_id": author_id,
            "body": note,
        })
    )
    return jsonify({"ok": True})


@document_bp.route("/<int:document_id>/reject", methods=["POST"])
def reject_document(document_id):
    err = require_login()
    if err:
        return err
    err = block_if_admin()
    if err:
        return err

    active_stage = _get_active_stage(document_id)
    if active_stage:
        err = block_if_no_stage_permission(active_stage)
        if err:
            return err

    execute_with_retry(
        supabase.table("documents").update({"rejected": True}).eq("id", document_id)
    )
    return jsonify({"ok": True})


@document_bp.route("/<int:document_id>/stages/<int:stage_order>/comments", methods=["POST"])
def add_comment(document_id, stage_order):
    err = require_login()
    if err:
        return err
    err = block_if_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    text = (body.get("body") or "").strip()
    if not text:
        return jsonify({"error": "Comment body is required"}), 400

    stage = get_stage(document_id, stage_order)
    if not stage:
        return jsonify({"error": "Stage not found"}), 404

    err = block_if_no_stage_permission(stage)
    if err:
        return err

    author_id = get_user_id(current_username())
    if not author_id:
        return jsonify({"error": "Current user record not found"}), 400

    res = execute_with_retry(
        supabase.table("document_comments").insert({
            "document_id": document_id,
            "stage_id": stage["id"],
            "author_id": author_id,
            "body": text,
        })
    )
    return jsonify(res.data[0] if res.data else {"ok": True})

document_bp.before_request(entity_permission_hook("tracking"))