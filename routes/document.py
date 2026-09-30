import logging
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify, session
from supabase_client import supabase
from auth.Rolemanagement import is_admin, get_user_permissions

document_bp = Blueprint("document", __name__, url_prefix="/api/documents")

logger = logging.getLogger(__name__)

# Substrings that identify a *transient* socket hiccup rather than a
# real database/query problem. [WinError 10035] (WSAEWOULDBLOCK, "A
# non-blocking socket operation could not be completed immediately")
# is the big one on Windows dev machines: it surfaces when two
# requests race to use the shared `supabase` httpx client at nearly
# the same instant — e.g. the frontend firing loadList() and
# loadHandlers() together on page mount — not because anything is
# actually wrong with the query or the data.
_TRANSIENT_ERROR_MARKERS = ("10035", "WinError", "WSAEWOULDBLOCK", "temporarily unavailable")


# WORKFLOW FIX (Posting Period): how many days a document must remain
# posted before the "Posting Period" stage can be completed. Used by
# start_posting_period() below to compute posting_end_at, and by
# complete_stage() to refuse completing this stage until that many
# days have actually elapsed.
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

# WORKFLOW FIX: the four allowed release destinations for the final
# "Releasing" stage.
RELEASE_DESTINATIONS = ["Owner's Copy", "Hospital", "PSA", "Archive Office"]

# ─────────────────────────────────────────────────────────────────────────
# SCHEMA REQUIREMENT for the personnel delete/restore fix used below:
#
#   ALTER TABLE document_personnel ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
#   ALTER TABLE documents ADD COLUMN IF NOT EXISTS deleted_handler_id integer
#     REFERENCES document_personnel(id);
#
# Run these once against the database before deploying this version —
# delete_handler() / assign_handler() / list_handlers() / add_handler()
# below all assume both columns already exist.
#
# SCHEMA REQUIREMENT for the workflow fix below (see
# migration_workflow_fields.sql):
#
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS registry_number text;
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS release_destination text;
#
# complete_stage() / save_registry_number() / save_release_destination()
# below all assume these columns already exist.
#
# SCHEMA REQUIREMENT for the Posting Period stage below:
#
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS posting_start_at timestamptz;
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS posting_end_at timestamptz;
#
# complete_stage() / start_posting_period() below assume these columns
# already exist. (These are the same posting_start_at / posting_end_at
# columns referenced by an earlier, since-removed Posting Period stage;
# they are back in active use now that the stage has been reintroduced.)
#
# ── SCHEMA REQUIREMENT for the PER-STAGE HANDLER FIX (NEW) ──────────────
#
#   ALTER TABLE document_stages ADD COLUMN IF NOT EXISTS assigned_handler_id
#     integer REFERENCES document_personnel(id);
#
# This is the one new column the per-stage "Currently handling" fix
# needs: each stage row now carries ITS OWN handler, independent of
# documents.assigned_handler_id. get_document_detail() reads it,
# assign_stage_handler() writes it, and delete_handler() clears it.
# Nothing else in this file changed behaviour because of it.
# ─────────────────────────────────────────────────────────────────────────


def execute_with_retry(query_builder, attempts=3, base_delay=0.2):
    """
    Calls .execute() on a Supabase/PostgREST query builder, retrying a
    couple of times (with a short backoff) if the failure looks like
    the transient socket issue above. Anything else — a real
    permission error, a missing table/column, a genuine connection
    failure — is raised immediately on the first try, so real problems
    still surface right away instead of being masked by retries.
    """
    last_err = None
    for attempt in range(attempts):
        try:
            return query_builder.execute()
        except Exception as e:
            last_err = e
            if attempt < attempts - 1 and any(marker in str(e) for marker in _TRANSIENT_ERROR_MARKERS):
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise last_err


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────

# Maps the lowercase Postgres enum values in documents.status to the
# human-readable labels the frontend's STATUS_STYLES / FILTERS expect.
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
        return jsonify({"error": "Not authenticated"}), 401
    return None


def block_if_admin():
    """
    Returns an error response tuple if the current user is an admin,
    else None.

    ROLE POLICY: called again by complete_stage(), flag_stage(),
    reject_document(), add_comment(), save_registry_number(),
    save_release_destination(), and start_posting_period() below.
    Administrators are strictly view-only on working a document — they
    monitor status, create new documents, and administer
    personnel/assignment, but they never complete/flag/reject/comment
    on a stage themselves, regardless of whether a handler is
    assigned. This is what makes the "regular users are the only ones
    who handle/process/move/update documents" rule actually enforced
    server-side, not just a UI convention the frontend happens to
    follow.
    """
    if is_admin(current_username()):
        return jsonify({"error": "Admins have view-only access to Document Tracking"}), 403
    return None


# ─────────────────────────────────────────────────────────────────────────
# STAGE PERMISSION FIX (NEW)
# ─────────────────────────────────────────────────────────────────────────
# Every Document Tracking pipeline stage has its own dedicated
# permission module (document_stage_registration,
# document_stage_civil_registrar, document_stage_posting_period,
# document_stage_records_division, document_stage_registry_number,
# document_stage_releasing — see DOCUMENT_TRACKING_STAGE_MODULES /
# BUILTIN_ROLE_PERMISSIONS in auth/Rolemanagement.py), and each of the
# six Document Tracking stage roles (Registration, Civil Registrar,
# Posting Period, Records Division, Assign Registry Number, Releasing)
# is meant to hold exactly one of them.
#
# Nothing below this comment existed before this fix. Previously,
# every stage-mutating route in this file only ever called
# block_if_admin() — which only asks "is this user an admin?" and
# says nothing about "does this user's role match THIS stage?". Once
# any non-admin user was assigned as a document's handler, they could
# complete/flag/reject/comment/save-registry-number/save-release-
# destination/start-posting-period on *any* active stage of that
# document, regardless of which single stage permission their actual
# role granted them. That's exactly how a user whose only role is
# "Assign Registry Number" could still act on the Registration or
# Civil Registrar stages: nothing ever checked their permissions
# against the stage being acted on.
#
# _stage_permission_for_label() below identifies the required
# permission purely from the stage's label text, mirroring how
# _is_registry_number_stage() / _is_releasing_stage() /
# _is_posting_period_stage() further down already identify these same
# stages — so documents running an older/custom workflow whose stage
# labels don't match any of the six known names are left unrestricted,
# exactly like those existing label-matched checks already behave.
# block_if_no_stage_permission() is then called, in ADDITION to (never
# instead of) block_if_admin(), on every stage-mutating route below.
# ─────────────────────────────────────────────────────────────────────────

def _stage_permission_for_label(label):
    """
    STAGE PERMISSION FIX: maps a document_stages.label to the single
    document_stage_* permission module (see
    DOCUMENT_TRACKING_STAGE_MODULES in auth/Rolemanagement.py) that
    scopes a role to acting on that one stage. Returns None for a
    label that doesn't match any of the six known stages, so such a
    stage is left unrestricted rather than blocked against a
    permission that doesn't exist.
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
    STAGE PERMISSION FIX: returns an error response tuple if the
    current user's role does not carry the specific document_stage_*
    permission required for this stage, else None.

    Called alongside block_if_admin() (never instead of it) on every
    stage-mutating route below, so admins remain fully blocked exactly
    as before, and non-admins are now further scoped to only the one
    stage their role actually grants — e.g. a user whose only role is
    "Assign Registry Number" (permission document_stage_registry_number)
    is refused here on the Registration / Civil Registrar / Posting
    Period / Records Division / Releasing stages, and only allowed
    through on the "Assign Registry Number" stage.

    A wildcard permission ("*") passes every stage, matching how a "*"
    role is already treated as full access everywhere else (see
    hasAccess() in PermissionContext.jsx and is_admin()/get_roles() in
    Rolemanagement.py).
    """
    required_permission = _stage_permission_for_label(stage.get("label"))
    if not required_permission:
        return None
    perms = get_user_permissions(current_username())
    if "*" in perms or required_permission in perms:
        return None
    return (
        jsonify({
            "error": "Access denied — your role does not include this Document Tracking stage"
        }),
        403,
    )


# ─────────────────────────────────────────────────────────────────────────
# ROLE-BASED HANDLER FIX (NEW)
# ─────────────────────────────────────────────────────────────────────────
# "Currently handling" on a stage previously could only ever come from
# document_stages.assigned_handler_id (a document_personnel row, set via
# the now-removed per-stage assign UI in document_tracking.jsx). But the
# ACTUAL way someone gets scoped to a stage today is Role Management's
# "Document Tracking Credentials" tab: assigning a user a stage role
# (Registration, Civil Registrar, etc.) writes a user_roles row carrying
# the matching document_stage_* permission (see BUILTIN_ROLE_PERMISSIONS
# / CATEGORY_MODULES in auth/Rolemanagement.py). Nothing previously
# connected that assignment back to "Currently handling", which is why a
# user given the "Registration" role in Role Management still showed
# "Unsigned" there.
#
# _get_stage_handler_username() below closes that gap: for a given
# document_stage_* permission, it finds the username currently holding a
# Document Tracking role that grants it, and get_document_detail() uses
# that username as the stage's displayed handler when one is found. It
# never matches the Administrator role (which technically carries every
# permission via ALL_MODULES) or the reserved "admin" account, and it is
# scoped to category="document" wherever that column exists, so it can
# only ever pick up an actual Document Tracking Credentials assignment —
# never a Vital Record Management or Admin one.
#
# This is purely additive: if no one currently holds the stage's
# permission, behaviour falls back exactly to the existing
# document_personnel-based resolution already in get_document_detail().
# ─────────────────────────────────────────────────────────────────────────

_DOC_CATEGORY_COLUMN_OK = None


def _document_category_column_available():
    """
    ROLE-BASED HANDLER FIX: True when user_roles.category exists, so
    _get_stage_handler_username() / _get_stage_handler_usernames()
    below can scope their lookup to category="document" (Document
    Tracking Credentials only). Probed once per process and cached,
    mirroring the same probe pattern already used in
    auth/Rolemanagement.py for this exact column.
    """
    global _DOC_CATEGORY_COLUMN_OK
    if _DOC_CATEGORY_COLUMN_OK is not None:
        return _DOC_CATEGORY_COLUMN_OK
    try:
        execute_with_retry(supabase.table("user_roles").select("category").limit(1))
        _DOC_CATEGORY_COLUMN_OK = True
    except Exception:
        _DOC_CATEGORY_COLUMN_OK = False
    return _DOC_CATEGORY_COLUMN_OK


def _get_stage_handler_username(permission):
    """
    ROLE-BASED HANDLER FIX: returns the username currently holding a
    Document Tracking role that grants `permission` (e.g.
    "document_stage_registration"), or None if nobody currently does.

    Reads user_roles joined with roles(name, permissions) — the exact
    same data Role Management's "Document Tracking Credentials" tab is
    built from — rather than document_personnel, so this reflects
    whoever was actually assigned there (see Image 1: assigning
    "jamaica" the "Registration" role is what should make jamaica show
    up as "Currently handling" on the Registration stage).

    Deliberately skips the Administrator role and the reserved "admin"
    account: Administrator's permission list is ALL_MODULES, so without
    this exclusion every stage would resolve to "admin" instead of the
    actual assigned user.

    NOTE: kept as a single-permission lookup for any other/future
    caller that only needs one permission resolved. get_document_detail()
    below no longer calls this in a per-stage loop — see the
    PER-REQUEST QUERY-COUNT FIX and _get_stage_handler_usernames()
    just below for why, and for the batched version it uses instead.
    """
    if not permission:
        return None
    try:
        query = supabase.table("user_roles").select("username, roles(name, permissions)")
        if _document_category_column_available():
            query = query.eq("category", "document")
        res = execute_with_retry(query)
    except Exception:
        logger.exception("Failed to resolve role-based handler for permission %s", permission)
        return None

    for row in (res.data or []):
        role = row.get("roles")
        if isinstance(role, list):
            role = role[0] if role else None
        if not role:
            continue
        if (role.get("name") or "") == "Administrator":
            continue
        raw_perms = role.get("permissions")
        if isinstance(raw_perms, str):
            try:
                import json
                raw_perms = json.loads(raw_perms)
            except Exception:
                raw_perms = []
        if raw_perms and permission in raw_perms:
            username = row.get("username")
            if username and username.lower() != "admin":
                return username
    return None


def _get_stage_handler_usernames(permissions):
    """
    PER-REQUEST QUERY-COUNT FIX (NEW): batched counterpart to
    _get_stage_handler_username() above.

    get_document_detail() used to call _get_stage_handler_username()
    once per stage — a fresh user_roles/roles Supabase query every
    single time. For the current 6-stage workflow (Registration,
    Civil Registrar, Posting Period, Records Division, Assign Registry
    Number, Releasing) that meant up to 6 extra near-simultaneous
    queries on a single GET /api/documents/<id> call — fired at the
    exact same moment the frontend's runAction() also fires a parallel
    GET /api/documents (see the Promise.all(...) in runAction() in
    document_tracking.jsx). That is exactly the kind of concurrent-
    request burst _TRANSIENT_ERROR_MARKERS / execute_with_retry above
    already exist to work around (the Windows "WinError 10035" socket
    race). Adding the Posting Period stage brought the workflow to its
    current 6 stages — enough extra concurrent load that
    execute_with_retry's 3 short retries could no longer reliably
    absorb the race, which is what surfaced as the detail request
    "hanging" and then failing to load right after completing or
    commenting on a stage.

    This does the same lookup ONCE for every permission any of the
    document's stages actually needs, in a single query, and returns
    {permission: username} for every permission that currently has
    someone assigned via a Document Tracking role — omitting any
    permission nobody currently holds, exactly like
    _get_stage_handler_username() returning None for that case.
    Selection rules (skip the Administrator role, skip the reserved
    "admin" account, first matching row wins for a given permission)
    are identical to _get_stage_handler_username() above — this is
    purely a batching fix, not a behavior change.
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
            break  # every requested permission already has a match
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
                import json
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


def require_admin():
    """
    Returns an error response tuple if the current user is NOT an
    admin, else None. Used for the administration actions in this
    module: managing the handler pool (adding/removing a person),
    assigning a handler to a specific document, and — per the
    PER-STAGE HANDLER FIX — assigning a handler to a specific stage of
    a document. Deciding who's allowed to handle documents, and who
    handles which one (and which step of it), are all administration
    actions, not something a handler grants themselves.
    """
    if not is_admin(current_username()):
        return jsonify({"error": "Admin access required"}), 403
    return None


def get_user_id(username):
    """
    Resolve a username to its Supabase users.id. Used only for
    author_id / assigned_by_id / owner_id — i.e. which logged-in
    account performed an action. This is unrelated to
    document_personnel (who is assignable as a handler), which never
    touches `users`.
    """
    res = execute_with_retry(
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
    )
    return res.data[0]["id"] if res.data else None


def get_stage(document_id, stage_order):
    """Fetch a single stage row by (document_id, stage_order), or None."""
    res = execute_with_retry(
        supabase.table("document_stages")
        .select("*")
        .eq("document_id", document_id)
        .eq("stage_order", stage_order)
        .limit(1)
    )
    return res.data[0] if res.data else None


def _document_has_progress(document_id):
    """
    HANDLER-LOCK FIX: True if this document has at least one stage
    with done=True — i.e. real work has already happened under
    whoever is currently assigned. Used by assign_handler() to refuse
    reassignment once that's the case (except for the
    REASSIGN-AFTER-DELETE exception carved out there).
    """
    res = execute_with_retry(
        supabase.table("document_stages")
        .select("id, done")
        .eq("document_id", document_id)
    )
    return any(s.get("done") for s in (res.data or []))


def _is_registry_number_stage(stage):
    """WORKFLOW FIX: identifies the "Assign Registry Number" stage by label."""
    return "registry number" in (stage.get("label") or "").lower()


def _is_releasing_stage(stage):
    """WORKFLOW FIX: identifies the final "Releasing" stage by label."""
    return (stage.get("label") or "").strip().lower() == "releasing"


def _is_posting_period_stage(stage):
    """WORKFLOW FIX: identifies the "Posting Period" stage by label."""
    return (stage.get("label") or "").strip().lower() == "posting period"


# ─────────────────────────────────────────────────────────────────────────
# POSTING PERIOD FIX (doc-type gating) — NEW
# ─────────────────────────────────────────────────────────────────────────
# The "Posting Period" stage's 10-day window (and, per this fix, its
# required explanatory comment) only applies to documents that are
# actually a Late Registration. Every other document type should skip
# this stage's extra requirements entirely and complete it like any
# other pass-through stage, once its assigned handler acts on it.
#
# _document_is_late_registration() below is the single source of
# truth complete_stage() consults for this, mirroring
# isLateRegistrationDocType() in document_tracking.jsx exactly (same
# case-insensitive substring match against the document's doc_type).
# ─────────────────────────────────────────────────────────────────────────

def _document_is_late_registration(document_id):
    """
    POSTING PERIOD FIX (doc-type gating): True when this document's
    doc_type indicates a Late Registration — the only case where the
    "Posting Period" stage requires its 10-day window (and an
    explanatory comment) before it can be completed. Matched by a
    case-insensitive substring check against documents.doc_type,
    mirroring how every other label-matched check in this file (e.g.
    _is_posting_period_stage() above) is intentionally loose about
    exact formatting. Any document whose doc_type does not mention
    "late registration" skips the posting requirement entirely and
    this stage behaves like a normal pass-through step for it.
    """
    try:
        res = execute_with_retry(
            supabase.table("documents")
            .select("doc_type")
            .eq("id", document_id)
            .limit(1)
        )
    except Exception:
        logger.exception("Failed to check doc_type for document %s", document_id)
        return False
    if not res.data:
        return False
    doc_type = (res.data[0].get("doc_type") or "").strip().lower()
    return "late registration" in doc_type


def _get_active_stage(document_id):
    """
    WORKFLOW FIX: returns the current active stage row (the first
    stage that is neither done nor flagged) for a document, or None if
    every stage is done. Mirrors getActiveIndex() in
    document_tracking.jsx, and is what lets complete_stage() below
    refuse to complete a stage out of order.
    """
    res = execute_with_retry(
        supabase.table("document_stages")
        .select("*")
        .eq("document_id", document_id)
        .order("stage_order")
    )
    for s in (res.data or []):
        if not s.get("done") or s.get("flag"):
            return s
    return None


def _handler_names(handler_ids):
    """
    Batch-resolve a list of document_personnel.id -> full_name.
    PERSONNEL FIX: previously resolved against `users`; now reads
    exclusively from the dedicated document_personnel table.

    Deliberately NOT filtered by deleted_at: callers may need to
    resolve the display name of a soft-deleted person too (e.g. the
    "Restore to <name>" recovery option, or an "owner" that happens to
    still be a soft-deleted person after a restore) — see the
    RESTORE FIX notes in list_documents() / get_document_detail() /
    delete_handler() / assign_handler() below.
    """
    handler_ids = [h for h in set(handler_ids) if h]
    if not handler_ids:
        return {}
    res = execute_with_retry(
        supabase.table("document_personnel")
        .select("id, full_name")
        .in_("id", handler_ids)
    )
    return {p["id"]: p["full_name"] for p in (res.data or [])}


def _summarize_document(row, handler_names):
    """
    Shapes a raw `documents` row into what the frontend expects, using
    the same field names the frontend already reads first (title,
    type, status, owner, updated_at, assigned_handler_id) so this
    lines up with document_tracking.jsx's mapping without needing any
    changes there.

    documents.doc_type -> "type", and documents.status (a lowercase
    Postgres enum) is translated to the human-readable label the
    frontend's STATUS_STYLES / FILTERS keys on, via STATUS_LABELS.

    RESTORE FIX: also surfaces deleted_handler_id / deleted_handler_name
    when this document was left unassigned by a personnel deletion
    (see delete_handler() below). The frontend uses this pair to offer
    a "Restore to <name>" option in the handler dropdown, and
    assign_handler() is what actually enforces that this can only be
    used to put this exact document back with this exact person (or,
    per the ADMIN FULL-REASSIGN FIX, with anyone at all).
    """
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
# 1. Handler dropdown — "who should handle this document"
#    PERSONNEL FIX: reads from document_personnel, a table dedicated to
#    Document Tracking names only — never from `users` (login
#    accounts), so a real account can never appear here.
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/handlers", methods=["GET"])
def list_handlers():
    err = require_login()
    if err:
        return err

    try:
        # RESTORE FIX: soft-deleted personnel (deleted_at set — see
        # delete_handler() below) are excluded from the normal pool so
        # they read as fully removed everywhere in ordinary use. The
        # one exception (reassigning a specific document back to
        # exactly the person who used to handle it) is offered by the
        # frontend directly from the document's own deleted_handler_id
        # / deleted_handler_name, not from this list.
        res = execute_with_retry(
            supabase.table("document_personnel")
            .select("id, full_name")
            .is_("deleted_at", "null")
        )
    except Exception as e:
        logger.exception("Failed to query handlers")
        return jsonify({"error": f"Database error while loading handlers: {e}"}), 500

    handlers = [
        {"id": p["id"], "name": p["full_name"]}
        for p in (res.data or [])
    ]
    handlers.sort(key=lambda h: h["name"].lower())
    return jsonify(handlers)


# ─────────────────────────────────────────────────────────────────────────
# 1b. Add a new person to the handler pool — admin-only. Deciding who's
#     allowed to handle documents is an administration action.
#     PERSONNEL FIX: inserts a bare full_name into document_personnel.
#     No username, no password, no `users` row — this cannot create a
#     login account of any kind.
#     FIX 4: .select() forces the inserted row back in the response so
#     the frontend can merge it into local state immediately, instead
#     of only appearing after a reload.
# ─────────────────────────────────────────────────────────────────────────

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
        # Case-insensitive duplicate check (the table also enforces
        # this at the DB level via a unique index on lower(full_name),
        # so this is a friendlier error message on top of that, not
        # the only thing preventing a duplicate).
        # RESTORE FIX: scoped to non-deleted rows only, so re-adding a
        # name that belongs to a soft-deleted person (see
        # delete_handler() below) doesn't get incorrectly blocked as
        # "already in the list" — from this endpoint's point of view a
        # soft-deleted person isn't in the list anymore.
        existing = execute_with_retry(
            supabase.table("document_personnel")
            .select("id")
            .ilike("full_name", name)
            .is_("deleted_at", "null")
            .limit(1)
        )
        if existing.data:
            return jsonify({"error": "This person is already in the list"}), 409

        # FIX 4: explicitly request the inserted row back. Without
        # .select(...) here, some client/PostgREST configurations
        # return an empty `data` list on a successful insert, which
        # made this endpoint report a false 500 and left the frontend
        # unable to show the new person without a manual refresh.
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
    return (
        jsonify(
            {
                "id": new_person["id"],
                "name": new_person.get("full_name") or name,
            }
        ),
        201,
    )


# ─────────────────────────────────────────────────────────────────────────
# 1c. Remove a person from the handler pool.
#     PERSONNEL REMOVE FIX: this route was missing entirely, which is
#     why the trash icon in "Add person" did nothing — every click hit
#     a 404 that the frontend's apiFetch() surfaced as a generic
#     "Could not remove this person." Admin-only, same as add_handler().
#
#     RESTORE FIX: this now soft-deletes (stamps deleted_at) instead of
#     hard-deleting the row. A hard delete permanently destroyed the
#     document_personnel row, so an accidental removal could never be
#     undone: assign_handler()'s validation checks handler_id against
#     document_personnel, and a deleted row can never pass that check
#     again. Soft-deleting keeps the row around (hidden from
#     list_handlers() and from add_handler()'s duplicate check, so it
#     still reads as fully removed everywhere in normal use) so that
#     the one document this person was actually handling can still be
#     restored to them specifically — see the deleted_handler_id
#     bookkeeping below and the matching check in assign_handler().
#
#     PER-STAGE HANDLER FIX: any per-stage assignments pointing at this
#     person are cleared too, so a removed person can never linger as a
#     stage's "Currently handling" value. Those stages simply read as
#     "Unsigned" again until an admin assigns someone to them.
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/handlers/<int:handler_id>", methods=["DELETE"])
def delete_handler(handler_id):
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
        # RESTORE FIX: before unassigning, remember which document(s)
        # currently point at this handler, so the specific document(s)
        # they were actually handling can be stamped with
        # deleted_handler_id below — the one thing that lets
        # assign_handler() later recognize "this document, and only
        # this document, can be restored to this exact removed
        # person".
        affected = execute_with_retry(
            supabase.table("documents")
            .select("id")
            .eq("assigned_handler_id", handler_id)
        )
        affected_ids = [d["id"] for d in (affected.data or [])]

        if affected_ids:
            # Unassign, but record who it *was* assigned to in
            # deleted_handler_id so the frontend can offer "restore to
            # <name>" and assign_handler() can verify that specific
            # (document_id, handler_id) pairing before allowing it.
            execute_with_retry(
                supabase.table("documents")
                .update({"assigned_handler_id": None, "deleted_handler_id": handler_id})
                .eq("assigned_handler_id", handler_id)
            )

        # PER-STAGE HANDLER FIX: clear this person off any individual
        # stage they were assigned to, so no stage keeps displaying a
        # removed person as its "Currently handling". Touches only the
        # new document_stages.assigned_handler_id column — every other
        # column on those stage rows (done/flag/registry_number/…) is
        # left exactly as it was.
        execute_with_retry(
            supabase.table("document_stages")
            .update({"assigned_handler_id": None})
            .eq("assigned_handler_id", handler_id)
        )

        # Clear assignment history rows for this handler too, in case
        # document_assignments.handler_id has a foreign key back to
        # document_personnel.id that would otherwise block the delete.
        execute_with_retry(
            supabase.table("document_assignments")
            .delete()
            .eq("handler_id", handler_id)
        )

        # RESTORE FIX: soft-delete (stamp deleted_at) instead of
        # deleting the row outright — see the docstring above for why.
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
# 2. Document list — left panel
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("", methods=["GET"])
def list_documents():
    err = require_login()
    if err:
        return err

    try:
        res = execute_with_retry(
            supabase.table("documents").select("*").order("updated_at", desc=True)
        )
        rows = res.data
    except Exception as e:
        # A failed/misconfigured query (missing table/column, RLS
        # denial, etc.) would otherwise bubble up as an unhandled
        # exception and Flask would return a bare, non-JSON 500 — the
        # frontend then has no message to show beyond "Request failed
        # (500)". Surfacing the real message here makes that
        # diagnosable instead of a silent dead end.
        logger.exception("Failed to query documents")
        return jsonify({"error": f"Database error while loading documents: {e}"}), 500

    if rows is None:
        # A failed/misconfigured query can also come back as data=None
        # instead of raising — surface that as a real error instead of
        # quietly rendering "0 documents".
        return jsonify({"error": "Could not load documents from the database"}), 500

    try:
        # RESTORE FIX: also resolve deleted_handler_id's name, not
        # just assigned_handler_id's, so _summarize_document() can
        # label each document's "restore to <name>" recovery target
        # (if any) correctly.
        handler_ids = []
        for r in rows:
            handler_ids.append(r.get("assigned_handler_id"))
            handler_ids.append(r.get("deleted_handler_id"))
        handler_names = _handler_names(handler_ids)
        documents = [_summarize_document(r, handler_names) for r in rows]
    except Exception as e:
        logger.exception("Failed to shape document rows")
        return jsonify({"error": f"Server error while processing documents: {e}"}), 500

    return jsonify(documents)


# ─────────────────────────────────────────────────────────────────────────
# 2b. Create a document/request record.
#     ADMIN-ONLY (require_admin()). Regular users only handle,
#     process, and move documents already assigned to them — they
#     never create new document/request records. Assigning who
#     *handles* a newly created document still requires the existing
#     /assign endpoint below (also admin-only).
#
#     doc_number is REQUIRED from the client, typed in by whoever
#     creates the document. The trg_generate_doc_number trigger
#     (doc_number_format.sql) is left in place untouched — it still
#     only fires when doc_number is NULL, so it now simply acts as a
#     fallback/safety net for any insert that somehow omits it (e.g. a
#     future script or a different caller), rather than as the normal
#     path. A pre-check against the documents table gives a clear
#     "already in use" error instead of a raw Postgres unique-
#     violation message bubbling up from the UNIQUE constraint on
#     documents.doc_number.
#
#     WORKFLOW FIX: STARTER_STAGES now seeds the current 6-stage civil-
#     registry workflow (Registration -> Civil Registrar -> Posting
#     Period -> Records Division -> Assign Registry Number ->
#     Releasing). Nothing else about document creation changed.
#
#     PER-STAGE HANDLER FIX: newly seeded stages deliberately carry NO
#     handler at all (assigned_handler_id stays NULL), so every stage
#     starts out reading "Unsigned" rather than inheriting anyone.
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("", methods=["POST"])
def create_document():
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
            supabase.table("documents")
            .select("id")
            .ilike("doc_number", doc_number)
            .limit(1)
        )
        if existing.data:
            return jsonify({"error": f'"{doc_number}" is already in use by another document'}), 409

        # status and rejected are left out on purpose — they default at
        # the column level ('in_review' / false). doc_number IS
        # supplied now, so trg_generate_doc_number's "IF NEW.doc_number
        # IS NOT NULL THEN RETURN NEW" branch fires and leaves it
        # exactly as typed.
        # .select() forces the inserted row back in the response — same
        # reasoning as FIX 4 on add_handler() above.
        doc_res = execute_with_retry(
            supabase.table("documents")
            .insert(
                {
                    "doc_number": doc_number,
                    "title": title,
                    "doc_type": doc_type,
                    "owner_id": owner_id,
                    "assigned_handler_id": None,
                }
            )
            .select("*")
        )
    except Exception as e:
        logger.exception("Failed to create document")
        return jsonify({"error": f"Could not create this document: {e}"}), 500

    if not doc_res.data:
        return jsonify({"error": "Could not create this document"}), 500

    new_doc = doc_res.data[0]

    try:
        # Seed the starter stage set so the timeline/active-step logic
        # on the frontend has something to show immediately.
        execute_with_retry(
            supabase.table("document_stages").insert(
                [
                    {
                        "document_id": new_doc["id"],
                        "stage_order": s["stage_order"],
                        "label": s["label"],
                        "detail": s["detail"],
                        "done": False,
                        "flag": False,
                    }
                    for s in STARTER_STAGES
                ]
            )
        )
    except Exception as e:
        # The document row itself was created successfully; failing to
        # seed stages shouldn't be reported as if the whole create
        # failed, but it does need to be visible rather than silent.
        logger.exception("Document %s created but failed to seed stages", new_doc.get("id"))
        return (
            jsonify(
                {
                    **_summarize_document(new_doc, {}),
                    "warning": f"Document created, but starter stages could not be added: {e}",
                }
            ),
            201,
        )

    return jsonify(_summarize_document(new_doc, {})), 201


# ─────────────────────────────────────────────────────────────────────────
# 3. Document detail — stages + comments, for the right panel
#
#    WORKFLOW FIX: also surfaces registry_number / release_destination
#    at the top level of the returned document, pulled from whichever
#    stage actually carries them, so the frontend can show them in the
#    document's header/tracking info without an extra request.
#
#    PER-STAGE HANDLER FIX: every returned stage now carries its OWN
#    assigned_handler_id and the resolved assigned_handler_name for
#    exactly that id — resolved per stage, never borrowed from the
#    document's assigned_handler_id and never defaulted to the first
#    person in the handler pool. A stage with no handler comes back
#    with assigned_handler_id = None and assigned_handler_name = None,
#    which the frontend renders as "Unsigned".
#
#    ROLE-BASED HANDLER FIX (NEW): each stage's assigned_handler_name
#    is now additionally checked against whoever currently holds that
#    stage's document_stage_* permission via Role Management's
#    Document Tracking Credentials. When someone holds it, THEIR
#    username is what's shown — this takes priority over the
#    document_personnel-based name above, since that's the system
#    actually used to assign people to stages today. If nobody
#    currently holds the permission, the existing document_personnel-
#    based name (or None -> "Unsigned") is left exactly as it was.
#
#    PER-REQUEST QUERY-COUNT FIX (NEW): this used to resolve that
#    role-based name by calling _get_stage_handler_username() once per
#    stage (one Supabase query each). That is now done in a single
#    batched call to _get_stage_handler_usernames() before the loop —
#    see that function's docstring for why the per-stage version was
#    causing the detail request to intermittently fail to load right
#    after acting on a stage (most visibly once the Posting Period
#    stage brought the workflow to 6 stages). This is a pure
#    performance/reliability change: the set of permissions resolved,
#    and the priority/fallback rules for each stage's displayed name,
#    are unchanged.
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/<int:document_id>", methods=["GET"])
def get_document_detail(document_id):
    err = require_login()
    if err:
        return err

    try:
        doc_res = execute_with_retry(
            supabase.table("documents")
            .select("*")
            .eq("id", document_id)
            .limit(1)
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
        # RESTORE FIX: resolve deleted_handler_id's name too — see
        # _summarize_document() and list_documents() above.
        handler_names = _handler_names([row.get("assigned_handler_id"), row.get("deleted_handler_id")])
        document = _summarize_document(row, handler_names)

        stages_res = execute_with_retry(
            supabase.table("document_stages")
            .select("*")
            .eq("document_id", document_id)
            .order("stage_order")
        )
        stages = stages_res.data or []

        # PER-STAGE HANDLER FIX: resolve each stage's own handler name
        # from that stage's own assigned_handler_id, in one batched
        # lookup. Stages with no handler are left as None on purpose —
        # there is deliberately no fallback to the document's handler
        # or to any other stage's handler.
        stage_handler_names = _handler_names(
            [s.get("assigned_handler_id") for s in stages]
        )

        # PER-REQUEST QUERY-COUNT FIX (NEW): resolve every stage's
        # document_stage_* permission up front, then look all of them
        # up in ONE Supabase query via _get_stage_handler_usernames(),
        # instead of the loop below calling
        # _get_stage_handler_username() separately for every stage
        # (which is what used to turn a single document-detail fetch
        # into up to 6 extra queries). See that function's docstring
        # for the full reasoning.
        stage_permissions = [_stage_permission_for_label(s.get("label")) for s in stages]
        role_based_usernames = _get_stage_handler_usernames(stage_permissions)

        for s in stages:
            stage_handler_id = s.get("assigned_handler_id")
            s["assigned_handler_id"] = stage_handler_id
            s["assigned_handler_name"] = (
                stage_handler_names.get(stage_handler_id) if stage_handler_id else None
            )

            # ROLE-BASED HANDLER FIX: if a user currently holds this
            # stage's document_stage_* permission via Role Management's
            # Document Tracking Credentials, their username takes
            # priority for display over the document_personnel-based
            # name resolved above. Falls back to whatever was already
            # set (including None -> "Unsigned" on the frontend) when
            # nobody currently holds that permission, so this can never
            # make an already-working assignment disappear.
            stage_permission = _stage_permission_for_label(s.get("label"))
            role_based_username = role_based_usernames.get(stage_permission)
            if role_based_username:
                s["assigned_handler_name"] = role_based_username

        comments_res = execute_with_retry(
            supabase.table("document_comments")
            .select("*")
            .eq("document_id", document_id)
            .order("created_at")
        )
        comments = comments_res.data or []

        # Resolve author display names in one extra query, then attach
        # each comment to its stage. Comment authors are logged-in
        # users (they wrote the comment), so this still resolves
        # against `users` — unrelated to document_personnel.
        author_ids = list({c["author_id"] for c in comments})
        authors = {}
        if author_ids:
            users_res = execute_with_retry(
                supabase.table("users")
                .select("id, full_name, username")
                .in_("id", author_ids)
            )
            authors = {
                u["id"]: (u.get("full_name") or u["username"]) for u in (users_res.data or [])
            }

        comments_by_stage = {}
        for c in comments:
            comments_by_stage.setdefault(c["stage_id"], []).append(
                {
                    "id": c["id"],
                    "author": authors.get(c["author_id"], "Unknown"),
                    "body": c["body"],
                    "created_at": c["created_at"],
                }
            )

        for s in stages:
            s["comments"] = comments_by_stage.get(s["id"], [])

        document["stages"] = stages

        # WORKFLOW FIX: surface the Registry Number / release
        # destination at the document level too (in addition to living
        # on their own stage rows), so the frontend can display them
        # in the document's tracking information without having to
        # search the stages array itself.
        document["registry_number"] = next(
            (s.get("registry_number") for s in stages if _is_registry_number_stage(s) and s.get("registry_number")),
            None,
        )
        document["release_destination"] = next(
            (s.get("release_destination") for s in stages if _is_releasing_stage(s) and s.get("release_destination")),
            None,
        )
    except Exception as e:
        logger.exception("Failed to assemble document detail for %s", document_id)
        return jsonify({"error": f"Server error while loading this document: {e}"}), 500

    return jsonify(document)


# ─────────────────────────────────────────────────────────────────────────
# 3b. Delete a document outright.
#     ADMIN-ONLY (require_admin()), same as add_handler() / assign_handler().
#     Regular users must never have access to this — they only handle,
#     process, and move documents already assigned to them, never
#     delete them. Child rows (comments, assignments, stages) are
#     deleted first so this works whether or not your schema has
#     ON DELETE CASCADE set up on their document_id foreign keys —
#     these deletes are a no-op if there's nothing to remove.
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/<int:document_id>", methods=["DELETE"])
def delete_document(document_id):
    err = require_login()
    if err:
        return err
    err = require_admin()
    if err:
        return err

    try:
        existing = execute_with_retry(
            supabase.table("documents")
            .select("id")
            .eq("id", document_id)
            .limit(1)
        )
    except Exception as e:
        logger.exception("Failed to look up document %s for deletion", document_id)
        return jsonify({"error": f"Database error while looking up this document: {e}"}), 500

    if not existing.data:
        return jsonify({"error": "Document not found"}), 404

    try:
        execute_with_retry(
            supabase.table("document_comments").delete().eq("document_id", document_id)
        )
        execute_with_retry(
            supabase.table("document_assignments").delete().eq("document_id", document_id)
        )
        execute_with_retry(
            supabase.table("document_stages").delete().eq("document_id", document_id)
        )
        execute_with_retry(
            supabase.table("documents").delete().eq("id", document_id)
        )
    except Exception as e:
        logger.exception("Failed to delete document %s", document_id)
        return jsonify({"error": f"Could not delete this document: {e}"}), 500

    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────
# 4. Assign / reassign the handler picked from the dropdown
#    ADMIN-ONLY: deciding who handles a given document is an
#    administration decision, same as deciding who's in the handler
#    pool at all (POST /handlers, above).
#    PERSONNEL FIX: validates handler_id against document_personnel
#    instead of users.
#    HANDLER-LOCK FIX: once the document has any completed (done=True)
#    stage, reassignment is refused outright — see _document_has_progress()
#    and the module docstring for the full reasoning.
#    RESTORE FIX: a soft-deleted person (deleted_at set) still has a
#    row in document_personnel, so the plain existence check below is
#    no longer enough on its own to gate assignment. The extra check
#    added restricts assigning to a deleted person to exactly the
#    accidental-deletion recovery case: this document's own
#    deleted_handler_id must match the handler_id being requested. A
#    still-active (never deleted) person is completely unaffected by
#    this — they're assignable to any (non-locked) document as before.
#    REASSIGN-AFTER-DELETE EXCEPTION (ADMIN FULL-REASSIGN FIX): if a
#    progressed document lost its handler to a deletion
#    (assigned_handler_id is null AND deleted_handler_id is set), the
#    HANDLER-LOCK FIX is lifted for that document. An admin may either
#    restore the exact person recorded in deleted_handler_id, or assign
#    any other active person from document_personnel — both are
#    accepted here now. A still-soft-deleted person other than the one
#    recorded in deleted_handler_id remains refused (see the
#    "not in the handler pool" check further below). Any OTHER
#    progressed document (i.e. not left unassigned by a personnel
#    deletion) still keeps the normal "already progressed" lock and
#    cannot be reassigned at all.
#
#    NOTE (PER-STAGE HANDLER FIX): this route is unchanged and still
#    governs the DOCUMENT-level handler only. Who is shown as
#    "Currently handling" on an individual stage comes from the
#    separate, per-stage route in 4b below and is never derived from
#    this value.
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/<int:document_id>/assign", methods=["POST"])
def assign_handler(document_id):
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

        # REASSIGN-AFTER-DELETE EXCEPTION to the HANDLER-LOCK FIX:
        # normally, once a document has progressed, reassignment is
        # refused outright. The one carve-out: if the document is
        # currently unassigned specifically because its handler was
        # removed (deleted_handler_id is set, assigned_handler_id is
        # null — see delete_handler() above), the lock would otherwise
        # strand the document forever with no one able to continue it.
        left_unassigned_by_deletion = (
            doc_lock_row.get("assigned_handler_id") is None
            and doc_lock_row.get("deleted_handler_id") is not None
        )

        has_progress = _document_has_progress(document_id)

        # HANDLER-LOCK FIX: once real work has happened (any stage
        # marked done), the handler assignment is locked — no further
        # reassignment, by anyone, for this document — unless the
        # REASSIGN-AFTER-DELETE exception above applies.
        if has_progress and not left_unassigned_by_deletion:
            return (
                jsonify(
                    {
                        "error": "This document has already progressed — the assigned "
                        "handler can no longer be changed."
                    }
                ),
                409,
            )

        # ADMIN FULL-REASSIGN FIX: previously, this branch rejected any
        # handler_id other than doc_lock_row["deleted_handler_id"] here,
        # restricting a progressed-but-deletion-orphaned document to
        # ONLY being restored to the exact person who was removed. Per
        # updated requirements, an admin can now assign this document to
        # any active person in the handler pool as well — not just
        # restore the deleted one — so that extra restriction has been
        # removed. The checks further below (handler must exist in
        # document_personnel, and a soft-deleted handler is only
        # accepted when it matches this document's own
        # deleted_handler_id) still fully apply and are what continue to
        # make "restore to the exact removed person" possible alongside
        # "assign anyone else".

        # Make sure this is actually someone in the handler pool
        # (added via "Add person" / POST /handlers), not an arbitrary
        # id — checked against document_personnel, not users.
        handler_check = execute_with_retry(
            supabase.table("document_personnel")
            .select("id, deleted_at")
            .eq("id", handler_id)
            .limit(1)
        )
        if not handler_check.data:
            return jsonify({"error": "That person isn't in the handler pool"}), 400

        # RESTORE FIX: if this person was soft-deleted, the only way
        # they can still be assigned is as the recovery target of the
        # exact document they were handling when they were removed —
        # i.e. this document's deleted_handler_id must equal their id.
        # Any other document, or any other deleted person, is refused
        # with the same "not in the handler pool" message a normal
        # invalid id would get, so this doesn't leak which ids exist.
        handler_row = handler_check.data[0]
        if handler_row.get("deleted_at") is not None:
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

        # RESTORE FIX: any successful assignment — whether restoring
        # to the deleted person or assigning someone else entirely on
        # a non-locked document (or, per the ADMIN FULL-REASSIGN FIX,
        # someone else entirely on a deletion-orphaned progressed
        # document) — clears deleted_handler_id, since the "this
        # document can still be restored to so-and-so" window closes
        # the moment the document has a handler again.
        #
        # Note: document_assignments' own AFTER INSERT trigger
        # (trg_sync_document_from_assignment_insert) also writes
        # assigned_handler_id from the row inserted below, but it does
        # not know about deleted_handler_id, so this explicit update is
        # still what clears that column — the trigger just re-confirms
        # the same handler_id a moment later, which is a harmless no-op.
        execute_with_retry(
            supabase.table("documents").update(
                {"assigned_handler_id": handler_id, "deleted_handler_id": None}
            ).eq("id", document_id)
        )

        # trg_close_previous_assignment (document_tracking.sql) closes
        # out any still-open assignment row for this document before
        # this insert lands, so idx_document_assignments_active is
        # never violated by a reassignment — including this
        # reassign-after-deletion path.
        execute_with_retry(
            supabase.table("document_assignments").insert(
                {
                    "document_id": document_id,
                    "handler_id": handler_id,
                    "assigned_by_id": assigned_by_id,
                    "note": note,
                }
            )
        )
    except Exception as e:
        logger.exception("Failed to assign handler for document %s", document_id)
        return jsonify({"error": f"Could not assign this person: {e}"}), 500

    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────
# 4b. PER-STAGE HANDLER FIX (NEW) — assign the person who handles ONE
#     specific stage of a document.
#
#     This route is what makes "Currently handling" correct per stage:
#     each document_stages row now stores its own assigned_handler_id
#     (see the SCHEMA REQUIREMENT block at the top of this file), so
#     Registration can be John Doe while Civil Registrar is Maria
#     Santos, and a stage nobody has been assigned to stays NULL — the
#     frontend renders that as "Unsigned" rather than falling back to
#     the document's handler or to the first name in the pool.
#
#     ADMIN-ONLY (require_admin()), exactly like assign_handler()
#     above: deciding who handles which step is an administration
#     decision, not something a handler grants themselves.
#
#     Sending handler_id = null (or omitting it) clears the stage's
#     handler, putting it back to "Unsigned". A handler_id must belong
#     to an ACTIVE (non soft-deleted) person in document_personnel;
#     anything else is refused with the same neutral message
#     assign_handler() uses, so this can't be used to probe which ids
#     exist.
#
#     This route deliberately does NOT touch documents.assigned_handler_id,
#     document_assignments, done/flag, or any workflow field — it only
#     writes the one new column, so no existing behaviour (the handler
#     lock, the restore-after-delete recovery, stage permissions,
#     status recomputation) is affected by it.
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/<int:document_id>/stages/<int:stage_order>/assign", methods=["POST"])
def assign_stage_handler(document_id, stage_order):
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

    # Treat null / "" / 0 as "clear this stage's handler" → "Unsigned".
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
        logger.exception(
            "Failed to assign stage handler for document %s stage %s", document_id, stage_order
        )
        return jsonify({"error": f"Could not assign this person to this step: {e}"}), 500

    return jsonify(
        {
            "ok": True,
            "stage_order": stage_order,
            "assigned_handler_id": handler_id,
            "assigned_handler_name": handler_name,
        }
    )


# ─────────────────────────────────────────────────────────────────────────
# 5. Mark the active stage complete ("Mark complete → next step")
#
#    ROLE POLICY: block_if_admin() is enforced here. Administrators are
#    view-only on working a document — they can never complete a
#    stage, including when the document is unassigned or the assigned
#    handler hasn't acted. Only a logged-in, non-admin user (the
#    assigned handler, per the frontend's gating) can call this.
#
#    STAGE PERMISSION FIX: block_if_no_stage_permission() is now also
#    enforced here, in addition to block_if_admin(). Previously any
#    non-admin assigned handler could complete ANY active stage; now
#    they must also hold the specific document_stage_* permission for
#    the stage being completed (e.g. only a "Assign Registry Number"
#    role can complete that stage — a "Registration" role gets a 403
#    here even if they're the document's assigned handler). Completing
#    a stage simply advances _get_active_stage() to the next stage row
#    as before, which is what "forwards" the document to the next
#    role's queue — that next stage then requires whichever
#    document_stage_* permission covers it before anyone can act on it.
#
#    WORKFLOW FIX (this route also enforces, in order):
#      1. SEQUENTIAL-ORDER — only the current active stage (mirrors
#         the frontend's own getActiveIndex()) may be completed, so a
#         direct API call can't skip ahead or re-complete a resolved
#         step out of order.
#      2. REGISTRY NUMBER — the "Assign Registry Number" stage can't
#         be completed until a Registry Number has been saved via
#         save_registry_number() below.
#      3. RELEASE DESTINATION — the final "Releasing" stage can't be
#         completed until a destination has been saved via
#         save_release_destination() below.
#      4. POSTING PERIOD — for a Late Registration document only (see
#         POSTING PERIOD FIX (doc-type gating) below), the "Posting
#         Period" stage can't be completed until the posting period
#         has been started via start_posting_period() below, AND
#         POSTING_PERIOD_DAYS days have actually elapsed since it
#         started, AND an explanatory comment has been added on this
#         stage. Any other document type skips this requirement
#         entirely and this stage completes like a normal step.
#    All label-matched checks match stages purely by label text (see
#    _is_registry_number_stage() / _is_releasing_stage() /
#    _is_posting_period_stage() / _stage_permission_for_label() above),
#    so documents still running an older workflow never match any of
#    them and behave exactly as they did before this change.
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/<int:document_id>/stages/<int:stage_order>/complete", methods=["POST"])
def complete_stage(document_id, stage_order):
    err = require_login()
    if err:
        return err
    err = block_if_admin()
    if err:
        return err

    stage = get_stage(document_id, stage_order)
    if not stage:
        return jsonify({"error": "Stage not found"}), 404

    # STAGE PERMISSION FIX: see module-level docstring above.
    err = block_if_no_stage_permission(stage)
    if err:
        return err

    # SEQUENTIAL-ORDER FIX: see docstring above.
    active_stage = _get_active_stage(document_id)
    if not active_stage or active_stage.get("stage_order") != stage_order:
        return jsonify({"error": "This step is not the current active step."}), 409

    # REGISTRY NUMBER FIX: see docstring above.
    if _is_registry_number_stage(stage) and not (stage.get("registry_number") or "").strip():
        return jsonify({"error": "Enter and save the Registry Number before completing this step."}), 409

    # RELEASE DESTINATION FIX: see docstring above.
    if _is_releasing_stage(stage) and not (stage.get("release_destination") or "").strip():
        return jsonify({"error": "Select the release destination before completing this step."}), 409

    # POSTING PERIOD FIX (doc-type gating): the 10-day window (and its
    # required explanatory comment) only applies to a Late Registration
    # document — see _document_is_late_registration() above. Any other
    # document type skips this whole block and this stage completes
    # like any other pass-through step.
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
            return (
                jsonify(
                    {
                        "error": f"The {POSTING_PERIOD_DAYS}-day posting period has not "
                        "elapsed yet."
                    }
                ),
                409,
            )
        # POSTING PERIOD FIX (doc-type gating): a Late Registration
        # document additionally requires at least one explanatory
        # comment on this stage before it can be completed — mirrors
        # stagePostingCommentMissing in document_tracking.jsx.
        comment_check = execute_with_retry(
            supabase.table("document_comments")
            .select("id")
            .eq("stage_id", stage["id"])
            .limit(1)
        )
        if not comment_check.data:
            return jsonify({"error": "Add a comment on this step before completing it."}), 409

    execute_with_retry(
        supabase.table("document_stages").update(
            {"done": True, "flag": False, "completed_at": "now()"}
        ).eq("id", stage["id"])
    )
    # trg_recompute_status (from document_tracking.sql) updates
    # documents.status automatically after this write.

    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────
# 5b. Save the Registry Number for the "Assign Registry Number" stage.
#
#    ROLE POLICY: block_if_admin() is enforced here — same reasoning
#    as complete_stage() above. Only the assigned, non-admin handler
#    can enter the Registry Number.
#
#    STAGE PERMISSION FIX: block_if_no_stage_permission() is now also
#    enforced here — only a user holding document_stage_registry_number
#    can save this stage's Registry Number.
#
#    This does NOT complete the stage — complete_stage() above is
#    still the only thing that advances the pipeline, and it now
#    refuses to complete this specific stage until a Registry Number
#    has been saved here. The value is stored on the stage row itself
#    so it stays attached to it going forward and is returned by
#    get_document_detail() (both on the stage and surfaced at the
#    document's top level).
# ─────────────────────────────────────────────────────────────────────────

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

    # STAGE PERMISSION FIX: see module-level docstring above.
    err = block_if_no_stage_permission(stage)
    if err:
        return err

    if not _is_registry_number_stage(stage):
        return jsonify({"error": "This step does not accept a Registry Number"}), 400

    execute_with_retry(
        supabase.table("document_stages").update(
            {"registry_number": registry_number}
        ).eq("id", stage["id"])
    )
    return jsonify({"ok": True, "registry_number": registry_number})


# ─────────────────────────────────────────────────────────────────────────
# 5c. Save the release destination for the final "Releasing" stage.
#
#    ROLE POLICY: block_if_admin() is enforced here — same reasoning
#    as complete_stage() above. Only the assigned, non-admin handler
#    can record where the document was released.
#
#    STAGE PERMISSION FIX: block_if_no_stage_permission() is now also
#    enforced here — only a user holding document_stage_releasing can
#    save this stage's release destination.
#
#    Same non-completing relationship to complete_stage() as
#    save_registry_number() above: this only records the destination,
#    and complete_stage() refuses to complete this stage until a
#    destination has been saved.
# ─────────────────────────────────────────────────────────────────────────

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
        return (
            jsonify(
                {
                    "error": "Release destination must be one of: "
                    + ", ".join(RELEASE_DESTINATIONS)
                }
            ),
            400,
        )

    stage = get_stage(document_id, stage_order)
    if not stage:
        return jsonify({"error": "Stage not found"}), 404

    # STAGE PERMISSION FIX: see module-level docstring above.
    err = block_if_no_stage_permission(stage)
    if err:
        return err

    if not _is_releasing_stage(stage):
        return jsonify({"error": "This step does not accept a release destination"}), 400

    execute_with_retry(
        supabase.table("document_stages").update(
            {"release_destination": destination}
        ).eq("id", stage["id"])
    )
    return jsonify({"ok": True, "release_destination": destination})


# ─────────────────────────────────────────────────────────────────────────
# 5d. Start the Posting Period for the "Posting Period" stage.
#
#    ROLE POLICY: block_if_admin() is enforced here — same reasoning
#    as complete_stage() above. Only the assigned, non-admin handler
#    can start the posting period.
#
#    STAGE PERMISSION FIX: block_if_no_stage_permission() is now also
#    enforced here — only a user holding document_stage_posting_period
#    can start this stage's posting period.
#
#    Records posting_start_at (now) and posting_end_at
#    (now + POSTING_PERIOD_DAYS days) on the stage row. Computed in
#    Python rather than via Postgres now()/interval so the exact end
#    timestamp can be returned to the caller immediately. This does
#    NOT complete the stage — complete_stage() above is still the only
#    thing that advances the pipeline, and it now refuses to complete
#    this specific stage (for a Late Registration document) until the
#    posting period has both been started here AND actually elapsed.
# ─────────────────────────────────────────────────────────────────────────

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

    # STAGE PERMISSION FIX: see module-level docstring above.
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
        supabase.table("document_stages").update(
            {
                "posting_start_at": start_at.isoformat(),
                "posting_end_at": end_at.isoformat(),
            }
        ).eq("id", stage["id"])
    )
    return jsonify(
        {
            "ok": True,
            "posting_start_at": start_at.isoformat(),
            "posting_end_at": end_at.isoformat(),
        }
    )


# ─────────────────────────────────────────────────────────────────────────
# 6. Request changes on the active stage (blocks the pipeline)
#
#    ROLE POLICY: block_if_admin() is enforced here — same reasoning
#    as complete_stage() above. Administrators cannot request changes
#    on behalf of anyone; only the assigned, non-admin handler can.
#
#    STAGE PERMISSION FIX: block_if_no_stage_permission() is now also
#    enforced here — a user may only flag/request-changes on a stage
#    their own role actually covers.
# ─────────────────────────────────────────────────────────────────────────

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

    # STAGE PERMISSION FIX: see module-level docstring above.
    err = block_if_no_stage_permission(stage)
    if err:
        return err

    author_id = get_user_id(current_username())
    if not author_id:
        return jsonify({"error": "Current user record not found"}), 400

    execute_with_retry(
        supabase.table("document_stages").update(
            {"flag": True, "done": False, "completed_at": "now()"}
        ).eq("id", stage["id"])
    )

    execute_with_retry(
        supabase.table("document_comments").insert(
            {
                "document_id": document_id,
                "stage_id": stage["id"],
                "author_id": author_id,
                "body": note,
            }
        )
    )

    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────
# 7. Reject the document outright
#
#    ROLE POLICY: block_if_admin() is enforced here — same reasoning
#    as complete_stage() above. Only the assigned, non-admin handler
#    can reject a document.
#
#    STAGE PERMISSION FIX: rejecting a document is an action taken
#    against whichever stage is currently active, so
#    block_if_no_stage_permission() is now also enforced here against
#    that active stage — otherwise a user scoped to one stage (e.g.
#    Assign Registry Number) could reject a document that's actually
#    sitting at a completely different stage (e.g. Registration) they
#    have no role in. If every stage is already done (no active stage
#    left), this check is skipped, matching the fact that there is no
#    single stage left to scope the action to.
# ─────────────────────────────────────────────────────────────────────────

@document_bp.route("/<int:document_id>/reject", methods=["POST"])
def reject_document(document_id):
    err = require_login()
    if err:
        return err
    err = block_if_admin()
    if err:
        return err

    # STAGE PERMISSION FIX: see module-level docstring above.
    active_stage = _get_active_stage(document_id)
    if active_stage:
        err = block_if_no_stage_permission(active_stage)
        if err:
            return err

    execute_with_retry(
        supabase.table("documents").update({"rejected": True}).eq("id", document_id)
    )
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────
# 8. Add a plain comment on a stage
#
#    ROLE POLICY: block_if_admin() is enforced here — same reasoning
#    as complete_stage() above. Only the assigned, non-admin handler
#    can comment on an active stage from this screen.
#
#    STAGE PERMISSION FIX: block_if_no_stage_permission() is now also
#    enforced here — a user may only comment on a stage their own role
#    actually covers.
# ─────────────────────────────────────────────────────────────────────────

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

    # STAGE PERMISSION FIX: see module-level docstring above.
    err = block_if_no_stage_permission(stage)
    if err:
        return err

    author_id = get_user_id(current_username())
    if not author_id:
        return jsonify({"error": "Current user record not found"}), 400

    res = execute_with_retry(
        supabase.table("document_comments").insert(
            {
                "document_id": document_id,
                "stage_id": stage["id"],
                "author_id": author_id,
                "body": text,
            }
        )
    )
    return jsonify(res.data[0] if res.data else {"ok": True})