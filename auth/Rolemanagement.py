# -*- coding: utf-8 -*-
# Rolemanagement.py
import json
import time
from datetime import datetime, timezone
from functools import wraps

import httpx
from flask import Blueprint, request, jsonify, session
from logs.Audits import audit_action, record_action, set_audit_context
from security import audit_denial, require_admin
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash

from auth.offline_record import build_offline_record
from supabase_client import supabase

role_bp = Blueprint("role_management", __name__)

print("[ROLES] Using Supabase tables 'roles' / 'user_roles' / 'users'")

# ─────────────────────────────────────────────
# DOCUMENT TRACKING STAGE MODULES
# ─────────────────────────────────────────────
# One granular module per Document Tracking pipeline stage, so a user can be
# scoped to exactly one stage (mirrors how "birth_verification" scopes a
# Birth Verifier to only the Birth module in Vital Records Management).
# "document_tracking" itself is also added to ALL_MODULES below.
DOCUMENT_TRACKING_STAGE_MODULES = {
    "document_stage_registration":     "Registration",
    "document_stage_civil_registrar":  "Civil Registrar",
    "document_stage_posting_period":   "Posting Period",
    "document_stage_records_division": "Records Division",
    "document_stage_registry_number":  "Assign Registry Number",
    "document_stage_releasing":        "Releasing",
}

ALL_MODULES = [
    "dashboard",
    "birth_verification",
    "birth_archive_uploader",
    "death_verification",
    "death_archive_uploader",
    "marriage_verification",
    "marriage_archive_uploader",
    "document_tracking",
    "document_stage_registration",
    "document_stage_civil_registrar",
    "document_stage_posting_period",
    "document_stage_records_division",
    "document_stage_registry_number",
    "document_stage_releasing",
    "audit_logs",
    "role_management",
    "user_management",
    "change_password",
    "offline_sync",
]

ADMIN_ONLY_MODULES = {"role_management", "user_management", "audit_logs"}

# ─────────────────────────────────────────────
# CREDENTIAL CATEGORIES
# ─────────────────────────────────────────────
# Vital Record Management Credentials and Document Tracking Credentials are
# completely independent slots: a single username may hold ONE role in
# EACH category at the same time. This mirrors CATEGORY_MODULES on the
# frontend (RoleManagement.jsx).
CATEGORY_MODULES = {
    "vital": {
        "birth_verification",
        "birth_archive_uploader",
        "death_verification",
        "death_archive_uploader",
        "marriage_verification",
        "marriage_archive_uploader",
    },
    "document": set(DOCUMENT_TRACKING_STAGE_MODULES.keys()) | {"document_tracking"},
}

# Every category value this file may ever write into user_roles.category or
# users.category.
KNOWN_CATEGORIES = {"vital", "document", "admin", "other"}


def get_role_category(role: dict) -> str:
    """Which independent credential category a role belongs to. Administrator
    (or any role granting role_management/user_management) is its own
    'admin' category, separate from both Vital and Document credentials."""
    perms = set(parse_permissions(role.get("permissions")))
    if role.get("name") == "Administrator" or "role_management" in perms or "user_management" in perms:
        return "admin"
    if perms & CATEGORY_MODULES["document"]:
        return "document"
    if perms & CATEGORY_MODULES["vital"]:
        return "vital"
    return "other"


# The bootstrap super-admin account. Always has full access (see is_admin())
# and never appears in the Role Management user list.
RESERVED_ADMIN_USERNAME = "admin"

# ─────────────────────────────────────────────
# TWO-ADMINISTRATOR CAP
# ─────────────────────────────────────────────
# In addition to the reserved bootstrap "admin" account, exactly
# MAX_ADMINISTRATORS regular users may hold the Administrator role at any time.
MAX_ADMINISTRATORS = 2

BUILTIN_ROLE_PERMISSIONS = {
    "Administrator": ALL_MODULES,
    "Birth Verifier": [
        "dashboard",
        "birth_verification",
        "birth_archive_uploader",
        "change_password",
    ],
    "Death Verifier": [
        "dashboard",
        "death_verification",
        "death_archive_uploader",
        "change_password",
    ],
    "Marriage Verifier": [
        "dashboard",
        "marriage_verification",
        "marriage_archive_uploader",
        "change_password",
    ],
    # ─── DOCUMENT TRACKING STAGE ROLES ─────────────────────────────────────
    "Registration": [
        "dashboard",
        "document_tracking",
        "document_stage_registration",
        "change_password",
    ],
    "Civil Registrar": [
        "dashboard",
        "document_tracking",
        "document_stage_civil_registrar",
        "change_password",
    ],
    "Posting Period": [
        "dashboard",
        "document_tracking",
        "document_stage_posting_period",
        "change_password",
    ],
    "Records Division": [
        "dashboard",
        "document_tracking",
        "document_stage_records_division",
        "change_password",
    ],
    "Assign Registry Number": [
        "dashboard",
        "document_tracking",
        "document_stage_registry_number",
        "change_password",
    ],
    "Releasing": [
        "dashboard",
        "document_tracking",
        "document_stage_releasing",
        "change_password",
    ],
}


def _with_offline_sync(name, perms):
    """Every built-in role except Administrator (which already has every module)
    gets offline_sync, so its personnel can open Offline Data & Sync."""
    perms = list(perms)
    if name != "Administrator" and "offline_sync" not in perms:
        perms.append("offline_sync")
    return perms


# Apply offline_sync to every built-in role.
BUILTIN_ROLE_PERMISSIONS = {
    name: _with_offline_sync(name, perms)
    for name, perms in BUILTIN_ROLE_PERMISSIONS.items()
}

VERIFIER_ALLOWED = {
    "Birth Verifier":    {"dashboard", "birth_verification",    "birth_archive_uploader",    "change_password"},
    "Death Verifier":    {"dashboard", "death_verification",    "death_archive_uploader",    "change_password"},
    "Marriage Verifier": {"dashboard", "marriage_verification", "marriage_archive_uploader", "change_password"},
}

# ─────────────────────────────────────────────
# DOCUMENT TRACKING STAGE ALLOWLIST
# ─────────────────────────────────────────────
DOC_STAGE_ALLOWED = {
    "Registration":           {"dashboard", "document_tracking", "document_stage_registration",     "change_password"},
    "Civil Registrar":        {"dashboard", "document_tracking", "document_stage_civil_registrar",  "change_password"},
    "Posting Period":         {"dashboard", "document_tracking", "document_stage_posting_period",   "change_password"},
    "Records Division":       {"dashboard", "document_tracking", "document_stage_records_division", "change_password"},
    "Assign Registry Number": {"dashboard", "document_tracking", "document_stage_registry_number",  "change_password"},
    "Releasing":              {"dashboard", "document_tracking", "document_stage_releasing",        "change_password"},
}

# --- SUPABASE RETRY WRAPPER ---------------------------------------------------
#
# On Windows, the httpx client used internally by the Supabase Python SDK can
# intermittently raise httpx.ReadError (WinError 10035). This is a transient
# socket hiccup, so `_exec()` retries a couple of times before giving up, and
# the blueprint-level error handler guarantees failures come back as JSON.

TRANSIENT_ERRORS = (
    httpx.HTTPError,
    httpx.ReadError,
    httpx.ConnectError,
    httpx.RemoteProtocolError,
    httpx.WriteError,
    ConnectionError,
    OSError,
)


def _exec(query, retries=3, base_delay=0.3):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            return query.execute()
        except TRANSIENT_ERRORS as e:
            last_err = e
            print(f"[SUPABASE-RETRY] attempt {attempt}/{retries} failed: {e!r}")
            if attempt < retries:
                time.sleep(base_delay * attempt)
    raise last_err


@role_bp.errorhandler(Exception)
def _handle_role_bp_error(e):
    # Let normal HTTP errors (404, 401, etc. raised via abort()) behave as usual.
    if isinstance(e, HTTPException):
        return e
    print(f"[ROLES] Unhandled error: {e!r}")
    return jsonify({
        "error": "Server temporarily unavailable, please try again.",
        "detail": str(e),
    }), 503


# --- HELPERS -------------------------------------------------------------

def parse_permissions(perm_val):
    if not perm_val:
        return []
    if isinstance(perm_val, list):
        return perm_val
    try:
        return json.loads(perm_val)
    except Exception:
        import ast
        try:
            return ast.literal_eval(perm_val)
        except Exception:
            return []


def _unwrap_relation(val):
    if val is None:
        return None
    if isinstance(val, list):
        return val[0] if val else None
    if isinstance(val, dict):
        return val
    return None


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def is_valid_hash(s: str) -> bool:
    if not s or not isinstance(s, str):
        return False
    return s.startswith("scrypt:") or s.startswith("pbkdf2:")


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return check_password_hash(stored_hash, password)
    except Exception:
        return False


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _first(resp):
    data = getattr(resp, "data", None)
    return data[0] if data else None


# ─────────────────────────────────────────────
# SCHEMA GUARD: user_roles.category
# ─────────────────────────────────────────────
# Category-scoped deletes depend on user_roles.category existing. If the
# migration hasn't been applied, refuse the write rather than risk an
# unscoped delete.
_CATEGORY_COLUMN_OK = None
_CATEGORY_PROBED_AT = 0.0
_CATEGORY_RECHECK_SECONDS = 60.0


def _category_column_available() -> bool:
    """True when user_roles.category exists. A True result is cached
    permanently; a False result is cached only briefly so applying the
    migration takes effect without a restart."""
    global _CATEGORY_COLUMN_OK, _CATEGORY_PROBED_AT

    if _CATEGORY_COLUMN_OK is True:
        return True
    if (
        _CATEGORY_COLUMN_OK is False
        and (time.time() - _CATEGORY_PROBED_AT) < _CATEGORY_RECHECK_SECONDS
    ):
        return False

    try:
        _exec(supabase.table("user_roles").select("category").limit(1))
        _CATEGORY_COLUMN_OK = True
    except TRANSIENT_ERRORS:
        # Network hiccup, not a schema problem — don't cache a false negative.
        raise
    except Exception as e:
        print(f"[ROLES] user_roles.category not available: {e!r}")
        _CATEGORY_COLUMN_OK = False
    _CATEGORY_PROBED_AT = time.time()
    return _CATEGORY_COLUMN_OK


MIGRATION_REQUIRED_ERROR = (
    "Database migration required: the 'user_roles' table has no 'category' "
    "column. Run the 'MIGRATION: CREDENTIAL CATEGORY SEPARATION' section of "
    "schema.sql. Until then, the same username cannot hold separate Vital "
    "Record Management and Document Tracking credentials."
)


# ─────────────────────────────────────────────
# SCHEMA GUARD: users.category
# ─────────────────────────────────────────────
# Per-category passwords depend on this column. Not fatal: credential
# creation falls back to the legacy shared-password behaviour without it.
_USER_CATEGORY_COLUMN_OK = None
_USER_CATEGORY_PROBED_AT = 0.0
_USER_CATEGORY_RECHECK_SECONDS = 60.0


def _user_category_column_available() -> bool:
    """True when users.category exists. A True result is cached permanently;
    a False result is cached only briefly."""
    global _USER_CATEGORY_COLUMN_OK, _USER_CATEGORY_PROBED_AT

    if _USER_CATEGORY_COLUMN_OK is True:
        return True
    if (
        _USER_CATEGORY_COLUMN_OK is False
        and (time.time() - _USER_CATEGORY_PROBED_AT) < _USER_CATEGORY_RECHECK_SECONDS
    ):
        return False

    try:
        _exec(supabase.table("users").select("category").limit(1))
        _USER_CATEGORY_COLUMN_OK = True
    except TRANSIENT_ERRORS:
        raise
    except Exception as e:
        print(f"[ROLES] users.category not available: {e!r}")
        _USER_CATEGORY_COLUMN_OK = False
    _USER_CATEGORY_PROBED_AT = time.time()
    return _USER_CATEGORY_COLUMN_OK


USERS_MIGRATION_REQUIRED_ERROR = (
    "Database migration required: the 'users' table has no 'category' "
    "column. Run the 'MIGRATION: PER-CATEGORY PASSWORDS' section of "
    "schema.sql. Until then, the same username cannot hold a separate "
    "password per credential category."
)

USERS_MIGRATION_NOTICE = (
    "Note: the 'users' table has no 'category' column yet, so this username "
    "shares ONE password across all credential categories. Run the "
    "'MIGRATION: PER-CATEGORY PASSWORDS' section of schema.sql to give each "
    "category its own separate password. The role assignment itself is "
    "correctly scoped and unaffected."
)


def _delete_user_role_scoped(username: str, category: str):
    """Delete ONLY the row occupying (username, category) in user_roles.
    Refuses to run if `category` is missing or unrecognised."""
    if not username:
        raise ValueError("username is required for a scoped user_roles delete")
    if category not in KNOWN_CATEGORIES:
        raise ValueError(f"refusing unscoped user_roles delete (bad category: {category!r})")
    return _exec(
        supabase.table("user_roles")
        .delete()
        .eq("username", username)
        .eq("category", category)
    )


def get_role_by_name(name):
    resp = _exec(supabase.table("roles").select("*").eq("name", name))
    return _first(resp)


def get_role_by_id(role_id):
    resp = _exec(supabase.table("roles").select("*").eq("id", role_id))
    return _first(resp)


def get_user_by_username(username):
    """Any account row for this username, in any category (first match).
    Only for existence checks that are NOT about one specific credential."""
    resp = _exec(supabase.table("users").select("*").eq("username", username))
    return _first(resp)


def get_user_by_username_category(username, category):
    """The specific account row for (username, category). Each credential
    category has its own password and lock state."""
    resp = _exec(
        supabase.table("users")
        .select("*")
        .eq("username", username)
        .eq("category", category)
    )
    return _first(resp)


def get_current_admin_usernames():
    """Usernames (EXCLUDING the reserved bootstrap 'admin' account) that
    currently hold the Administrator role, ordered by assignment time."""
    admin_role = get_role_by_name("Administrator")
    if not admin_role:
        return []
    resp = _exec(
        supabase.table("user_roles")
        .select("username, assigned_at")
        .eq("role_id", admin_role["id"])
        .neq("username", RESERVED_ADMIN_USERNAME)
        .order("assigned_at")
    )
    return [r["username"] for r in (resp.data or [])]


# --- PERMISSION HELPERS ------------------------------------------------------

def get_user_permissions(username: str) -> list:
    # A username can hold up to one role per category, so permissions from
    # every matching user_roles row are unioned together (order-preserving).
    resp = _exec(
        supabase.table("user_roles")
        .select("roles(permissions)")
        .eq("username", username)
    )
    rows = resp.data or []
    if not rows:
        return ["dashboard"]

    combined = []
    seen = set()
    for row in rows:
        role = _unwrap_relation(row.get("roles"))
        if not role:
            continue
        for m in parse_permissions(role.get("permissions")):
            if m not in seen:
                seen.add(m)
                combined.append(m)

    return combined if combined else ["dashboard"]


def is_admin(username: str) -> bool:
    if not username:
        return False
    if username.lower() == RESERVED_ADMIN_USERNAME:
        return True

    perms = get_user_permissions(username)
    result = "role_management" in perms or "user_management" in perms
    print(f"[ADMIN-CHECK] '{username}' is_admin = {result}")
    return result


def require_permission(module: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            username = session.get("username")
            if not username:
                audit_denial("Permission check requires authentication")
                return jsonify({"error": "Not logged in"}), 401
            perms = get_user_permissions(username)
            if module not in perms:
                audit_denial(f"Required permission missing: {module}")
                return jsonify({
                    "error": f"Access denied — your role does not include '{module}'"
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# --- BACKFILL ---------------------------------------------------------------

def backfill_offline_sync_on_roles():
    """Give offline_sync to every non-Administrator role that lacks it,
    including custom roles that were created before the permission existed.
    Touches only roles.permissions. Never changes users or user_roles."""
    resp = _exec(supabase.table("roles").select("id, name, permissions"))
    for r in (resp.data or []):
        if r["name"] == "Administrator":
            continue  # already has every module
        perms = parse_permissions(r["permissions"])
        if "offline_sync" in perms:
            continue
        try:
            _exec(supabase.table("roles").update({
                "permissions": perms + ["offline_sync"],
            }).eq("id", r["id"]))
            print(f"[init] Added offline_sync to role: {r['name']}")
        except Exception as e:
            print(f"[init] Could not add offline_sync to {r['name']}: {e!r}")


# --- INIT --------------------------------------------------------------------

def init_roles_db():
    builtin_roles = [
        ("Administrator",    "Full system access",                        ALL_MODULES),
        ("Birth Verifier",    "Access to birth-related modules only",   ["dashboard", "birth_verification",    "birth_archive_uploader",    "change_password"]),
        ("Death Verifier",    "Access to death-related modules only",   ["dashboard", "death_verification",    "death_archive_uploader",    "change_password"]),
        ("Marriage Verifier", "Access to marriage-related modules only", ["dashboard", "marriage_verification", "marriage_archive_uploader", "change_password"]),
        ("Registration",           "Access to the Registration stage of Document Tracking only",            ["dashboard", "document_tracking", "document_stage_registration",     "change_password"]),
        ("Civil Registrar",        "Access to the Civil Registrar stage of Document Tracking only",         ["dashboard", "document_tracking", "document_stage_civil_registrar",  "change_password"]),
        ("Posting Period",         "Access to the Posting Period stage of Document Tracking only",          ["dashboard", "document_tracking", "document_stage_posting_period",   "change_password"]),
        ("Records Division",       "Access to the Records Division stage of Document Tracking only",       ["dashboard", "document_tracking", "document_stage_records_division", "change_password"]),
        ("Assign Registry Number", "Access to the Assign Registry Number stage of Document Tracking only", ["dashboard", "document_tracking", "document_stage_registry_number",  "change_password"]),
        ("Releasing",              "Access to the Releasing stage of Document Tracking only",               ["dashboard", "document_tracking", "document_stage_releasing",        "change_password"]),
    ]

    for name, desc, perms in builtin_roles:
        perms = _with_offline_sync(name, perms)
        existing = get_role_by_name(name)
        if not existing:
            try:
                _exec(supabase.table("roles").insert({
                    "name": name,
                    "description": desc,
                    "permissions": perms,
                }))
            except Exception as e:
                print(f"[init] Could not insert role {name}: {e}")
        try:
            _exec(supabase.table("roles").update({
                "permissions": perms,
            }).eq("name", name))
            print(f"[init] Enforced canonical permissions for role: {name}")
        except Exception as e:
            print(f"[init] Could not enforce permissions for role {name}: {e}")

    # ─────────────────────────────────────────────
    # STARTUP CHECK: credential category separation
    # ─────────────────────────────────────────────
    if not _category_column_available():
        print("[init] *** " + MIGRATION_REQUIRED_ERROR + " ***")
    if not _user_category_column_available():
        print("[init] *** " + USERS_MIGRATION_REQUIRED_ERROR + " ***")
        print("[init] *** Credentials can still be created — they will share "
              "one password per username until this migration is applied. ***")

    # ─────────────────────────────────────────────
    # NOTE: is_online is intentionally NOT reset here. It is only set False
    # by an explicit /api/logout or /api/logout-beacon call, so a server
    # restart never flips a logged-in administrator to "Not Active".
    # ─────────────────────────────────────────────

    admin_role = get_role_by_name("Administrator")
    if admin_role:
        admin_role_id = admin_role["id"]

        if _user_category_column_available():
            puser = get_user_by_username_category(RESERVED_ADMIN_USERNAME, "admin")
        else:
            puser = get_user_by_username(RESERVED_ADMIN_USERNAME)

        if not puser:
            try:
                insert_payload = {
                    "username": RESERVED_ADMIN_USERNAME,
                    "password": hash_password("admin123"),
                }
                if _user_category_column_available():
                    insert_payload["category"] = "admin"
                _exec(supabase.table("users").insert(insert_payload))
                print("[init] Created user: admin")
            except Exception as e:
                print(f"[init] Could not create admin user: {e}")
        elif not is_valid_hash(puser["password"]):
            q = supabase.table("users").update({
                "password": hash_password("admin123")
            }).eq("username", RESERVED_ADMIN_USERNAME)
            if _user_category_column_available():
                q = q.eq("category", "admin")
            _exec(q)
            print("[init] Re-hashed password for admin")

        # Admin still gets an Administrator row in user_roles, scoped to the
        # admin category only, so no Vital or Document rows are touched.
        try:
            _delete_user_role_scoped(RESERVED_ADMIN_USERNAME, "admin")
            _exec(supabase.table("user_roles").insert({
                "username": RESERVED_ADMIN_USERNAME,
                "role_id": admin_role_id,
                "category": "admin",
            }))
            print("[init] Assigned Administrator role to admin")
        except Exception as e:
            print(f"[init] Could not assign Administrator role to admin: {e!r}")

    # Give offline_sync to any role (including custom roles) that lacks it.
    try:
        backfill_offline_sync_on_roles()
    except Exception as e:
        print(f"[init] offline_sync backfill failed: {e!r}")

    print("[init] roles DB initialised — OK")


# --- ROUTES: ROLES -----------------------------------------------------------

@role_bp.route("/api/roles", methods=["GET"])
@require_admin
@audit_action("ROLES_VIEWED", resource_type="role", dedupe_window_seconds=300)
def get_roles():
    resp = _exec(supabase.table("roles").select("*").order("id"))
    rows = resp.data or []
    return jsonify([{
        "id":           r["id"],
        "name":        r["name"],
        "description": r["description"],
        "permissions": parse_permissions(r["permissions"]),
        "is_admin":    "role_management" in parse_permissions(r["permissions"]),
        "category":    get_role_category(r),
        "created_at":  str(r.get("created_at", "")),
        "updated_at":  str(r.get("updated_at", "")),
    } for r in rows])


@role_bp.route("/api/roles-list", methods=["GET"])
@require_admin
@audit_action("ROLES_VIEWED", resource_type="role", dedupe_window_seconds=300)
def get_roles_list():
    resp = _exec(supabase.table("roles").select("id, name, permissions").order("name"))
    rows = resp.data or []
    return jsonify([{
        "id":           r["id"],
        "name":        r["name"],
        "permissions": parse_permissions(r["permissions"]),
        "is_admin":    "role_management" in parse_permissions(r["permissions"]),
        "category":    get_role_category(r),
    } for r in rows])


@role_bp.route("/api/roles/<int:role_id>", methods=["GET"])
@require_admin
@audit_action("ROLES_VIEWED", resource_type="role", dedupe_window_seconds=300)
def get_role(role_id):
    row = get_role_by_id(role_id)
    if not row:
        return jsonify({"error": "Role not found"}), 404
    perms = parse_permissions(row["permissions"])
    return jsonify({
        "id":          row["id"],
        "name":        row["name"],
        "description": row["description"],
        "permissions": perms,
        "is_admin":    "role_management" in perms,
        "category":    get_role_category(row),
    })


@role_bp.route("/api/roles", methods=["POST"])
@require_admin
@audit_action("ROLE_CREATED", resource_type="role")
def create_role():
    data            = request.json or {}
    name            = (data.get("name") or "").strip()
    description     = (data.get("description") or "").strip()
    permissions     = data.get("permissions", [])
    is_admin_flag   = bool(data.get("is_admin", False))

    if not name:
        return jsonify({"error": "Role name is required"}), 400

    if name in BUILTIN_ROLE_PERMISSIONS:
        return jsonify({"error": f"'{name}' is a built-in role and cannot be recreated"}), 400

    invalid = [m for m in permissions if m not in ALL_MODULES]
    if invalid:
        return jsonify({"error": f"Invalid modules: {invalid}"}), 400

    if is_admin_flag and "role_management" not in permissions:
        permissions.append("role_management")

    if get_role_by_name(name):
        return jsonify({"error": "Role name already exists"}), 409

    set_audit_context(
        new_value={"name": name, "description": description, "permissions": permissions},
        resource_id=name,
    )
    try:
        _exec(supabase.table("roles").insert({
            "name": name,
            "description": description,
            "permissions": permissions,
        }))
    except Exception as e:
        return jsonify({"error": f"Could not create role: {e}"}), 500

    row = get_role_by_name(name)
    perms = parse_permissions(row["permissions"])
    set_audit_context(
        new_value={"name": name, "description": description, "permissions": perms},
        resource_id=row["id"],
    )
    return jsonify({
        "message": "Role created",
        "role": {
            "id":          row["id"],
            "name":        row["name"],
            "description": row["description"],
            "permissions": perms,
            "is_admin":    "role_management" in perms,
            "category":    get_role_category(row),
        }
    }), 201


@role_bp.route("/api/roles/<int:role_id>", methods=["PUT"])
@require_admin
@audit_action("ROLE_UPDATED", resource_type="role")
def update_role(role_id):
    data            = request.json or {}
    name            = (data.get("name") or "").strip()
    description     = (data.get("description") or "").strip()
    permissions     = data.get("permissions", [])
    is_admin_flag   = bool(data.get("is_admin", False))

    if not name:
        return jsonify({"error": "Role name is required"}), 400

    invalid = [m for m in permissions if m not in ALL_MODULES]
    if invalid:
        return jsonify({"error": f"Invalid modules: {invalid}"}), 400

    if is_admin_flag and "role_management" not in permissions:
        permissions.append("role_management")

    existing = get_role_by_id(role_id)
    if not existing:
        return jsonify({"error": "Role not found"}), 404

    if name != existing["name"] and get_role_by_name(name):
        return jsonify({"error": "Role name already exists"}), 409

    set_audit_context(
        old_value={
            "role_name": existing.get("name"),
            "description": existing.get("description"),
            "permissions": parse_permissions(existing.get("permissions")),
        },
        new_value={"role_name": name, "description": description, "permissions": permissions},
        resource_id=role_id,
    )

    # Snapshot old per-username categories for this role BEFORE updating, so
    # that if the edit moves the role into a different category we know which
    # users rows need to follow it.
    try:
        pre_update_rows = _exec(
            supabase.table("user_roles").select("username, category").eq("role_id", role_id)
        ).data or []
    except Exception as e:
        pre_update_rows = []
        print(f"[ROLES] Could not snapshot pre-update user_roles rows for role {role_id}: {e!r}")

    try:
        _exec(supabase.table("roles").update({
            "name": name,
            "description": description,
            "permissions": permissions,
        }).eq("id", role_id))
    except Exception as e:
        return jsonify({"error": f"Could not update role: {e}"}), 500

    # Editing a role's permissions can move it into a different credential
    # category. Existing assignment rows must follow it.
    try:
        updated = get_role_by_id(role_id) or {}
        new_category = get_role_category(updated)
        _exec(supabase.table("user_roles").update({
            "category": new_category,
        }).eq("role_id", role_id))

        # users.category re-sync: move the account row to match, but only when
        # doing so cannot collide with an independent credential the same
        # username already holds in the destination category.
        if _user_category_column_available():
            for row in pre_update_rows:
                uname   = row.get("username")
                old_cat = row.get("category")
                if not uname or not old_cat or old_cat == new_category:
                    continue
                try:
                    if get_user_by_username_category(uname, new_category):
                        print(
                            f"[ROLES] Skipped users.category re-sync for '{uname}': "
                            f"a '{new_category}' credential already exists for this user"
                        )
                        continue
                    _exec(
                        supabase.table("users")
                        .update({"category": new_category})
                        .eq("username", uname)
                        .eq("category", old_cat)
                    )
                except Exception as e:
                    print(f"[ROLES] Could not re-sync users.category for '{uname}': {e!r}")
    except Exception as e:
        print(f"[ROLES] Could not re-sync user_roles.category for role {role_id}: {e!r}")

    return jsonify({"message": "Role updated"})


@role_bp.route("/api/roles/<int:role_id>", methods=["DELETE"])
@require_admin
@audit_action("ROLE_DELETED", resource_type="role")
def delete_role(role_id):
    row = get_role_by_id(role_id)
    if not row:
        return jsonify({"error": "Role not found"}), 404

    if row["name"] in BUILTIN_ROLE_PERMISSIONS:
        return jsonify({"error": f"Cannot delete built-in role '{row['name']}'"}), 400

    set_audit_context(
        old_value={
            "role_name": row.get("name"),
            "description": row.get("description"),
            "permissions": parse_permissions(row.get("permissions")),
        },
        new_value=None,
        resource_id=role_id,
    )

    # Scoped by role_id, so only assignments OF THIS ROLE go away.
    _exec(supabase.table("user_roles").delete().eq("role_id", role_id))
    _exec(supabase.table("roles").delete().eq("id", role_id))
    return jsonify({"message": "Role deleted"})


@role_bp.route("/api/modules", methods=["GET"])
@require_admin
@audit_action("ROLES_VIEWED", resource_type="access_control", dedupe_window_seconds=300)
def get_modules():
    return jsonify({
        "all":        ALL_MODULES,
        "admin_only": list(ADMIN_ONLY_MODULES),
    })


# --- ROUTES: TWO-ADMINISTRATOR SELECTION -------------------------------------

@role_bp.route("/api/administrators", methods=["GET"])
@require_admin
@audit_action("PERSONNEL_VIEWED", resource_type="account", dedupe_window_seconds=300)
def get_administrators():
    """Current holders of the (capped) Administrator role, excluding the
    reserved bootstrap 'admin' account."""
    return jsonify({
        "administrators": get_current_admin_usernames(),
        "max": MAX_ADMINISTRATORS,
    })


@role_bp.route("/api/administrators", methods=["PUT"])
@require_admin
@audit_action("ADMINISTRATORS_UPDATED", resource_type="account")
def set_administrators():
    """Sets EXACTLY the two Administrator slots to the given usernames.
    Every delete is scoped to category="admin" so Vital or Document roles
    held by the same usernames are never disturbed."""
    data  = request.json or {}
    slot1 = (data.get("slot1_username") or "").strip()
    slot2 = (data.get("slot2_username") or "").strip()

    if not slot1 or not slot2:
        return jsonify({"error": "Both administrator slots are required"}), 400
    if slot1 == slot2:
        return jsonify({"error": "Choose two different users for the two Administrator slots"}), 400
    if slot1.lower() == RESERVED_ADMIN_USERNAME or slot2.lower() == RESERVED_ADMIN_USERNAME:
        return jsonify({
            "error": "The reserved admin account already has permanent full access and doesn't need a slot"
        }), 400

    for uname in (slot1, slot2):
        if not get_user_by_username(uname):
            return jsonify({"error": f"User '{uname}' does not exist"}), 404

    admin_role = get_role_by_name("Administrator")
    if not admin_role:
        return jsonify({"error": "Administrator role not found"}), 500
    admin_role_id = admin_role["id"]

    if not _category_column_available():
        return jsonify({"error": MIGRATION_REQUIRED_ERROR}), 500

    current_admins = get_current_admin_usernames()
    set_audit_context(
        old_value={"administrators": current_admins},
        new_value={"administrators": [slot1, slot2]},
        resource_id="Administrator",
    )
    for uname in current_admins:
        if uname not in (slot1, slot2):
            _delete_user_role_scoped(uname, "admin")

    for uname in (slot1, slot2):
        _delete_user_role_scoped(uname, "admin")
        _exec(supabase.table("user_roles").insert({
            "username": uname,
            "role_id": admin_role_id,
            "category": "admin",
        }))

    return jsonify({
        "message": "Administrators updated",
        "administrators": [slot1, slot2],
    })


# --- ROUTES: USER-ROLE ASSIGNMENT --------------------------------------------

@role_bp.route("/api/user-roles", methods=["GET"])
@require_admin
@audit_action("PERSONNEL_VIEWED", resource_type="user_role", dedupe_window_seconds=300)
def get_user_roles():
    select_cols = "id, username, category, assigned_at, roles(id, name, permissions)"
    if not _category_column_available():
        select_cols = "id, username, assigned_at, roles(id, name, permissions)"

    resp = _exec(
        supabase.table("user_roles")
        .select(select_cols)
        .neq("username", RESERVED_ADMIN_USERNAME)
        .order("id")
    )
    rows = resp.data or []

    usernames = [r["username"] for r in rows]

    # Lock/online lookup is keyed by (username, category) so one category's
    # lock state never bleeds into the other's row for the same username.
    users_scoped = _user_category_column_available()
    lock_info = {}
    if usernames:
        select_users_cols = "username, category, login_attempts, lock_time, lock_level, is_online, last_login, last_logout"
        if not users_scoped:
            select_users_cols = "username, login_attempts, lock_time, lock_level, is_online, last_login, last_logout"
        uresp = _exec(
            supabase.table("users")
            .select(select_users_cols)
            .in_("username", usernames)
        )
        for u in (uresp.data or []):
            key = (u["username"], u.get("category")) if users_scoped else u["username"]
            lock_info[key] = u

    out = []
    for r in rows:
        role = _unwrap_relation(r.get("roles")) or {}
        perms = parse_permissions(role.get("permissions"))
        category = r.get("category") or (get_role_category(role) if role else "other")
        info = lock_info.get((r["username"], category) if users_scoped else r["username"], {})
        out.append({
            "id":             r["id"],
            "username":       r["username"],
            "role_id":        role.get("id"),
            "role_name":      role.get("name"),
            "permissions":    perms,
            "is_admin":       "role_management" in perms,
            "category":       category,
            "assigned_at":    str(r["assigned_at"]),
            "login_attempts": info.get("login_attempts", 0),
            "lock_level":     info.get("lock_level", 0),
            "lock_time":      str(info.get("lock_time") or ""),
            "is_online":      bool(info.get("is_online", False)),
            "last_login":     str(info.get("last_login") or ""),
            "last_logout":    str(info.get("last_logout") or ""),
        })
    return jsonify(out)


@role_bp.route("/api/user-roles", methods=["POST"])
@require_admin
@audit_action("PERSONNEL_ADDED", resource_type="user_role")
def assign_role():
    data     = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    role_id  = data.get("role_id")

    if not username or not role_id:
        return jsonify({"error": "username and role_id are required"}), 400

    if username.lower() == RESERVED_ADMIN_USERNAME:
        return jsonify({"error": "Cannot reassign the reserved admin account"}), 400

    role = get_role_by_id(role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404

    # Two-administrator cap, enforced on the generic path too so it cannot be
    # bypassed by calling this route directly.
    if role["name"] == "Administrator":
        current_admins = get_current_admin_usernames()
        already_admin = username in current_admins
        if not already_admin and len(current_admins) >= MAX_ADMINISTRATORS:
            return jsonify({
                "error": (
                    f"Only {MAX_ADMINISTRATORS} Administrators are allowed. "
                    "Use the Administrator selection panel to swap one out first."
                )
            }), 400

    # Refuse to write if the user_roles.category migration hasn't been applied,
    # since an unscoped delete is what used to wipe a user's other credentials.
    category = get_role_category(role)
    if not _category_column_available():
        return jsonify({"error": MIGRATION_REQUIRED_ERROR}), 500
    if category not in KNOWN_CATEGORIES:
        return jsonify({"error": f"Unrecognised credential category '{category}'"}), 400

    # One holder per role per category. Checked BEFORE any account is created,
    # so a rejected role never leaves a new login behind. Administrator is
    # exempt because the two-slot cap above governs it.
    if category != "admin":
        holders = [
            r["username"]
            for r in (_exec(
                supabase.table("user_roles")
                .select("username")
                .eq("role_id", role_id)
                .eq("category", category)
            ).data or [])
            if r["username"] != username
        ]
        if holders:
            return jsonify({
                "error": (
                    f"'{role['name']}' is already assigned to '{holders[0]}' in this "
                    "category. Remove that assignment first."
                )
            }), 409

    # Per-category passwords. Without users.category, fall back to the legacy
    # shared-password behaviour instead of failing outright.
    users_scoped = _user_category_column_available()

    try:
        previous_query = (
            supabase.table("user_roles")
            .select("username, role_id, category")
            .eq("username", username)
            .eq("category", category)
        )
        previous_assignment = _exec(previous_query).data or []
    except Exception as e:
        previous_assignment = []
        print(f"[ROLES] Could not read previous assignment for audit: {e!r}")

    if users_scoped:
        existing_cred = get_user_by_username_category(username, category)
    else:
        existing_cred = get_user_by_username(username)

    account_created = False

    if not existing_cred:
        if not password:
            return jsonify({
                "error": (
                    "Password is required for a new credential in this category"
                    if users_scoped else
                    "Password is required — this username has no account yet"
                )
            }), 400
        try:
            insert_payload = {
                "username": username,
                "password": hash_password(password),
            }
            if users_scoped:
                insert_payload["category"] = category
            _exec(supabase.table("users").insert(insert_payload))
            account_created = True
            record_action(
                "ACCOUNT_CREATED",
                "Credential account created during role assignment",
                meta={"target_username": username, "category": category},
                resource_type="account",
                resource_id=username,
                new_value={"username": username, "category": category},
            )
        except Exception as e:
            print(f"[ROLES] Could not create credential for '{username}' ({category}): {e!r}")
            if users_scoped:
                return jsonify({
                    "error": (
                        f"Could not create a separate credential for '{username}' in this "
                        "category. The 'users' table still has a UNIQUE(username) "
                        "constraint — drop it and add UNIQUE (username, category) "
                        "(see the 'MIGRATION: PER-CATEGORY PASSWORDS' section of "
                        "schema.sql)."
                    ),
                    "detail": str(e),
                }), 500
    # If a credential already exists for this category, its password is left
    # untouched. Changing it goes through reset_password.

    set_audit_context(
        old_value=previous_assignment[0] if previous_assignment else None,
        new_value={
            "username": username,
            "role_id": role_id,
            "role_name": role.get("name"),
            "category": category,
            "account_created": account_created,
        },
        resource_id=username,
    )

    # Snapshot other categories so we can confirm nothing outside this
    # category was touched.
    before_other = _other_category_rows(username, category)

    # Upsert on (username, category): the existing row for this category is
    # updated in place, so the user never loses their current role if the
    # write is rejected. The database's unique index is the final guard
    # against two admins assigning the same role at the same moment.
    try:
        _exec(
            supabase.table("user_roles").upsert(
                {
                    "username": username,
                    "role_id": role_id,
                    "category": category,
                    "assigned_at": now_iso(),
                },
                on_conflict="username,category",
            )
        )
    except Exception as e:
        msg = str(e).lower()
        if "23505" in msg or "duplicate key" in msg:
            return jsonify({
                "error": (
                    f"'{role['name']}' was just assigned to someone else in this "
                    "category. Refresh and choose another role."
                )
            }), 409
        print(f"[ROLES] assign_role failed for '{username}' ({category}): {e!r}")
        return jsonify({"error": f"Could not assign role: {e}"}), 500

    # Only when a NEW credential was created with this password. If the
    # credential already existed, the submitted password was ignored by the
    # server, so writing a record here would encrypt with the wrong password.
    if account_created and password:
        _write_offline_record(username, category, password, role)

    after_other = _other_category_rows(username, category)
    lost = [c for c in before_other if c not in after_other]
    if lost:
        print(
            f"[ROLES] *** WARNING: assigning '{role['name']}' ({category}) to "
            f"'{username}' removed assignments in other categories: {lost} ***"
        )

    msg = (
        f"Account created and role '{role['name']}' assigned to '{username}'"
        if account_created
        else f"Role '{role['name']}' assigned to '{username}'"
    )
    payload = {
        "message": msg,
        "account_created": account_created,
        "category": category,
    }
    if not users_scoped:
        payload["warning"] = USERS_MIGRATION_NOTICE
    return jsonify(payload)


def _other_category_rows(username: str, category: str) -> dict:
    """{category: role_id} for every assignment this username holds OUTSIDE
    the given category. Used as a before/after safety check."""
    try:
        resp = _exec(
            supabase.table("user_roles")
            .select("category, role_id")
            .eq("username", username)
        )
        return {
            r.get("category"): r.get("role_id")
            for r in (resp.data or [])
            if r.get("category") != category
        }
    except Exception as e:
        print(f"[ROLES] _other_category_rows failed for '{username}': {e!r}")
        return {}


def _write_offline_record(username, category, password, role):
    """Store the encrypted offline record for one (username, category) credential.
    The password must be the one the server just stored for that credential."""
    perms = set(parse_permissions(role.get("permissions")))
    is_admin_role = "role_management" in perms
    permissions = perms | {"dashboard"}
    if is_admin_role:
        permissions.add("*")
    profile = {
        "username": username,
        "category": category,
        "roles": [role.get("name")],
        "is_admin": is_admin_role,
        "permissions": sorted(permissions),
    }
    try:
        record = build_offline_record(password, profile)
        q = supabase.table("users").update({"offline_record": record}).eq("username", username)
        if _user_category_column_available():
            q = q.eq("category", category)
        _exec(q)
    except Exception as e:
        print(f"[OFFLINE RECORD] could not store for '{username}' ({category}): {e!r}")


def _role_for_credential(username, category):
    rows = _exec(
        supabase.table("user_roles")
        .select("role_id")
        .eq("username", username)
        .eq("category", category)
    ).data or []
    return get_role_by_id(rows[0]["role_id"]) if rows else None


@role_bp.route("/api/user-roles/<username>", methods=["DELETE"])
@require_admin
@audit_action("PERSONNEL_REMOVED", resource_type="user_role")
def remove_user_role(username):
    caller = session.get("username")
    if caller == username:
        return jsonify({"error": "You cannot remove your own role"}), 400

    if username.lower() == RESERVED_ADMIN_USERNAME:
        return jsonify({"error": "Cannot remove the reserved admin account"}), 400

    # The frontend passes ?category= AND ?role_id= so only that one
    # category's assignment is deleted. Neither filter alone is ever allowed
    # to degrade into "remove every role this username holds".
    role_id  = request.args.get("role_id")
    category = request.args.get("category")

    if not role_id and not category:
        return jsonify({
            "error": (
                "role_id and/or category is required — refusing to remove every "
                "role this username holds across all credential categories."
            )
        }), 400

    if category and category not in KNOWN_CATEGORIES:
        return jsonify({"error": f"Unrecognised credential category '{category}'"}), 400

    category_filter_applicable = bool(category) and _category_column_available()

    if not role_id and not category_filter_applicable:
        return jsonify({
            "error": (
                "Cannot safely scope this delete: no role_id was provided and "
                "the credential-category column is not available yet. Refusing "
                "to remove every role this username holds."
            )
        }), 400

    try:
        previous_query = (
            supabase.table("user_roles")
            .select("username, role_id")
            .eq("username", username)
        )
        if role_id:
            previous_query = previous_query.eq("role_id", role_id)
        if category_filter_applicable:
            previous_query = previous_query.eq("category", category)
        previous_assignment = _exec(previous_query).data or []
    except Exception as e:
        previous_assignment = []
        print(f"[ROLES] Could not read removed assignment for audit: {e!r}")
    set_audit_context(
        old_value=previous_assignment[0] if previous_assignment else None,
        new_value=None,
        resource_id=username,
        meta={"category": category, "role_id": role_id},
    )

    query = supabase.table("user_roles").delete().eq("username", username)
    if role_id:
        query = query.eq("role_id", role_id)
    if category_filter_applicable:
        query = query.eq("category", category)
    _exec(query)

    # Intentionally does NOT delete the matching users (login) row. Removing a
    # role assignment revokes access; it does not delete the account/password.
    return jsonify({"message": f"Role removed from '{username}'"})


@role_bp.route("/api/user-roles/<username>/reset-password", methods=["PUT"])
@require_admin
@audit_action("PASSWORD_RESET", resource_type="account")
def reset_password(username):
    data     = request.json or {}
    password = (data.get("password") or "").strip()
    category = (data.get("category") or "").strip()

    if not password:
        return jsonify({"error": "New password is required"}), 400

    # Each category is its own account, so `category` scopes this update to
    # exactly one credential.
    if _user_category_column_available():
        if not category or category not in KNOWN_CATEGORIES:
            return jsonify({"error": "A valid category is required to reset this credential's password"}), 400
        existing_user = get_user_by_username_category(username, category)
        if not existing_user:
            return jsonify({"error": "User not found"}), 404
        set_audit_context(
            old_value={"credential_exists": bool(existing_user.get("password"))},
            new_value={"credential_reset": True},
            resource_id=username,
            meta={"category": category},
        )
        _exec(supabase.table("users").update({
            "password":       hash_password(password),
            "login_attempts": 0,
            "temp_attempts":  0,
            "lock_time":      None,
            "lock_level":     0,
        }).eq("username", username).eq("category", category))

        role = _role_for_credential(username, category)
        if role:
            _write_offline_record(username, category, password, role)
    else:
        # Pre-migration fallback: one shared account per username. `category`
        # is ignored rather than rejected.
        existing_user = get_user_by_username(username)
        if not existing_user:
            return jsonify({"error": "User not found"}), 404
        set_audit_context(
            old_value={"credential_exists": bool(existing_user.get("password"))},
            new_value={"credential_reset": True},
            resource_id=username,
        )
        _exec(supabase.table("users").update({
            "password":       hash_password(password),
            "login_attempts": 0,
            "temp_attempts":  0,
            "lock_time":      None,
            "lock_level":     0,
        }).eq("username", username))

    return jsonify({"message": "Password reset successfully"})


@role_bp.route("/api/user-roles/<username>/unlock", methods=["PUT"])
@require_admin
@audit_action("ACCOUNT_UNLOCKED", resource_type="account")
def unlock_user(username):
    # Lock state belongs to one (username, category) account. `category` is
    # passed as a query param since this is a plain PUT with no body.
    category = (request.args.get("category") or "").strip()

    if _user_category_column_available():
        if not category or category not in KNOWN_CATEGORIES:
            return jsonify({"error": "A valid category is required to unlock this credential"}), 400
        user = get_user_by_username_category(username, category)
        if not user:
            return jsonify({"error": "User not found"}), 404
        set_audit_context(
            old_value={
                "login_attempts": user.get("login_attempts"),
                "lock_level": user.get("lock_level"),
                "lock_time": user.get("lock_time"),
            },
            new_value={"login_attempts": 0, "lock_level": 0, "lock_time": None},
            resource_id=username,
            meta={"category": category},
        )
        _exec(supabase.table("users").update({
            "login_attempts": 0,
            "temp_attempts":  0,
            "lock_time":      None,
            "lock_level":     0,
        }).eq("username", username).eq("category", category))
    else:
        # Pre-migration fallback: one shared account per username.
        user = get_user_by_username(username)
        if not user:
            return jsonify({"error": "User not found"}), 404
        set_audit_context(
            old_value={
                "login_attempts": user.get("login_attempts"),
                "lock_level": user.get("lock_level"),
                "lock_time": user.get("lock_time"),
            },
            new_value={"login_attempts": 0, "lock_level": 0, "lock_time": None},
            resource_id=username,
        )
        _exec(supabase.table("users").update({
            "login_attempts": 0,
            "temp_attempts":  0,
            "lock_time":      None,
            "lock_level":     0,
        }).eq("username", username))

    return jsonify({"message": f"User '{username}' unlocked successfully"})


# --- CURRENT USER PERMISSIONS ------------------------------------------------

@role_bp.route("/api/my-permissions", methods=["GET"])
def my_permissions():
    username = session.get("username")
    if not username:
        return jsonify({"error": "Not logged in"}), 401

    resp = _exec(
        supabase.table("user_roles")
        .select("roles(name, permissions)")
        .eq("username", username)
    )
    rows = resp.data or []

    if not rows:
        return jsonify({"role": "None", "permissions": ["dashboard"], "is_admin": False})

    # A username may hold one row per category, so role names and permissions
    # across all of them are combined.
    role_names = []
    combined = []
    seen = set()
    for row in rows:
        role = _unwrap_relation(row.get("roles"))
        if not role:
            continue
        if role.get("name"):
            role_names.append(role.get("name"))
        for m in parse_permissions(role.get("permissions")):
            if m not in seen:
                seen.add(m)
                combined.append(m)

    if not combined:
        return jsonify({"role": "None", "permissions": ["dashboard"], "is_admin": False})

    payload = {
        "role":        " + ".join(role_names) if role_names else "None",
        "permissions": combined,
        "is_admin":    "role_management" in combined,
    }
    return jsonify(payload)


# --- OFFLINE ACCOUNTS EXPORT -------------------------------------------------

@role_bp.route("/api/offline-accounts", methods=["GET"])
@require_admin
@audit_action("OFFLINE_ACCOUNTS_EXPORTED", resource_type="account")
def offline_accounts():
    """Encrypted offline records for every ACTIVE credential (one that still has
    a user_roles row). Accounts that were disabled or whose role was removed are
    left out, so the device drops them on the next sync."""
    if not _category_column_available() or not _user_category_column_available():
        return jsonify({"error": MIGRATION_REQUIRED_ERROR}), 500

    assigned = _exec(
        supabase.table("user_roles").select("username, category")
    ).data or []
    active = {(r["username"], r.get("category")) for r in assigned}

    users = _exec(
        supabase.table("users").select("username, category, offline_record")
    ).data or []

    accounts = []
    for u in users:
        key = (u["username"], u.get("category"))
        if key not in active:
            continue
        accounts.append({
            "username": u["username"],
            "category": u.get("category"),
            "offline_record": u.get("offline_record"),
            # No record yet: this account must log in online once, or be reset.
            "needs_reset": not u.get("offline_record"),
        })

    resp = jsonify({"accounts": accounts})
    resp.headers["Cache-Control"] = "no-store"
    return resp