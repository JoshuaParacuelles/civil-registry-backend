# -*- coding: utf-8 -*-
# Rolemanagement.py
import json
import time
from datetime import datetime, timezone, timedelta
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
# Vital Record Management and Document Tracking credentials are independent
# slots: one username may hold ONE role in EACH category at the same time.
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

KNOWN_CATEGORIES = {"vital", "document", "admin", "other"}


def get_role_category(role: dict) -> str:
    """Which independent credential category a role belongs to. Administrator
    (or any role granting role_management/user_management) is its own
    'admin' category."""
    perms = set(parse_permissions(role.get("permissions")))
    if role.get("name") == "Administrator" or "role_management" in perms or "user_management" in perms:
        return "admin"
    if perms & CATEGORY_MODULES["document"]:
        return "document"
    if perms & CATEGORY_MODULES["vital"]:
        return "vital"
    return "other"


# The bootstrap super-admin account. Always has full access and never appears
# in the Role Management user list.
RESERVED_ADMIN_USERNAME = "admin"

# ─────────────────────────────────────────────
# ACTIVITY / ONLINE STATUS
# ─────────────────────────────────────────────
# An account counts as Active only when its login flag is set AND it has sent
# a heartbeat within this window. A closed or crashed app stops heartbeating,
# so the account turns Not Active without needing an explicit logout.
ONLINE_TIMEOUT_SECONDS = 120

# ─────────────────────────────────────────────
# TWO-ADMINISTRATOR CAP
# ─────────────────────────────────────────────
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
    """Every built-in role except Administrator gets offline_sync."""
    perms = list(perms)
    if name != "Administrator" and "offline_sync" not in perms:
        perms.append("offline_sync")
    return perms


BUILTIN_ROLE_PERMISSIONS = {
    name: _with_offline_sync(name, perms)
    for name, perms in BUILTIN_ROLE_PERMISSIONS.items()
}

# --- SUPABASE RETRY WRAPPER ---------------------------------------------------
#
# The httpx client used by the Supabase SDK can intermittently raise transient
# socket errors on Windows (WinError 10035). _exec() retries those before
# giving up, and the blueprint error handler returns failures as JSON.

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
    if isinstance(e, HTTPException):
        return e
    print(f"[ROLES] Unhandled error: {e!r}")
    return jsonify({
        "error": "Server temporarily unavailable, please try again.",
        "detail": str(e),
    }), 503


# --- SCHEMA PROBES ------------------------------------------------------------
#
# Checks whether an optional column exists. A True result is cached for good.
# A False result is cached briefly, so applying a migration takes effect
# without a restart. Transient network errors are re-raised and not cached.

class _SchemaProbe:
    RECHECK_SECONDS = 60.0

    def __init__(self, table: str, column: str):
        self.table = table
        self.column = column
        self._ok = None
        self._probed_at = 0.0

    def available(self) -> bool:
        if self._ok is True:
            return True
        if self._ok is False and (time.time() - self._probed_at) < self.RECHECK_SECONDS:
            return False
        try:
            _exec(supabase.table(self.table).select(self.column).limit(1))
            self._ok = True
        except TRANSIENT_ERRORS:
            raise
        except Exception as e:
            print(f"[ROLES] {self.table}.{self.column} not available: {e!r}")
            self._ok = False
        self._probed_at = time.time()
        return self._ok


_CATEGORY_PROBE = _SchemaProbe("user_roles", "category")
_USER_CATEGORY_PROBE = _SchemaProbe("users", "category")
_LAST_SEEN_PROBE = _SchemaProbe("users", "last_seen")

MIGRATION_REQUIRED_ERROR = (
    "Database migration required: the 'user_roles' table has no 'category' "
    "column. Run the 'MIGRATION: CREDENTIAL CATEGORY SEPARATION' section of "
    "schema.sql. Until then, the same username cannot hold separate Vital "
    "Record Management and Document Tracking credentials."
)

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

LAST_SEEN_MIGRATION_NOTICE = (
    "Database migration required: the 'users' table has no 'last_seen' column. "
    "Run: alter table public.users add column if not exists last_seen timestamptz; "
    "Until then, Active status falls back to the login flag only and can show "
    "stale 'Active' accounts."
)


# --- HELPERS -------------------------------------------------------------------

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


def _parse_ts(value):
    """Parse a Supabase timestamp into an aware datetime (naive values are UTC)."""
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _seen_recently(last_seen_value, now: datetime) -> bool:
    dt = _parse_ts(last_seen_value)
    if dt is None:
        return False
    return (now - dt) <= timedelta(seconds=ONLINE_TIMEOUT_SECONDS)


def _first(resp):
    data = getattr(resp, "data", None)
    return data[0] if data else None


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
    """Any account row for this username, in any category (first match)."""
    resp = _exec(supabase.table("users").select("*").eq("username", username))
    return _first(resp)


def get_user_by_username_category(username, category):
    """The account row for (username, category)."""
    resp = _exec(
        supabase.table("users")
        .select("*")
        .eq("username", username)
        .eq("category", category)
    )
    return _first(resp)


def get_current_admin_usernames():
    """Usernames (excluding the reserved bootstrap 'admin') holding the
    Administrator role, ordered by assignment time."""
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
    return "role_management" in perms or "user_management" in perms


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
    """Give offline_sync to every non-Administrator role that lacks it.
    Touches only roles.permissions."""
    resp = _exec(supabase.table("roles").select("id, name, permissions"))
    for r in (resp.data or []):
        if r["name"] == "Administrator":
            continue
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

    # STARTUP CHECK: schema migrations
    if not _CATEGORY_PROBE.available():
        print("[init] *** " + MIGRATION_REQUIRED_ERROR + " ***")
    if not _USER_CATEGORY_PROBE.available():
        print("[init] *** " + USERS_MIGRATION_REQUIRED_ERROR + " ***")
        print("[init] *** Credentials can still be created — they will share "
              "one password per username until this migration is applied. ***")
    if not _LAST_SEEN_PROBE.available():
        print("[init] *** " + LAST_SEEN_MIGRATION_NOTICE + " ***")

    # NOTE: is_online is intentionally NOT reset here. It is only cleared by an
    # explicit logout. Active status is also gated by last_seen (see heartbeat).

    admin_role = get_role_by_name("Administrator")
    if admin_role:
        admin_role_id = admin_role["id"]
        users_scoped = _USER_CATEGORY_PROBE.available()

        if users_scoped:
            puser = get_user_by_username_category(RESERVED_ADMIN_USERNAME, "admin")
        else:
            puser = get_user_by_username(RESERVED_ADMIN_USERNAME)

        if not puser:
            try:
                insert_payload = {
                    "username": RESERVED_ADMIN_USERNAME,
                    "password": hash_password("admin123"),
                }
                if users_scoped:
                    insert_payload["category"] = "admin"
                _exec(supabase.table("users").insert(insert_payload))
                print("[init] Created user: admin")
            except Exception as e:
                print(f"[init] Could not create admin user: {e}")
        elif not is_valid_hash(puser["password"]):
            q = supabase.table("users").update({
                "password": hash_password("admin123")
            }).eq("username", RESERVED_ADMIN_USERNAME)
            if users_scoped:
                q = q.eq("category", "admin")
            _exec(q)
            print("[init] Re-hashed password for admin")

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

    try:
        backfill_offline_sync_on_roles()
    except Exception as e:
        print(f"[init] offline_sync backfill failed: {e!r}")

    print("[init] roles DB initialised — OK")


# --- ROUTES: ACTIVITY HEARTBEAT ----------------------------------------------

@role_bp.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    """Called periodically by the logged-in app. Only refreshes last_seen; it
    never sets is_online, so a heartbeat arriving after logout cannot revive
    a session. Scoped to the credential the user logged in with, when the
    session records it."""
    username = session.get("username")
    if not username:
        return jsonify({"error": "Not logged in"}), 401

    if not _LAST_SEEN_PROBE.available():
        return jsonify({"ok": False, "reason": "migration_required"})

    q = supabase.table("users").update({"last_seen": now_iso()}).eq("username", username)
    category = session.get("category")
    if category in KNOWN_CATEGORIES and _USER_CATEGORY_PROBE.available():
        q = q.eq("category", category)
    _exec(q)
    return jsonify({"ok": True})


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

    try:
        updated = get_role_by_id(role_id) or {}
        new_category = get_role_category(updated)
        _exec(supabase.table("user_roles").update({
            "category": new_category,
        }).eq("role_id", role_id))

        if _USER_CATEGORY_PROBE.available():
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
    return jsonify({
        "administrators": get_current_admin_usernames(),
        "max": MAX_ADMINISTRATORS,
    })


@role_bp.route("/api/administrators", methods=["PUT"])
@require_admin
@audit_action("ADMINISTRATORS_UPDATED", resource_type="account")
def set_administrators():
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

    if not _CATEGORY_PROBE.available():
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
    if not _CATEGORY_PROBE.available():
        select_cols = "id, username, assigned_at, roles(id, name, permissions)"

    resp = _exec(
        supabase.table("user_roles")
        .select(select_cols)
        .neq("username", RESERVED_ADMIN_USERNAME)
        .order("id")
    )
    rows = resp.data or []
    usernames = [r["username"] for r in rows]

    users_scoped = _USER_CATEGORY_PROBE.available()
    seen_available = _LAST_SEEN_PROBE.available()

    lock_info = {}
    if usernames:
        cols = ["username", "login_attempts", "lock_time", "lock_level",
                "is_online", "last_login", "last_logout"]
        if users_scoped:
            cols.insert(1, "category")
        if seen_available:
            cols.append("last_seen")

        uresp = _exec(
            supabase.table("users")
            .select(", ".join(cols))
            .in_("username", usernames)
        )
        for u in (uresp.data or []):
            key = (u["username"], u.get("category")) if users_scoped else u["username"]
            lock_info[key] = u

    now = datetime.now(timezone.utc)
    out = []
    for r in rows:
        role = _unwrap_relation(r.get("roles")) or {}
        perms = parse_permissions(role.get("permissions"))
        category = r.get("category") or (get_role_category(role) if role else "other")
        info = lock_info.get((r["username"], category) if users_scoped else r["username"], {})

        # Active = login flag set AND a recent heartbeat. Without the last_seen
        # column there is no way to tell a live session from a stale one, so
        # the flag alone is used (and a startup warning is printed).
        login_flag = bool(info.get("is_online", False))
        is_online = login_flag and _seen_recently(info.get("last_seen"), now) if seen_available else login_flag

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
            "is_online":      is_online,
            "last_seen":      str(info.get("last_seen") or ""),
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

    category = get_role_category(role)
    if not _CATEGORY_PROBE.available():
        return jsonify({"error": MIGRATION_REQUIRED_ERROR}), 500
    if category not in KNOWN_CATEGORIES:
        return jsonify({"error": f"Unrecognised credential category '{category}'"}), 400

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

    users_scoped = _USER_CATEGORY_PROBE.available()

    try:
        previous_assignment = _exec(
            supabase.table("user_roles")
            .select("username, role_id, category")
            .eq("username", username)
            .eq("category", category)
        ).data or []
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

    before_other = _other_category_rows(username, category)

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
    """Store the encrypted offline record for one (username, category) credential."""
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
        if _USER_CATEGORY_PROBE.available():
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

    category_filter_applicable = bool(category) and _CATEGORY_PROBE.available()

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

    # Does NOT delete the users (login) row. Removing a role revokes access only.
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

    if _USER_CATEGORY_PROBE.available():
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
    category = (request.args.get("category") or "").strip()

    if _USER_CATEGORY_PROBE.available():
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

    return jsonify({
        "role":        " + ".join(role_names) if role_names else "None",
        "permissions": combined,
        "is_admin":    "role_management" in combined,
    })


# --- OFFLINE ACCOUNTS EXPORT -------------------------------------------------

@role_bp.route("/api/offline-accounts", methods=["GET"])
@require_admin
@audit_action("OFFLINE_ACCOUNTS_EXPORTED", resource_type="account")
def offline_accounts():
    """Encrypted offline records for every ACTIVE credential (one that still has
    a user_roles row)."""
    if not _CATEGORY_PROBE.available() or not _USER_CATEGORY_PROBE.available():
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
        if (u["username"], u.get("category")) not in active:
            continue
        accounts.append({
            "username": u["username"],
            "category": u.get("category"),
            "offline_record": u.get("offline_record"),
            "needs_reset": not u.get("offline_record"),
        })

    resp = jsonify({"accounts": accounts})
    resp.headers["Cache-Control"] = "no-store"
    return resp