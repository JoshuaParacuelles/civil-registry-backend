# -*- coding: utf-8 -*-
# Rolemanagement.py
import os
import sys
import json
import time
from datetime import datetime, timezone
from functools import wraps

import httpx
from flask import Blueprint, request, jsonify, session
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash

from supabase_client import supabase

role_bp = Blueprint("role_management", __name__)

print("[ROLES] Using Supabase tables 'roles' / 'user_roles' / 'users'")

# ─────────────────────────────────────────────
# DOCUMENT TRACKING STAGE MODULES (NEW)
# ─────────────────────────────────────────────
# One granular module per Document Tracking pipeline stage, so a user can be
# scoped to exactly one stage (mirrors how "birth_verification" scopes a
# Birth Verifier to only the Birth module in Vital Records Management).
# "document_tracking" itself is also added to ALL_MODULES below — it was
# previously omitted here even though the frontend already labels/uses it,
# because every authenticated user is auto-granted it in PermissionContext.
# Adding it to ALL_MODULES just lets it pass validation if a role's
# permission list is ever created/edited through the generic role endpoints.
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
]

ADMIN_ONLY_MODULES = {"role_management", "user_management", "audit_logs"}

# ─────────────────────────────────────────────
# CREDENTIAL CATEGORIES (NEW)
# ─────────────────────────────────────────────
# Vital Record Management Credentials and Document Tracking Credentials are
# completely independent slots: a single username may hold ONE role in
# EACH category at the same time (e.g. Marriage Verifier for Vital Records
# *and* Assign Registry Number for Document Tracking, simultaneously).
# This mirrors CATEGORY_MODULES on the frontend (Rolemanagement.jsx) and is
# used to decide which category a user_roles row belongs to, so assigning a
# role in one category never disturbs a role already held in another.
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
# users.category. Used by the guard rails below to make sure a scoped
# delete/write can never silently degrade into an unscoped one.
KNOWN_CATEGORIES = {"vital", "document", "admin", "other"}


def get_role_category(role: dict) -> str:
    """Which independent credential category a role belongs to. Administrator
    (or any role granting role_management/user_management) is its own
    'admin' category, separate from both Vital and Document credentials.
    This is also the value persisted in user_roles.category (and, for the
    account itself, users.category) — i.e. what actually keeps Vital Record
    Management and Document Tracking assignments AND passwords for the same
    username from colliding/overwriting."""
    perms = set(parse_permissions(role.get("permissions")))
    if role.get("name") == "Administrator" or "role_management" in perms or "user_management" in perms:
        return "admin"
    if perms & CATEGORY_MODULES["document"]:
        return "document"
    if perms & CATEGORY_MODULES["vital"]:
        return "vital"
    return "other"


# The bootstrap super-admin account. It always has full access (see is_admin()
# below) regardless of what's in user_roles, and it should never show up in
# the Role Management user list — it isn't a role someone "assigned".
RESERVED_ADMIN_USERNAME = "admin"

# ─────────────────────────────────────────────
# TWO-ADMINISTRATOR CAP
# ─────────────────────────────────────────────
# In addition to the reserved bootstrap "admin" account (which is permanent
# and separate), exactly MAX_ADMINISTRATORS regular users may hold the
# Administrator role at any time. Enforced both in assign_role() (generic
# path) and in the dedicated set_administrators() endpoint (slot-based path
# the frontend now uses instead of showing admins in a plain list).
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
    # ─── DOCUMENT TRACKING STAGE ROLES (NEW) ───────────────────────────────
    # Each of these scopes a user to exactly one Document Tracking pipeline
    # stage. "document_tracking" is included so the page itself shows up in
    # their permission chips (access to the page is already auto-granted to
    # any authenticated user by PermissionContext, but including it here
    # keeps the role's displayed permissions accurate/self-describing).
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

VERIFIER_ALLOWED = {
    "Birth Verifier":    {"dashboard", "birth_verification",    "birth_archive_uploader",    "change_password"},
    "Death Verifier":    {"dashboard", "death_verification",    "death_archive_uploader",    "change_password"},
    "Marriage Verifier": {"dashboard", "marriage_verification", "marriage_archive_uploader", "change_password"},
}

# ─────────────────────────────────────────────
# DOCUMENT TRACKING STAGE ALLOWLIST (NEW)
# ─────────────────────────────────────────────
# Mirrors VERIFIER_ALLOWED above, one entry per Document Tracking stage role.
# Not consumed by this file directly (VERIFIER_ALLOWED isn't either — both
# are provided as the canonical "what this role may touch" reference for
# whatever enforces per-stage access inside the actual Document Tracking
# page/route, which lives outside this blueprint).
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
# intermittently raise:
#
#   httpx.ReadError: [WinError 10035] A non-blocking socket operation could
#   not be completed immediately
#
# This is a transient OS-level socket hiccup (usually caused by connection
# pooling / keep-alive reuse timing on Windows), not a real data or auth
# problem. Previously this exception was unhandled, so Flask's default error
# handling rendered a raw HTML 500 page instead of JSON — which is why the
# frontend's `checkJson()` was reporting "Server returned non-JSON response".
#
# `_exec()` wraps every `.execute()` call so transient errors get a couple of
# quick retries before giving up, and the blueprint-level error handler below
# guarantees that even a final failure comes back as JSON, not HTML.

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
    # Let normal HTTP errors (404, 401, etc. raised via abort()) behave
    # as usual instead of being swallowed into a generic 500.
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
# SCHEMA GUARD: user_roles.category (NEW)
# ─────────────────────────────────────────────
# Every category-scoped delete/insert in this file depends on the
# `user_roles.category` column existing AND on the old single-column
# UNIQUE(username) constraint having been dropped (see schema.sql, section
# "MIGRATION: CREDENTIAL CATEGORY SEPARATION").
#
# If that migration has not been applied, the scoped delete would fail —
# and on some client/PostgREST versions a filter on a missing column is
# simply ignored, which would silently turn the scoped delete back into
# "delete every role this username has". That is precisely the bug being
# fixed here, so instead of risking it we detect the situation up front and
# refuse the write with an explicit, actionable error.
_CATEGORY_COLUMN_OK = None
_CATEGORY_PROBED_AT = 0.0
_CATEGORY_RECHECK_SECONDS = 60.0


def _category_column_available() -> bool:
    """True when user_roles.category exists.

    ─── FIX: NO LONGER CACHED FALSE FOREVER ───────────────────────────────
    A True result is cached permanently (a column never disappears). A
    False result used to be cached permanently too — which meant that if
    the 'CREDENTIAL CATEGORY SEPARATION' migration was applied to the
    database *while this process was already running*, every category-
    scoped write (assign_role, set_administrators, etc.) would keep
    returning MIGRATION_REQUIRED_ERROR forever, until someone thought to
    restart the server. A False result is now cached only briefly instead,
    exactly mirroring _user_category_column_available() below (which
    already worked this way), so applying the migration takes effect on a
    live server without a restart.
    """
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
# SCHEMA GUARD: users.category (NEW)
# ─────────────────────────────────────────────
# Companion probe to the one above, but for `users` (the password / login
# table). Per-category passwords depend on this column existing and on the
# old single-column UNIQUE(username) constraint having been dropped there
# too (see schema.sql, section "MIGRATION: PER-CATEGORY PASSWORDS").
#
# ─── FIX: THIS PROBE NO LONGER BLOCKS CREDENTIAL CREATION ───────────────
# A False result used to make assign_role() return HTTP 500 outright, which
# meant Document Tracking credentials could not be created AT ALL until the
# migration had been applied. That was too strict: only the *separate
# password per category* feature depends on this column. The role/category
# separation itself depends on user_roles.category, which is a different
# migration. assign_role() now degrades to the legacy single-account
# behaviour instead of failing (see PER-CATEGORY PASSWORDS there).
#
# The cached negative is also no longer permanent — see
# _refresh_user_category_probe() — so once the migration is applied the
# running process picks it up on its next write instead of needing a
# restart.
_USER_CATEGORY_COLUMN_OK = None
_USER_CATEGORY_PROBED_AT = 0.0
_USER_CATEGORY_RECHECK_SECONDS = 60.0


def _user_category_column_available() -> bool:
    """True when users.category exists.

    A True result is cached permanently (a column never disappears). A
    False result is cached only briefly, so applying the migration takes
    effect on a live server without a restart.
    """
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

# Same information, but phrased as a non-fatal notice returned alongside a
# SUCCESSFUL assignment made in legacy (shared-password) mode.
USERS_MIGRATION_NOTICE = (
    "Note: the 'users' table has no 'category' column yet, so this username "
    "shares ONE password across all credential categories. Run the "
    "'MIGRATION: PER-CATEGORY PASSWORDS' section of schema.sql to give each "
    "category its own separate password. The role assignment itself is "
    "correctly scoped and unaffected."
)


def _delete_user_role_scoped(username: str, category: str):
    """Delete ONLY the row occupying (username, category) in user_roles.

    Deliberately refuses to run if `category` is missing or unrecognised,
    because an unscoped delete here is exactly what used to wipe a user's
    role in the *other* module. Fail loudly rather than delete too much.
    """
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

    Used only for existence checks that are NOT about one specific
    credential — e.g. whether a username is a plausible candidate for an
    Administrator slot. Do NOT use this where a specific category's
    password or lock state must be read or written; use
    get_user_by_username_category for that, since (per the fix below) the
    SAME username can now have a different row — and a different password
    — in each category."""
    resp = _exec(supabase.table("users").select("*").eq("username", username))
    return _first(resp)


def get_user_by_username_category(username, category):
    """The specific account row for (username, category).

    ─── PER-CATEGORY PASSWORDS (NEW) ──────────────────────────────────────
    Each credential category (Vital Record Management / Document Tracking /
    Admin) is now its own independent account with its own password and
    its own lock/login-attempt state, even when it shares a username with
    an account in another category. This is what assign_role,
    reset_password and unlock_user use so they only ever touch the ONE row
    that belongs to the module actually being managed — never a
    same-named account sitting in a different category."""
    resp = _exec(
        supabase.table("users")
        .select("*")
        .eq("username", username)
        .eq("category", category)
    )
    return _first(resp)


def get_current_admin_usernames():
    """Usernames (EXCLUDING the reserved bootstrap 'admin' account) that
    currently hold the Administrator role, ordered by when they were
    assigned. Used both to enforce the MAX_ADMINISTRATORS cap and to
    populate the two admin-selection slots in the frontend."""
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
    # ─── CREDENTIAL CATEGORY SEPARATION (NEW) ──────────────────────────
    # A username can now hold up to one role per independent category
    # (Vital / Document / Admin) at the same time, so this can return
    # multiple user_roles rows for the same username. Their permissions
    # are unioned together (order-preserving, de-duplicated) so a user
    # assigned in both categories gets the combined access of both roles,
    # instead of only whichever single row happened to be assigned last.
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
                return jsonify({"error": "Not logged in"}), 401
            perms = get_user_permissions(username)
            if module not in perms:
                return jsonify({
                    "error": f"Access denied — your role does not include '{module}'"
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        username = session.get("username")
        if not username:
            return jsonify({"error": "Not logged in"}), 401
        if not is_admin(username):
            return jsonify({"error": "Access denied — admin privileges required"}), 403
        return fn(*args, **kwargs)
    return wrapper


# --- INIT --------------------------------------------------------------------
def init_roles_db():
    builtin_roles = [
        ("Administrator",    "Full system access",                        ALL_MODULES),
        ("Birth Verifier",    "Access to birth-related modules only",   ["dashboard", "birth_verification",    "birth_archive_uploader",    "change_password"]),
        ("Death Verifier",    "Access to death-related modules only",   ["dashboard", "death_verification",    "death_archive_uploader",    "change_password"]),
        ("Marriage Verifier", "Access to marriage-related modules only", ["dashboard", "marriage_verification", "marriage_archive_uploader", "change_password"]),
        # ─── DOCUMENT TRACKING STAGE ROLES (NEW) ───────────────────────────
        # One built-in role per pipeline stage shown in the Document
        # Tracking UI's "Currently handling" list. Each is scoped to just
        # that stage's module, the same way the verifier roles above are
        # scoped to just their record type.
        ("Registration",           "Access to the Registration stage of Document Tracking only",            ["dashboard", "document_tracking", "document_stage_registration",     "change_password"]),
        ("Civil Registrar",        "Access to the Civil Registrar stage of Document Tracking only",         ["dashboard", "document_tracking", "document_stage_civil_registrar",  "change_password"]),
        ("Posting Period",         "Access to the Posting Period stage of Document Tracking only",          ["dashboard", "document_tracking", "document_stage_posting_period",   "change_password"]),
        ("Records Division",       "Access to the Records Division stage of Document Tracking only",       ["dashboard", "document_tracking", "document_stage_records_division", "change_password"]),
        ("Assign Registry Number", "Access to the Assign Registry Number stage of Document Tracking only", ["dashboard", "document_tracking", "document_stage_registry_number",  "change_password"]),
        ("Releasing",              "Access to the Releasing stage of Document Tracking only",               ["dashboard", "document_tracking", "document_stage_releasing",        "change_password"]),
    ]

    for name, desc, perms in builtin_roles:
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
    # Surfaces a loud, unmissable warning at boot if schema.sql's migrations
    # haven't been applied, instead of letting the "credentials moved to the
    # other module" / "no separate password" bugs reappear at runtime.
    if not _category_column_available():
        print("[init] *** " + MIGRATION_REQUIRED_ERROR + " ***")
    if not _user_category_column_available():
        print("[init] *** " + USERS_MIGRATION_REQUIRED_ERROR + " ***")
        print("[init] *** Credentials can still be created — they will share "
              "one password per username until this migration is applied. ***")

    # ─────────────────────────────────────────────
    # BUG FIX: "admin goes inactive after a few hours"
    # ─────────────────────────────────────────────
    # This function runs every time the Flask process starts — including
    # automatic restarts (dev-server reloader, host idling/waking the app,
    # crash + auto-restart by a process manager, deploy redeploys, etc.).
    # The old code below unconditionally forced EVERY user's is_online to
    # False on every single startup:
    #
    #     _exec(supabase.table("users").update({"is_online": False}).neq("id", -1))
    #
    # That means a logged-in administrator's status could flip to "Not
    # Active" purely because the server restarted in the background —
    # nothing the admin did, and no real logout ever happened. That's
    # exactly the symptom you saw: active for a while, then silently
    # "Not Active" a few hours later.
    #
    # Per the requirement ("status should remain active unless
    # intentionally changed to inactive"), we no longer touch is_online
    # here at all. It is now ONLY ever set to False by an explicit
    # /api/logout or /api/logout-beacon call, and set True by your login
    # route (wherever that lives in your codebase) — i.e. only real,
    # intentional sign-outs change it.

    admin_role = get_role_by_name("Administrator")
    if admin_role:
        admin_role_id = admin_role["id"]

        # ─── PER-CATEGORY PASSWORDS (NEW) ──────────────────────────────
        # The reserved bootstrap account lives in its own 'admin' category
        # for its password row too, so it never collides with (or gets
        # confused for) a same-named account someone creates in Vital
        # Record Management or Document Tracking.
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

        # NOTE: admin still gets an Administrator row in user_roles (so it has
        # a role_id/permissions to resolve internally), but the /api/user-roles
        # LIST endpoint below explicitly filters this account out, since it's
        # a reserved system account rather than something you assigned.
        # Scoped to category="admin" only (not a blanket username delete) so
        # this never touches any Vital/Document rows — though admin never has
        # those, this keeps the pattern consistent everywhere else in the file.
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

    print("[init] roles DB initialised — OK")


# --- ROUTES: ROLES -----------------------------------------------------------

@role_bp.route("/api/roles", methods=["GET"])
@require_admin
def get_roles():
    resp = _exec(supabase.table("roles").select("*").order("id"))
    rows = resp.data or []
    return jsonify([{
        "id":           r["id"],
        "name":        r["name"],
        "description": r["description"],
        "permissions": parse_permissions(r["permissions"]),
        "is_admin":    "role_management" in parse_permissions(r["permissions"]),
        # Which credential category this role belongs to, so the frontend can
        # group/scope roles without having to re-derive it from permissions.
        "category":    get_role_category(r),
        "created_at":  str(r.get("created_at", "")),
        "updated_at":  str(r.get("updated_at", "")),
    } for r in rows])


@role_bp.route("/api/roles-list", methods=["GET"])
@require_admin
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
def create_role():
    data            = request.json or {}
    name            = (data.get("name") or "").strip()
    description     = (data.get("description") or "").strip()
    permissions     = data.get("permissions", [])
    is_admin_flag = bool(data.get("is_admin", False))

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
def update_role(role_id):
    data            = request.json or {}
    name            = (data.get("name") or "").strip()
    description     = (data.get("description") or "").strip()
    permissions     = data.get("permissions", [])
    is_admin_flag = bool(data.get("is_admin", False))

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

    # ─── FIX: snapshot old per-username categories for this role BEFORE
    # updating, so that if this edit moves the role into a different
    # credential category we know which `users` rows need to follow it.
    # (See the users.category re-sync block below.)
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

    # ─── CREDENTIAL CATEGORY SEPARATION (NEW) ──────────────────────────────
    # Editing a role's permissions can move it into a different credential
    # category (e.g. a custom role that gains a document_stage_* module).
    # Any existing assignment rows for that role must follow it, otherwise a
    # stale category value would leave the row filed under the wrong tab and
    # could collide with a genuinely different assignment later.
    try:
        updated = get_role_by_id(role_id) or {}
        new_category = get_role_category(updated)
        _exec(supabase.table("user_roles").update({
            "category": new_category,
        }).eq("role_id", role_id))

        # ─────────────────────────────────────────────
        # FIX: users.category re-sync
        # ─────────────────────────────────────────────
        # user_roles.category was already kept in sync above, but
        # users.category (the separate per-category ACCOUNT/password row)
        # was not — so after a role's category changed, an affected
        # username's login/lock-state row would stay filed under the OLD
        # category. get_user_by_username_category(username, new_category)
        # would then find nothing, silently breaking Reset Password and
        # Unlock for that account (and, on the old fatal path, could even
        # look like "User not found") even though the role assignment
        # itself resolved correctly. This moves the users.category row to
        # match, but ONLY when doing so cannot collide with — and
        # therefore cannot destroy — an independent credential the same
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
def delete_role(role_id):
    row = get_role_by_id(role_id)
    if not row:
        return jsonify({"error": "Role not found"}), 404

    if row["name"] in BUILTIN_ROLE_PERMISSIONS:
        return jsonify({"error": f"Cannot delete built-in role '{row['name']}'"}), 400

    # Scoped by role_id, so only assignments OF THIS ROLE go away. Any other
    # role the same usernames hold in another category is untouched.
    _exec(supabase.table("user_roles").delete().eq("role_id", role_id))
    _exec(supabase.table("roles").delete().eq("id", role_id))
    return jsonify({"message": "Role deleted"})


@role_bp.route("/api/modules", methods=["GET"])
@require_admin
def get_modules():
    return jsonify({
        "all":        ALL_MODULES,
        "admin_only": list(ADMIN_ONLY_MODULES),
    })


# --- ROUTES: TWO-ADMINISTRATOR SELECTION -------------------------------------

@role_bp.route("/api/administrators", methods=["GET"])
@require_admin
def get_administrators():
    """Current holders of the (capped) Administrator role, excluding the
    reserved bootstrap 'admin' account. Used to populate the two
    selection slots in the frontend instead of listing admins in a table."""
    return jsonify({
        "administrators": get_current_admin_usernames(),
        "max": MAX_ADMINISTRATORS,
    })


@role_bp.route("/api/administrators", methods=["PUT"])
@require_admin
def set_administrators():
    """Sets EXACTLY the two Administrator slots to the given usernames.
    Anyone else currently holding Administrator (other than the reserved
    'admin' account) is demoted back to having no role in the admin
    category. Both slots are required and must be two distinct, existing
    users — this is what guarantees the system always has exactly two
    (non-reserved) administrators, never more, never fewer than intended.

    NOTE: every delete below is scoped to category="admin" only. A user
    being promoted, or a previous admin being demoted, may separately hold
    a completely independent Vital Record Management or Document Tracking
    role — that assignment must be left untouched by admin-slot changes.
    This endpoint only assigns the Administrator ROLE; it does not create a
    new password/account, so a promoted user keeps logging in with
    whichever existing credential (from whatever category) they already
    have."""
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

    # Demote anyone currently holding Administrator who ISN'T one of the two
    # incoming usernames, back to having no role assigned — in the admin
    # category only; their Vital/Document assignments (if any) are untouched.
    current_admins = get_current_admin_usernames()
    for uname in current_admins:
        if uname not in (slot1, slot2):
            _delete_user_role_scoped(uname, "admin")

    # (Re)assign both slots. Delete-then-insert avoids relying on an
    # upsert/on-conflict clause, and keeps this consistent with how the
    # rest of this file assigns roles. Scoped to category="admin" so this
    # never disturbs a Vital or Document role the same username also holds.
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
def get_user_roles():
    # ─── CREDENTIAL CATEGORY SEPARATION (NEW) ──────────────────────────────
    # `category` is selected and returned per row so the frontend can put
    # each assignment under the correct credential tab directly, instead of
    # inferring it from the permission list. A username with rows in both
    # categories now legitimately appears twice in this payload — once per
    # category — each with its own row id, role and assigned_at.
    select_cols = "id, username, category, assigned_at, roles(id, name, permissions)"
    if not _category_column_available():
        select_cols = "id, username, assigned_at, roles(id, name, permissions)"

    resp = _exec(
        supabase.table("user_roles")
        .select(select_cols)
        # Hide the reserved bootstrap admin account from the assignment list —
        # it's not something anyone "assigned", it's the built-in super-admin.
        .neq("username", RESERVED_ADMIN_USERNAME)
        .order("id")
    )
    rows = resp.data or []

    usernames = [r["username"] for r in rows]

    # ─── PER-CATEGORY PASSWORDS (NEW) ──────────────────────────────────────
    # `users` can now hold MULTIPLE rows per username (one per category), so
    # the lock/online lookup below is keyed by (username, category) rather
    # than by username alone — otherwise a Vital Record Management row's
    # lock/online state could bleed into the Document Tracking row for the
    # same username, or vice versa, whichever happened to come back last.
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
        # Fall back to deriving the category from the role itself if the
        # stored value is missing (pre-migration row).
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

    # ─────────────────────────────────────────────
    # TWO-ADMINISTRATOR CAP (generic assignment path)
    # ─────────────────────────────────────────────
    # Even though the frontend now steers admin assignment through the
    # dedicated /api/administrators slot endpoint, this generic endpoint
    # is enforced too, so the cap can never be bypassed by calling this
    # route directly.
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

    # ─────────────────────────────────────────────
    # CREDENTIAL CATEGORY SEPARATION (NEW)
    # ─────────────────────────────────────────────
    # Refuse to write at all if the schema migration hasn't been applied.
    # Without the category column the scoped delete below cannot be
    # guaranteed, and an unscoped one is what "moved" a user's credentials
    # from Vital Record Management into Document Tracking.
    #
    # NOTE: this check is about user_roles.category and is genuinely fatal —
    # it protects existing assignments from being destroyed. The separate
    # users.category check that used to sit here is NOT fatal and has been
    # replaced by the graceful fallback below.
    category = get_role_category(role)
    if not _category_column_available():
        return jsonify({"error": MIGRATION_REQUIRED_ERROR}), 500
    if category not in KNOWN_CATEGORIES:
        return jsonify({"error": f"Unrecognised credential category '{category}'"}), 400

    # ─────────────────────────────────────────────
    # PER-CATEGORY PASSWORDS (FIXED — NO LONGER FATAL)
    # ─────────────────────────────────────────────
    # Each credential category is meant to be its own independent ACCOUNT:
    # the same username can exist once per category, each with its OWN
    # password. That requires users.category.
    #
    # Previously, if that column was missing this endpoint returned HTTP 500
    # and NOTHING could be created — which is why Document Tracking
    # credentials could not be added at all. That was heavier-handed than
    # necessary: only the separate-password feature depends on this column,
    # not the role assignment itself.
    #
    # So now:
    #   • Column present  → full behaviour. A credential is "new" if THIS
    #     category has no account for this username yet, so "joshua" can get
    #     a brand-new Document Tracking password even though "joshua"
    #     already has a different Vital Record Management password.
    #   • Column missing  → legacy behaviour. One account per username,
    #     shared across categories. The assignment still succeeds and is
    #     still correctly category-scoped; the response carries a `warning`
    #     explaining that passwords are shared until the migration is run.
    users_scoped = _user_category_column_available()

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
        except Exception as e:
            # A duplicate-key error here means a UNIQUE(username) constraint
            # still exists on `users` even though the category column does.
            # Surface it instead of swallowing it, because the credential
            # would otherwise silently not exist.
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
    # If a credential already exists for this exact category, its password
    # is left untouched here — changing a password goes through the
    # dedicated "Reset Password" action (reset_password below), which is
    # itself scoped to this same (username, category) pair.

    # Previously this deleted EVERY existing user_roles row for `username`
    # before inserting the new one — so assigning a Document Tracking role
    # to a username that already had a Vital Record Management role would
    # silently wipe out the Vital role (and vice versa), because the old
    # schema only allowed one row per username, period.
    #
    # Now the delete (and the insert) is scoped to this role's category, so
    # only the row already occupying THAT SAME category gets replaced. A
    # role already held in a different category is left completely intact
    # — which is exactly what makes it possible to assign the same username
    # a separate role (and, per the fix above, a separate password) in
    # Document Tracking without touching its existing Vital Record
    # Management role or password.
    #
    # Snapshot of the other categories is taken first and verified after the
    # write, so if anything ever does over-delete it is caught immediately
    # rather than quietly losing an assignment.
    before_other = _other_category_rows(username, category)

    try:
        _delete_user_role_scoped(username, category)
        _exec(supabase.table("user_roles").insert({
            "username": username,
            "role_id": role_id,
            "category": category,
        }))
    except Exception as e:
        print(f"[ROLES] assign_role failed for '{username}' ({category}): {e!r}")
        return jsonify({"error": f"Could not assign role: {e}"}), 500

    after_other = _other_category_rows(username, category)
    lost = [c for c in before_other if c not in after_other]
    if lost:
        # Should be impossible now, but never fail silently if it happens.
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
    the given category. Used purely as a before/after safety check around a
    category-scoped write."""
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


@role_bp.route("/api/user-roles/<username>", methods=["DELETE"])
@require_admin
def remove_user_role(username):
    caller = session.get("username")
    if caller == username:
        return jsonify({"error": "You cannot remove your own role"}), 400

    if username.lower() == RESERVED_ADMIN_USERNAME:
        return jsonify({"error": "Cannot remove the reserved admin account"}), 400

    # ─────────────────────────────────────────────
    # CREDENTIAL CATEGORY SEPARATION (NEW)
    # ─────────────────────────────────────────────
    # A username can now hold an independent role in both the Vital Record
    # Management and Document Tracking categories at once, so a bare
    # username is no longer enough to identify a single assignment to
    # remove. The frontend passes ?category=<vital|document> AND
    # ?role_id=<id> (the specific user_roles row) so ONLY that one
    # category's assignment is deleted — any other role the same username
    # holds in a different category is left completely untouched.
    #
    # Both filters are applied when present. If neither is supplied the
    # request is rejected rather than falling back to the old
    # "remove every role this username holds" behaviour, which is what
    # could destroy the other module's credentials.
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

    # ─────────────────────────────────────────────
    # FIX: never silently degrade into an unscoped delete
    # ─────────────────────────────────────────────
    # The category filter can only actually be applied once the
    # user_roles.category column exists. If the caller supplied ONLY a
    # category (no role_id) and that column isn't available yet, neither
    # filter below would end up applied — leaving the delete scoped by
    # `username` alone, which removes EVERY role that username holds
    # across all categories. That is exactly the "wiped the other
    # module's credentials" bug this endpoint exists to prevent, so this
    # specific combination is refused up front instead.
    category_filter_applicable = bool(category) and _category_column_available()

    if not role_id and not category_filter_applicable:
        return jsonify({
            "error": (
                "Cannot safely scope this delete: no role_id was provided and "
                "the credential-category column is not available yet. Refusing "
                "to remove every role this username holds."
            )
        }), 400

    query = supabase.table("user_roles").delete().eq("username", username)
    if role_id:
        query = query.eq("role_id", role_id)
    if category_filter_applicable:
        query = query.eq("category", category)
    _exec(query)

    # NOTE: this intentionally does NOT delete the matching `users` (login
    # credential) row. Removing a role assignment revokes access; it does
    # not delete the account/password itself (this mirrors the original,
    # pre-existing behaviour — "The user account will remain" — now simply
    # scoped to the one category's credential instead of the whole user).

    return jsonify({"message": f"Role removed from '{username}'"})


@role_bp.route("/api/user-roles/<username>/reset-password", methods=["PUT"])
@require_admin
def reset_password(username):
    data     = request.json or {}
    password = (data.get("password") or "").strip()
    category = (data.get("category") or "").strip()

    if not password:
        return jsonify({"error": "New password is required"}), 400

    # ─────────────────────────────────────────────
    # PER-CATEGORY PASSWORDS (NEW)
    # ─────────────────────────────────────────────
    # Each credential category is now its own account with its own
    # password, so a bare username is no longer enough to know WHICH
    # password to change. `category` (sent by the frontend, taken from the
    # exact row the admin opened "Reset Password" on) scopes this update to
    # that ONE credential — it can never touch a same-named account sitting
    # in a different category.
    if _user_category_column_available():
        if not category or category not in KNOWN_CATEGORIES:
            return jsonify({"error": "A valid category is required to reset this credential's password"}), 400
        if not get_user_by_username_category(username, category):
            return jsonify({"error": "User not found"}), 404
        _exec(supabase.table("users").update({
            "password":       hash_password(password),
            "login_attempts": 0,
            "temp_attempts":  0,
            "lock_time":      None,
            "lock_level":     0,
        }).eq("username", username).eq("category", category))
    else:
        # Pre-migration fallback — matches the old, username-only behaviour
        # (one shared account/password per username). `category` is simply
        # ignored here rather than rejected, so the frontend can always send
        # it and this keeps working either way.
        if not get_user_by_username(username):
            return jsonify({"error": "User not found"}), 404
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
def unlock_user(username):
    # ─── PER-CATEGORY PASSWORDS (NEW) ──────────────────────────────────────
    # Lock state (login_attempts / lock_level / lock_time) now belongs to
    # one specific (username, category) account, not to the username alone
    # — the same reasoning as reset_password above. `category` is passed as
    # a query param since this is a plain PUT with no request body.
    category = (request.args.get("category") or "").strip()

    if _user_category_column_available():
        if not category or category not in KNOWN_CATEGORIES:
            return jsonify({"error": "A valid category is required to unlock this credential"}), 400
        if not get_user_by_username_category(username, category):
            return jsonify({"error": "User not found"}), 404
        _exec(supabase.table("users").update({
            "login_attempts": 0,
            "temp_attempts":  0,
            "lock_time":      None,
            "lock_level":     0,
        }).eq("username", username).eq("category", category))
    else:
        # Pre-migration fallback — matches the old, username-only behaviour.
        if not get_user_by_username(username):
            return jsonify({"error": "User not found"}), 404
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

    # ─── CREDENTIAL CATEGORY SEPARATION (NEW) ──────────────────────────
    # A username may now hold more than one row (one per category), so
    # role names and permissions across all of them are combined instead
    # of only reading whichever single row came back first.
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


# --- LOGOUT -------------------------------------------------------------------
@role_bp.route("/api/logout", methods=["POST"])
def logout():
    username = session.get("username")
    if username:
        try:
            _exec(supabase.table("users").update({
                "is_online":   False,
                "last_logout": now_iso(),
            }).eq("username", username))
        except Exception as e:
            # Don't let a transient Supabase/network hiccup prevent the
            # session from actually being cleared — the user must always
            # be able to log out cleanly even if the "last seen"
            # bookkeeping update itself fails. Without this try/except the
            # exception would propagate to the blueprint error handler
            # (returning a 503 before session.clear() runs), leaving the
            # client and server in an inconsistent "am I logged in?" state.
            print(f"[ROLES] logout: failed to update is_online for '{username}': {e!r}")

    session.clear()
    return jsonify({"message": "Logged out successfully"})


@role_bp.route("/api/logout-beacon", methods=["POST"])
def logout_beacon():
    username = session.get("username")
    if username:
        try:
            _exec(supabase.table("users").update({
                "is_online":   False,
                "last_logout": now_iso(),
            }).eq("username", username))
        except Exception as e:
            print(f"[ROLES] logout_beacon: failed to update is_online for '{username}': {e!r}")
    return ("", 204)
# -*- coding: utf-8 -*-