import json
import os
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from supabase_client import supabase
from auth.offline_record import build_offline_record

login_bp = Blueprint('login', __name__)

ADMIN_ONLY_MODULES = {"role_management", "user_management", "audit_logs"}
RESERVED_ADMIN_USERNAME = "admin"

# Session lifetimes (seconds). Stored INSIDE each session as `ttl` and enforced
# by enforce_session_expiry() in app.py.
SESSION_TTL_DEFAULT = 24 * 3600
SESSION_TTL_REMEMBER_ME = 7 * 24 * 3600

# Single source of truth for which column holds the password hash.
PASSWORD_COLUMN = "password"

# ─────────────────────────────────────────────
# ATTEMPT / LOCKOUT CONFIG (online, stored in Supabase)
# ─────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 3
LOCK_TIER_SECONDS = {
    1: 5 * 60,            # 5 minutes
    2: 10 * 60,           # 10 minutes
    3: 24 * 60 * 60,      # 24 hours
}
MAX_LOCK_TIER = 3

# ─────────────────────────────────────────────
# LOCAL USER CACHE (offline fallback)
# ─────────────────────────────────────────────
# When Supabase can't be reached (no internet / brownout / outage), login falls
# back to this file. It only ever stores the salted password HASH, never the
# plain password. Add `local_users.json` to .gitignore.
#
# The file is filled in two ways:
#   1. Automatically after every successful ONLINE login.
#   2. Manually with seed_local_users.py (for users who never logged in online).
LOCAL_USERS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "local_users.json"
)

OFFLINE_MAX_ATTEMPTS = 5
OFFLINE_LOCK_SECONDS = 5 * 60


def hash_password(password):
    """Hash a password using a salted algorithm (pbkdf2:sha256 by default)."""
    return generate_password_hash(password)


def verify_password(password, stored_hash):
    """Verify a plaintext password against a stored salted hash."""
    try:
        return check_password_hash(stored_hash, password)
    except Exception as e:
        print(f"[LOGIN] Password verification error: {e}")
        return False


def now_iso():
    """Return current UTC time in ISO format"""
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value):
    """Best-effort parse of a Supabase timestamp value (str or datetime) into
    a tz-aware UTC datetime. Returns None if it can't be parsed."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        raw = value.replace("Z", "+00:00") if value.endswith("Z") else value
        dt = datetime.fromisoformat(raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def compute_lock_status(user):
    """
    Returns (is_locked, seconds_remaining, lock_level) for a user row,
    computed fresh against the current time.
    """
    lock_level = user.get('lock_level') or 0
    locked_until = _parse_ts(user.get('lock_time'))

    if not lock_level or not locked_until:
        return False, 0, lock_level

    now = datetime.now(timezone.utc)
    if now < locked_until:
        return True, int((locked_until - now).total_seconds()), lock_level

    return False, 0, lock_level


def _format_duration(seconds):
    """Human-readable duration for lockout messages."""
    if seconds >= 3600:
        hrs = max(1, round(seconds / 3600))
        return f"{hrs} hour{'s' if hrs != 1 else ''}"
    mins = max(1, round(seconds / 60))
    return f"{mins} minute{'s' if mins != 1 else ''}"


# ─────────────────────────────────────────────
# LOCAL CACHE HELPERS
# ─────────────────────────────────────────────
def _load_local_users():
    try:
        with open(LOCAL_USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[LOCAL CACHE] Could not read {LOCAL_USERS_FILE}: {e}")
        return {}


def _write_local_users(data):
    try:
        tmp = LOCAL_USERS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, LOCAL_USERS_FILE)
        return True
    except Exception as e:
        print(f"[LOCAL CACHE] Could not write {LOCAL_USERS_FILE}: {e}")
        return False


def _save_local_user(user, role_names, permissions):
    """Copy the user (hash only) into the local cache after an online login."""
    try:
        data = _load_local_users()
        key = user["username"].strip().lower()
        previous = data.get(key, {})
        data[key] = {
            "id": user["id"],
            "username": user["username"],
            "password": user[PASSWORD_COLUMN],
            "roles": list(role_names),
            "permissions": sorted(permissions),
            "saved_at": now_iso(),
            "fail_count": 0,
            "locked_until": None,
        }
        # keep nothing else from the previous record; it is fully refreshed
        _ = previous
        _write_local_users(data)
    except Exception as e:
        print(f"[LOCAL CACHE ERROR] {e}")


def _offline_login(username, password):
    """Verify against the local cache when Supabase is unreachable."""
    key = (username or "").strip().lower()
    data = _load_local_users()
    rec = data.get(key)

    if not rec:
        return jsonify({
            "success": False,
            "message": "Server database is unavailable and this account has no saved offline login."
        }), 503

    # Offline lockout (stored in the local file so a refresh can't bypass it)
    locked_until = _parse_ts(rec.get("locked_until"))
    now = datetime.now(timezone.utc)
    if locked_until and now < locked_until:
        remaining = int((locked_until - now).total_seconds())
        return jsonify({
            "success": False,
            "message": f"Account is locked. Please try again in {_format_duration(remaining)}.",
            "lock_seconds_remaining": remaining,
        }), 403

    if not verify_password(password, rec.get("password", "")):
        fails = (rec.get("fail_count") or 0) + 1
        rec["fail_count"] = fails
        if fails >= OFFLINE_MAX_ATTEMPTS:
            rec["fail_count"] = 0
            rec["locked_until"] = (now + timedelta(seconds=OFFLINE_LOCK_SECONDS)).isoformat()
            _write_local_users(data)
            return jsonify({
                "success": False,
                "message": (
                    f"Account locked after {OFFLINE_MAX_ATTEMPTS} failed attempts. "
                    f"Please try again in {_format_duration(OFFLINE_LOCK_SECONDS)}."
                ),
                "lock_seconds_remaining": OFFLINE_LOCK_SECONDS,
            }), 403
        _write_local_users(data)
        return jsonify({
            "success": False,
            "message": "Invalid username or password."
        }), 401

    # Correct password
    rec["fail_count"] = 0
    rec["locked_until"] = None
    _write_local_users(data)

    perms = set(rec.get("permissions", []))
    roles = rec.get("roles", [])
    is_admin_flag = "*" in perms or rec["username"].lower() == RESERVED_ADMIN_USERNAME
    if is_admin_flag:
        perms.add("*")
    perms.add("dashboard")

    session.clear()
    session['user_id'] = rec["id"]
    session['username'] = rec["username"]
    session['is_admin'] = is_admin_flag
    session['role'] = ", ".join(roles) if roles else (
        "Administrator" if is_admin_flag else "User"
    )
    session['logged_in_at'] = now_iso()
    session['ttl'] = SESSION_TTL_DEFAULT
    session['last_seen'] = datetime.now(timezone.utc).timestamp()
    session['offline_mode'] = True
    session.permanent = True

    print(f"[LOGIN] OFFLINE login for '{rec['username']}'")

    return jsonify({
        "success": True,
        "message": "Login successful (offline mode)",
        "user": {
            "id": rec["id"],
            "username": rec["username"],
            "is_admin": is_admin_flag,
            "is_locked": False,
            "roles": roles,
            "permissions": sorted(perms),
        },
    }), 200


# ─────────────────────────────────────────────
# AUDIT LOG ADAPTER
# ─────────────────────────────────────────────
AUDIT_DESCRIPTIONS = {
    "LOGIN_SUCCESS": "Signed in",
    "LOGIN_FAILED":  "Failed sign-in attempt",
    "ACCOUNT_LOCKED": "Account locked",
    "LOGOUT":        "Signed out",
}


def client_ip():
    """Real client IP. Behind Vercel/Render, request.remote_addr is the proxy's
    address, so prefer the first entry of X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def safe_record_action(user_id, action, details=None, status=None):
    """Safely record an audit action - handles errors gracefully"""
    try:
        from logs.Audits import record_action

        details = dict(details or {})
        description = AUDIT_DESCRIPTIONS.get(action, action.replace("_", " ").title())
        if details.get("reason"):
            description = f"{description}: {details['reason']}"

        username = details.get("username") or session.get("username")
        role_names = details.get("roles") or []
        role = details.get("role") or (", ".join(role_names) if role_names else None)
        if user_id is not None:
            details.setdefault("user_id", user_id)
        if status is None:
            status = {
                "LOGIN_SUCCESS": "SUCCESS",
                "LOGIN_FAILED": "FAILED",
                "ACCOUNT_LOCKED": "DENIED",
                "LOGOUT": "SUCCESS",
            }.get(action, "FAILED")

        return record_action(
            action,
            description,
            username=username,
            meta=details,
            ip=client_ip(),
            user_id=user_id,
            role=role,
            status=status,
        )
    except Exception as e:
        print(f"[AUDIT ERROR] {e}")
        return None


def get_roles_and_permissions(username, category=None):
    """Role names + permission set for a username. When `category` is given,
    only that credential's role is counted, so each password unlocks exactly
    its own category's permissions."""
    role_names = []
    permissions = set()

    def _fetch(with_category):
        q = supabase.table('user_roles').select('role_id, roles(*)').eq('username', username)
        if with_category and category:
            q = q.eq('category', category)
        return q.execute().data or []

    try:
        try:
            user_roles = _fetch(True)
        except Exception:
            # user_roles.category not migrated yet: use every row.
            user_roles = _fetch(False)
        print(f"[LOGIN] Found {len(user_roles)} role(s) for '{username}'")

        for ur in user_roles:
            role = ur.get('roles', {})
            if isinstance(role, list):
                role = role[0] if role else {}
            if role:
                role_names.append(role.get('name', ''))
                role_perms = role.get('permissions', [])
                if isinstance(role_perms, list):
                    permissions.update(role_perms)
                elif isinstance(role_perms, str):
                    try:
                        perms_list = json.loads(role_perms)
                        if isinstance(perms_list, list):
                            permissions.update(perms_list)
                    except Exception:
                        pass
    except Exception as e:
        print(f"[ROLES ERROR] {e} (This is okay if roles table doesn't exist yet)")

    return role_names, permissions


def resolve_is_admin(username, permissions):
    """
    users has no 'is_admin' column. The reserved 'admin' account is always
    admin, otherwise it's whoever holds an admin-only module permission.
    """
    if username and username.lower() == RESERVED_ADMIN_USERNAME:
        return True
    return bool(permissions & ADMIN_ONLY_MODULES)


def _pick_credential_row(rows, password):
    """A username can have one users row per category, each with its own
    password. Return the row whose password matches, or the first row with
    matched=False if none match."""
    for row in rows:
        stored = row.get(PASSWORD_COLUMN)
        if stored and verify_password(password, stored):
            return row, True
    return (rows[0] if rows else None), False


def _store_offline_record(user, password, role_names, permissions, is_admin_flag):
    """Save the encrypted offline unlock record. This is possible only here,
    because this is the moment the plaintext password is known."""
    try:
        profile = {
            "id": user["id"],
            "username": user["username"],
            "category": user.get("category"),
            "is_admin": bool(is_admin_flag),
            "roles": list(role_names),
            "permissions": sorted(permissions),
        }
        record = build_offline_record(password, profile)
        supabase.table("users").update(
            {"offline_record": record}
        ).eq("id", user["id"]).execute()
    except Exception as e:
        print(f"[OFFLINE RECORD] could not store for '{user.get('username')}': {e}")


@login_bp.route('/api/login', methods=['POST'])
def login():
    username = None
    try:
        data = request.get_json()
        print(f"[LOGIN] Request received")

        if not data:
            safe_record_action(None, "LOGIN_FAILED", {"reason": "Malformed JSON body"})
            return jsonify({
                "success": False,
                "message": "Missing JSON body"
            }), 400

        username = data.get('username')
        password = data.get('password')
        remember_me = data.get('remember_me', False)

        if username:
            username = username.strip()

        print(f"[LOGIN] Username: '{username}'")

        if not username or not password:
            safe_record_action(None, "LOGIN_FAILED", {
                "username": username,
                "reason": "Malformed credentials",
            })
            return jsonify({
                "success": False,
                "message": "Username and password required"
            }), 400

        # Query user by username
        try:
            response = supabase.table('users')\
                .select('*')\
                .eq('username', username)\
                .execute()

            users = response.data
            print(f"[LOGIN] Found {len(users)} user(s)")
        except Exception as e:
            # Supabase unreachable (no internet, outage, brownout recovery...)
            # -> fall back to the locally saved hash instead of failing.
            print(f"[DB ERROR] {e}")
            print("[LOGIN] Database unreachable, trying local offline cache")
            return _offline_login(username, password)

        if not users:
            safe_record_action(None, "LOGIN_FAILED", {"username": username, "reason": "User not found"})
            return jsonify({
                "success": False,
                "message": "Invalid username or password"
            }), 401

        user, _matched = _pick_credential_row(users, password)

        if PASSWORD_COLUMN not in user:
            print(f"[LOGIN ERROR] Expected '{PASSWORD_COLUMN}' column not found on users row: {list(user.keys())}")
            safe_record_action(user.get("id"), "LOGIN_FAILED", {
                "username": username,
                "reason": "Password configuration error",
            })
            return jsonify({
                "success": False,
                "message": "Database configuration error"
            }), 500

        # ── LOCKOUT CHECK (before password verification) ──────────────
        is_locked, seconds_remaining, _ = compute_lock_status(user)
        if is_locked:
            safe_record_action(user.get('id'), "ACCOUNT_LOCKED", {
                "username": username,
                "reason": "Account locked",
            })
            return jsonify({
                "success": False,
                "message": f"Account is locked. Please try again in {_format_duration(seconds_remaining)}.",
                "lock_seconds_remaining": seconds_remaining,
            }), 403

        stored_hash = user.get(PASSWORD_COLUMN)
        print(f"[LOGIN] Using password column: '{PASSWORD_COLUMN}'")

        # Verify password using salted hash comparison
        if not stored_hash or not verify_password(password, stored_hash):
            print(f"[LOGIN] Password mismatch for user '{username}'")

            attempts = (user.get('login_attempts') or 0) + 1
            update_fields = {'login_attempts': attempts}

            if attempts >= MAX_LOGIN_ATTEMPTS:
                new_tier = min((user.get('lock_level') or 0) + 1, MAX_LOCK_TIER)
                duration = LOCK_TIER_SECONDS[new_tier]
                locked_until = datetime.now(timezone.utc) + timedelta(seconds=duration)
                update_fields.update({
                    'lock_level': new_tier,
                    'lock_time': locked_until.isoformat(),
                    'login_attempts': 0,
                })
            else:
                update_fields['lock_time'] = None

            try:
                supabase.table('users').update(update_fields).eq('id', user['id']).execute()
            except Exception as e:
                print(f"[LOGIN LOCKOUT UPDATE ERROR] {e}")

            if attempts >= MAX_LOGIN_ATTEMPTS:
                safe_record_action(user.get('id'), "LOGIN_FAILED", {
                    "username": username,
                    "reason": "Invalid password",
                })
                safe_record_action(user.get('id'), "ACCOUNT_LOCKED", {
                    "username": username,
                    "reason": "Maximum failed attempts reached",
                    "lock_level": update_fields["lock_level"],
                })
                return jsonify({
                    "success": False,
                    "message": (
                        f"Account locked after {MAX_LOGIN_ATTEMPTS} failed attempts. "
                        f"Please try again in {_format_duration(duration)}."
                    ),
                }), 403

            remaining = MAX_LOGIN_ATTEMPTS - attempts
            safe_record_action(user.get('id'), "LOGIN_FAILED", {
                "username": username,
                "reason": "Invalid password",
            })
            return jsonify({
                "success": False,
                "message": (
                    f"Invalid username or password. {remaining} attempt"
                    f"{'s' if remaining != 1 else ''} remaining before temporary lockout."
                ),
            }), 401

        # Get roles/permissions BEFORE building the session
        role_names, permissions = get_roles_and_permissions(user['username'], user.get('category'))
        is_admin_flag = resolve_is_admin(user['username'], permissions)

        if is_admin_flag:
            permissions.add('*')

        # Always include baseline dashboard access
        permissions.add('dashboard')

        # Refresh the local offline cache (hash only) after every good login
        _save_local_user(user, role_names, permissions)
        _store_offline_record(user, password, role_names, permissions, is_admin_flag)

        # ============================================
        # SUCCESSFUL LOGIN - SET SESSION
        # ============================================
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = is_admin_flag
        session['role'] = ", ".join(role_names) if role_names else (
            "Administrator" if is_admin_flag else "User"
        )
        # NOTE: with signed-cookie sessions everything below lives inside the
        # browser cookie (~4 KB limit). Delete this if nothing reads it.
        user_data = {k: v for k, v in user.items() if k != PASSWORD_COLUMN}
        session['user_data'] = user_data
        session['logged_in_at'] = now_iso()

        session['ttl'] = SESSION_TTL_REMEMBER_ME if remember_me else SESSION_TTL_DEFAULT
        session['last_seen'] = datetime.now(timezone.utc).timestamp()
        session.permanent = True

        print(f"[LOGIN] Session set for user: {username}")

        # Successful login fully resets the attempt/lockout state.
        try:
            update_data = {
                'last_login': now_iso(),
                'is_online': True,
                'login_attempts': 0,
                'lock_level': 0,
                'lock_time': None,
            }
            supabase.table('users')\
                .update(update_data)\
                .eq('id', user['id'])\
                .execute()
            print(f"[LOGIN] Updated last_login for user {username}")
        except Exception as e:
            print(f"[DB UPDATE ERROR] {e}")

        safe_record_action(user['id'], "LOGIN_SUCCESS", {
            "username": username,
            "remember_me": remember_me,
            "roles": role_names,
        })

        response_user = {
            "id": user['id'],
            "username": user['username'],
            "is_admin": is_admin_flag,
            "is_locked": False,
            "roles": role_names,
            "permissions": list(permissions),
            "category": user.get("category"),
        }

        print(f"[LOGIN] Login successful for {username}")

        return jsonify({
            "success": True,
            "message": "Login successful",
            "user": response_user
        }), 200

    except Exception as e:
        print(f"[LOGIN ERROR] {e}")
        safe_record_action(None, "LOGIN_FAILED", {
            "username": username,
            "reason": "Unexpected login failure",
        })
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": "Server error. Please try again later."
        }), 500


@login_bp.route('/api/logout', methods=['POST'])
def logout():
    try:
        user_id = session.get('user_id')

        if user_id:
            try:
                supabase.table('users')\
                    .update({
                        'is_online': False,
                        'last_logout': now_iso()
                    })\
                    .eq('id', user_id)\
                    .execute()
            except Exception as e:
                print(f"[LOGOUT UPDATE ERROR] {e}")

            # Must run BEFORE session.clear() so the username is still available.
            safe_record_action(user_id, "LOGOUT", {"username": session.get('username')})

        session.clear()

        return jsonify({
            "success": True,
            "message": "Logged out successfully"
        }), 200

    except Exception as e:
        print(f"[LOGOUT ERROR] {e}")
        return jsonify({
            "success": False,
            "message": "Logout failed"
        }), 500


@login_bp.route('/api/logout-beacon', methods=['POST'])
def logout_beacon():
    """Update presence on page hide without treating it as an explicit logout."""
    user_id = session.get('user_id')
    if user_id:
        try:
            supabase.table('users').update({
                'is_online': False,
                'last_logout': now_iso(),
            }).eq('id', user_id).execute()
        except Exception as e:
            print(f"[LOGOUT BEACON UPDATE ERROR] {e}")
    return '', 204


def _session_from_local_cache():
    """Build a /api/session response from the local cache when the DB is down,
    so an already-logged-in user isn't kicked out during an outage."""
    username = session.get('username')
    rec = _load_local_users().get((username or "").strip().lower())
    if not rec:
        return None

    perms = set(rec.get("permissions", []))
    roles = rec.get("roles", [])
    is_admin_flag = "*" in perms or rec["username"].lower() == RESERVED_ADMIN_USERNAME
    if is_admin_flag:
        perms.add("*")
    perms.add("dashboard")

    return jsonify({
        "authenticated": True,
        "is_admin": is_admin_flag,
        "role": roles[0] if roles else None,
        "permissions": list(perms),
        "offline": True,
        "user": {
            "id": rec["id"],
            "username": rec["username"],
            "is_admin": is_admin_flag,
            "is_locked": False,
            "roles": roles,
            "permissions": list(perms),
        },
    }), 200


@login_bp.route('/api/session', methods=['GET'])
@login_bp.route('/api/my-permissions', methods=['GET'])
def get_session():
    """Check session authentication status and return active permissions"""
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                "authenticated": False,
                "permissions": [],
                "is_admin": False
            }), 200

        try:
            response = supabase.table('users')\
                .select('*')\
                .eq('id', user_id)\
                .execute()

            if not response.data:
                session.clear()
                return jsonify({
                    "authenticated": False,
                    "permissions": [],
                    "is_admin": False
                }), 200

            user = response.data[0]

            role_names, permissions = get_roles_and_permissions(user['username'], user.get('category'))
            is_admin_flag = resolve_is_admin(user['username'], permissions)

            if is_admin_flag:
                permissions.add('*')

            permissions.add('dashboard')

            is_locked, _, _ = compute_lock_status(user)

            return jsonify({
                "authenticated": True,
                "is_admin": is_admin_flag,
                "role": role_names[0] if role_names else None,
                "permissions": list(permissions),
                "user": {
                    "id": user['id'],
                    "username": user['username'],
                    "is_admin": is_admin_flag,
                    "is_locked": is_locked,
                    "roles": role_names,
                    "permissions": list(permissions)
                }
            }), 200

        except Exception as e:
            # Transient Supabase/network error: the login itself is still valid,
            # so do NOT clear the session. Use the local cache if we have one,
            # otherwise report a temporary failure and let the client retry.
            print(f"[SESSION ERROR] {e}")
            cached = _session_from_local_cache()
            if cached is not None:
                return cached
            return jsonify({
                "error": "Temporary server error, please retry"
            }), 503

    except Exception as e:
        print(f"[SESSION ERROR] {e}")
        return jsonify({
            "authenticated": False,
            "permissions": [],
            "is_admin": False
        }), 200


@login_bp.route('/api/current-user', methods=['GET'])
def current_user():
    username = session.get("username")
    if not username:
        return jsonify({"error": "Not logged in"}), 401

    role_names, permissions = get_roles_and_permissions(username)
    is_admin_flag = resolve_is_admin(username, permissions)
    if is_admin_flag:
        permissions.add("*")
    permissions.add("dashboard")
    return jsonify({
        "username": username,
        "is_admin": is_admin_flag,
        "permissions": list(permissions),
    }), 200


OFFLINE_CRED_MODULES = [
    "birth_record", "archive_birth",
    "death_record", "archive_death",
    "marriage_record", "archive_marriage",
]

@login_bp.route('/api/offline-credentials', methods=['GET'])
def offline_credentials():
    """Return the bcrypt verifier for every module password so the device can
    verify offline. Requires a logged-in session. Null = no password set."""
    if not session.get('user_id'):
        return jsonify({"error": "Not logged in."}), 401
    try:
        res = (supabase.table("module_passwords")
               .select("module_key, password_hash")
               .in_("module_key", OFFLINE_CRED_MODULES)
               .execute())
    except Exception as e:
        print(f"[OFFLINE CREDS] {e}")
        return jsonify({"error": "Temporary server error"}), 503
    found = {r["module_key"]: r.get("password_hash") for r in (res.data or [])}
    modules = {
        m: (found[m] if found.get(m) and str(found[m]).startswith("$2") else None)
        for m in OFFLINE_CRED_MODULES
    }
    resp = jsonify({"modules": modules})
    resp.headers["Cache-Control"] = "no-store"
    return resp, 200