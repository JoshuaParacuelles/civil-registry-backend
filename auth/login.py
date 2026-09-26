import os
import sys
import json
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from supabase_client import supabase

login_bp = Blueprint('login', __name__)

ADMIN_ONLY_MODULES = {"role_management", "user_management", "audit_logs"}
RESERVED_ADMIN_USERNAME = "admin"

# Session lifetimes (seconds). Stored INSIDE each session as `ttl` and enforced
# by enforce_session_expiry() in app.py. Do NOT change
# app.config['PERMANENT_SESSION_LIFETIME'] per login: that value is global to
# the whole process, and Flask uses it to validate every session cookie's age.
SESSION_TTL_DEFAULT = 24 * 3600
SESSION_TTL_REMEMBER_ME = 7 * 24 * 3600

# The single source of truth for which column holds the password hash.
# Rolemanagement.py (account creation, password reset, and the bootstrap
# 'admin' user) exclusively writes to a column called 'password'. The old
# version of this file guessed between several possible column names
# ('password_hash', 'password', 'pass_hash', ...) and picked whichever one
# appeared first in that list — if the users table also had an unused
# 'password_hash' column sitting around, it would be picked over the real
# 'password' column, read as None, and cause every login to fail with
# "Invalid credentials" even with the correct password.
PASSWORD_COLUMN = "password"

# ─────────────────────────────────────────────
# ATTEMPT / LOCKOUT CONFIG
# ─────────────────────────────────────────────
# Each "cycle" gives the account MAX_LOGIN_ATTEMPTS failed tries before it is
# locked. The lock duration escalates with each *consecutive* lockout:
#   tier 1 -> 5 minutes
#   tier 2 -> 10 minutes
#   tier 3 -> 24 hours
# A successful login is the only thing that resets the tier back to 0.
# Beyond tier 3 the spec doesn't say what happens on a further failure cycle,
# so this caps at the 24h duration (tier stays at 3) rather than escalating
# further or wrapping back to 5 minutes. Change MAX_LOCK_TIER's behavior
# below (the `min(..., MAX_LOCK_TIER)` line) if you'd rather have it wrap
# back to tier 1 after a 24h lock is served.
MAX_LOGIN_ATTEMPTS = 3
LOCK_TIER_SECONDS = {
    1: 5 * 60,            # 5 minutes
    2: 10 * 60,           # 10 minutes
    3: 24 * 60 * 60,      # 24 hours
}
MAX_LOCK_TIER = 3

# Column semantics for the two columns that already existed on `users`:
#   lock_level -> escalation tier (0..MAX_LOCK_TIER). PERSISTS across an
#                 unlock so the *next* lockout in a row escalates. Only a
#                 successful login resets it to 0.
#   lock_time  -> the UTC timestamp the CURRENT lock EXPIRES AT (not when it
#                 started). NULL whenever there is no active lock. This
#                 lets "is currently locked" be a single now()-comparison
#                 instead of needing to also know the tier's duration.
# `login_attempts` keeps its original meaning: failed tries in the current
# (post-unlock) cycle. `temp_attempts` is left untouched/unused.


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
    based on the persisted lock_level / lock_time columns. Always computed
    fresh against the current time so a lock that has simply timed out
    (but hasn't been written back to the DB yet by a login attempt) is
    correctly reported as unlocked.
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
# AUDIT LOG ADAPTER
# ─────────────────────────────────────────────
# This file calls safe_record_action(user_id, action, details), but
# logs.Audits.record_action has the signature
# record_action(action, description, username=None, meta=None, ip=None).
# Passing the arguments straight through stored the user id as the action
# and the details dict as the username, which is why login rows looked
# garbled. This adapter translates between the two, and maps LOGIN_SUCCESS
# onto "LOGIN", the key the Audit Logs page actually has a badge for.
AUDIT_ACTION_MAP = {
    "LOGIN_SUCCESS": "LOGIN",
}

AUDIT_DESCRIPTIONS = {
    "LOGIN_SUCCESS": "Signed in",
    "LOGIN_FAILED":  "Failed sign-in attempt",
    "LOGOUT":        "Signed out",
    "LOGOUT_BEACON": "Left the page or closed the tab",
}


def client_ip():
    """Real client IP. Behind Vercel/Render, request.remote_addr is the proxy's
    address, so prefer the first entry of X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def safe_record_action(user_id, action, details=None):
    """Safely record an audit action - handles errors gracefully"""
    try:
        from logs.Audits import record_action

        details = dict(details or {})
        description = AUDIT_DESCRIPTIONS.get(action, action.replace("_", " ").title())
        if details.get("reason"):
            description = f"{description}: {details['reason']}"

        username = details.get("username") or session.get("username")
        if user_id is not None:
            details.setdefault("user_id", user_id)

        return record_action(
            AUDIT_ACTION_MAP.get(action, action),
            description,
            username=username,
            meta=details,
            ip=client_ip(),
        )
    except Exception as e:
        print(f"[AUDIT ERROR] {e}")
        return None


def get_roles_and_permissions(username):
    """
    Look up role names + flattened permission set for a username.

    IMPORTANT: user_roles is keyed by 'username' (see Rolemanagement.py /
    the roles schema), NOT 'user_id' — there is no user_id column on that
    table. Querying by user_id silently returns zero rows.
    """
    role_names = []
    permissions = set()
    try:
        roles_response = (
            supabase.table('user_roles')
            .select('role_id, roles(*)')
            .eq('username', username)
            .execute()
        )
        user_roles = roles_response.data or []
        print(f"[LOGIN] Found {len(user_roles)} role(s) for '{username}'")

        for ur in user_roles:
            role = ur.get('roles', {})
            # Supabase embeds can come back as a dict OR a single-item list
            # depending on the relationship direction. Normalize both.
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
    users has no 'is_admin' column, so it can't be read off the row.
    Derive it the same way Rolemanagement.py's is_admin() does: the
    reserved 'admin' account is always admin, otherwise it's whoever
    holds an admin-only module permission.
    """
    if username and username.lower() == RESERVED_ADMIN_USERNAME:
        return True
    return bool(permissions & ADMIN_ONLY_MODULES)


@login_bp.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        print(f"[LOGIN] Request received")

        if not data:
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
            print(f"[DB ERROR] {e}")
            return jsonify({
                "success": False,
                "message": "Database error"
            }), 500

        if not users:
            # No account to rate-limit/lock here — nothing is persisted for
            # a username that doesn't exist, so there's nothing to escalate.
            safe_record_action(None, "LOGIN_FAILED", {"username": username, "reason": "User not found"})
            return jsonify({
                "success": False,
                "message": "Invalid username or password"
            }), 401

        user = users[0]

        if PASSWORD_COLUMN not in user:
            print(f"[LOGIN ERROR] Expected '{PASSWORD_COLUMN}' column not found on users row: {list(user.keys())}")
            return jsonify({
                "success": False,
                "message": "Database configuration error"
            }), 500

        # ── LOCKOUT CHECK (before password verification) ──────────────
        # Checked first and computed fresh against the current time, so a
        # lock that has simply timed out is treated as unlocked even if no
        # prior request has written that back to the row yet. A locked
        # account never has its password checked, so failed attempts can't
        # be probed/counted while it's locked, and clearing browser
        # storage / switching devices / calling the API directly can't
        # bypass this — it's evaluated purely from the DB row.
        is_locked, seconds_remaining, _ = compute_lock_status(user)
        if is_locked:
            safe_record_action(user.get('id'), "LOGIN_FAILED", {
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
                # 3rd (or more) failed attempt in this cycle -> lock the
                # account, escalating the tier from whatever it was left at
                # by the previous lockout.
                new_tier = min((user.get('lock_level') or 0) + 1, MAX_LOCK_TIER)
                duration = LOCK_TIER_SECONDS[new_tier]
                locked_until = datetime.now(timezone.utc) + timedelta(seconds=duration)
                update_fields.update({
                    'lock_level': new_tier,
                    'lock_time': locked_until.isoformat(),
                    'login_attempts': 0,  # fresh 3 attempts once this lock is served
                })
            else:
                # Not locking yet on this attempt. Make sure any stale
                # (already-expired) lock_time from a previous cycle is
                # cleared so lock status stays accurate.
                update_fields['lock_time'] = None

            try:
                supabase.table('users').update(update_fields).eq('id', user['id']).execute()
            except Exception as e:
                print(f"[LOGIN LOCKOUT UPDATE ERROR] {e}")

            if attempts >= MAX_LOGIN_ATTEMPTS:
                safe_record_action(user.get('id'), "LOGIN_FAILED", {
                    "username": username,
                    "reason": f"Account locked (tier {update_fields['lock_level']})",
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

        # Get roles/permissions BEFORE building the session, since is_admin
        # is derived from permissions (there's no is_admin column on users).
        role_names, permissions = get_roles_and_permissions(user['username'])
        is_admin_flag = resolve_is_admin(user['username'], permissions)

        if is_admin_flag:
            permissions.add('*')

        # Always include baseline dashboard access
        permissions.add('dashboard')

        # ============================================
        # SUCCESSFUL LOGIN - SET SESSION
        # ============================================
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = is_admin_flag
        # NOTE: with signed-cookie sessions everything below lives inside the
        # browser cookie, which browsers silently drop above ~4 KB. If no other
        # route reads session['user_data'], delete this line to keep the cookie small.
        user_data = {k: v for k, v in user.items() if k != PASSWORD_COLUMN}
        session['user_data'] = user_data
        session['logged_in_at'] = now_iso()

        # Per-session lifetime, enforced by enforce_session_expiry() in app.py.
        session['ttl'] = SESSION_TTL_REMEMBER_ME if remember_me else SESSION_TTL_DEFAULT
        session['last_seen'] = datetime.now(timezone.utc).timestamp()
        session.permanent = True

        print(f"[LOGIN] Session set for user: {username}")

        # Update last login time. A successful login is the only thing that
        # fully resets the attempt/lockout state, including the escalation
        # tier — start clean next time the account has a failure.
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
            "remember_me": remember_me
        })

        response_user = {
            "id": user['id'],
            "username": user['username'],
            "is_admin": is_admin_flag,
            "is_locked": False,
            "roles": role_names,
            "permissions": list(permissions)
        }

        print(f"[LOGIN] Login successful for {username}")

        return jsonify({
            "success": True,
            "message": "Login successful",
            "user": response_user
        }), 200

    except Exception as e:
        print(f"[LOGIN ERROR] {e}")
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
    """Endpoint for navigator.sendBeacon() - doesn't need JSON response"""
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
            except Exception:
                pass

            safe_record_action(user_id, "LOGOUT_BEACON", {"username": session.get('username')})

        # Deliberately NOT calling session.clear() here. sendBeacon fires on
        # page unload/hide (reload, tab switch, navigation) and can't tell those
        # apart from the tab really closing, so clearing the session here
        # silently logged people out. The frontend keeps its auth flag in
        # sessionStorage, which disappears when the tab closes, and an explicit
        # Logout still goes through /api/logout, which does clear the session.

    except Exception:
        pass

    return '', 204


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

            role_names, permissions = get_roles_and_permissions(user['username'])
            is_admin_flag = resolve_is_admin(user['username'], permissions)

            if is_admin_flag:
                permissions.add('*')

            # Ensure baseline access
            permissions.add('dashboard')

            # Computed fresh (not read straight off lock_level) so this
            # reflects an auto-expired lock immediately, rather than
            # whatever lock_level was last written to the row.
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
            # A transient Supabase/network error (timeout, dropped connection,
            # Render cold start) lands here. The login itself is still valid,
            # so do NOT clear the session — doing so turned any one-off backend
            # hiccup into a permanent logout. Report a temporary failure instead
            # and let the client retry on its next poll/focus.
            print(f"[SESSION ERROR] {e}")
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