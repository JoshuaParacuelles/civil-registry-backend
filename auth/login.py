import os
import sys
import json
from datetime import datetime, timezone
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


def safe_record_action(user_id, action, details=None):
    """Safely record an audit action - handles errors gracefully"""
    try:
        from logs.Audits import record_action
        return record_action(user_id, action, details)
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

        stored_hash = user.get(PASSWORD_COLUMN)
        print(f"[LOGIN] Using password column: '{PASSWORD_COLUMN}'")

        # Verify password using salted hash comparison
        if not stored_hash or not verify_password(password, stored_hash):
            print(f"[LOGIN] Password mismatch for user '{username}'")
            safe_record_action(user.get('id'), "LOGIN_FAILED", {"reason": "Invalid password"})
            return jsonify({
                "success": False,
                "message": "Invalid username or password"
            }), 401

        # Check if user is locked. The schema stores this as an integer
        # 'lock_level' (0 = unlocked), not a boolean 'is_locked' column.
        if user.get('lock_level', 0) > 0:
            safe_record_action(user['id'], "LOGIN_FAILED", {"reason": "Account locked"})
            return jsonify({
                "success": False,
                "message": "Account is locked. Please contact an administrator."
            }), 403

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

        # Update last login time
        try:
            update_data = {
                'last_login': now_iso(),
                'is_online': True,
                'login_attempts': 0
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
            "is_locked": user.get('lock_level', 0) > 0,
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

            safe_record_action(user_id, "LOGOUT", {})

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

            safe_record_action(user_id, "LOGOUT_BEACON", {})

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

            return jsonify({
                "authenticated": True,
                "is_admin": is_admin_flag,
                "role": role_names[0] if role_names else None,
                "permissions": list(permissions),
                "user": {
                    "id": user['id'],
                    "username": user['username'],
                    "is_admin": is_admin_flag,
                    "is_locked": user.get('lock_level', 0) > 0,
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