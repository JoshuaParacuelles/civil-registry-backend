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

SESSION_TTL_DEFAULT = 24 * 3600
SESSION_TTL_REMEMBER_ME = 7 * 24 * 3600

PASSWORD_COLUMN = "password"


def hash_password(password):
    return generate_password_hash(password)


def verify_password(password, stored_hash):
    try:
        return check_password_hash(stored_hash, password)
    except Exception as e:
        print(f"[LOGIN] Password verification error: {e}")
        return False


def now_iso():
    return datetime.now(timezone.utc).isoformat()


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
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def safe_record_action(user_id, action, details=None):
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
                "message": "Invalid credentials."
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
                "message": "Invalid credentials."
            }), 400

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
                "message": "Wrong username or password."
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

        if not stored_hash or not verify_password(password, stored_hash):
            print(f"[LOGIN] Password mismatch for user '{username}'")
            safe_record_action(user.get('id'), "LOGIN_FAILED", {
                "username": username,
                "reason": "Invalid password",
            })
            return jsonify({
                "success": False,
                "message": "Wrong username or password."
            }), 401

        if user.get('lock_level', 0) > 0:
            safe_record_action(user['id'], "LOGIN_FAILED", {
                "username": username,
                "reason": "Account locked",
            })
            return jsonify({
                "success": False,
                "message": "Account is locked. Please contact an administrator."
            }), 403

        role_names, permissions = get_roles_and_permissions(user['username'])
        is_admin_flag = resolve_is_admin(user['username'], permissions)

        if is_admin_flag:
            permissions.add('*')

        permissions.add('dashboard')

        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = is_admin_flag
        user_data = {k: v for k, v in user.items() if k != PASSWORD_COLUMN}
        session['user_data'] = user_data
        session['logged_in_at'] = now_iso()

        session['ttl'] = SESSION_TTL_REMEMBER_ME if remember_me else SESSION_TTL_DEFAULT
        session['last_seen'] = datetime.now(timezone.utc).timestamp()
        session.permanent = True

        print(f"[LOGIN] Session set for user: {username}")

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

    except Exception:
        pass

    return '', 204


@login_bp.route('/api/session', methods=['GET'])
@login_bp.route('/api/my-permissions', methods=['GET'])
def get_session():
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