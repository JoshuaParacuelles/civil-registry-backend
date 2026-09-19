# app.py
from dotenv import load_dotenv
load_dotenv()

import os
import sys
from datetime import timedelta
from flask import Flask, session, jsonify
from flask_cors import CORS
from flask_session import Session

try:
    from supabase_client import supabase
except Exception as e:
    print("=" * 60)
    print(f"[APP] FATAL while importing supabase_client: {type(e).__name__}: {e}")
    print(f"[APP] Python executable: {sys.executable}")
    print(f"[APP] Working directory: {os.getcwd()}")
    print(f"[APP] sys.path[0]: {sys.path[0]}")
    print("=" * 60)
    raise

from auth.login import login_bp
from auth.changepass import changepass_bp
from routes.marriage_death_birth import birth_bp, death_bp, marriage_bp
from routes.analytics import analytics_bp
from routes.notification import notifications_bp
from routes.external_scims import external_bp
from routes.document import document_bp
from auth.birth_password import birth_archive_bp, init_birth_archive_db
from auth.Death_password import death_archive_bp, init_death_archive_db
from auth.marriage_password import marriage_auth_bp, init_marriage_archive_db
from logs.Audits import audit_bp, init_audit_db
from auth.Rolemanagement import (
    role_bp,
    init_roles_db,
    is_admin,
    get_user_permissions,
)

app = Flask(__name__)

IS_PRODUCTION = os.environ.get('FLASK_ENV', '').lower() == 'production'

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production-12345')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

app.config['SESSION_COOKIE_SECURE'] = IS_PRODUCTION
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None' if IS_PRODUCTION else 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = os.environ.get('SESSION_COOKIE_DOMAIN') or None
app.config['SESSION_USE_SIGNER'] = True

Session(app)

ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:5000',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:5174',
]

extra_origins = os.environ.get('CORS_EXTRA_ORIGINS', '')
if extra_origins:
    ALLOWED_ORIGINS.extend([o.strip() for o in extra_origins.split(',') if o.strip()])

CORS(app,
     supports_credentials=True,
     origins=ALLOWED_ORIGINS,
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'Cache-Control', 'Pragma'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
     expose_headers=['Content-Type', 'Set-Cookie'],
     max_age=86400
)

app.config["DB"] = None
app.config["DB_CONFIG"] = None
app.config["SUPABASE"] = supabase

app.register_blueprint(login_bp)
app.register_blueprint(changepass_bp)
app.register_blueprint(birth_bp)
app.register_blueprint(death_bp)
app.register_blueprint(marriage_bp)
app.register_blueprint(birth_archive_bp)
app.register_blueprint(death_archive_bp)
app.register_blueprint(marriage_auth_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(analytics_bp)
app.register_blueprint(role_bp)
app.register_blueprint(notifications_bp)
app.register_blueprint(external_bp)
app.register_blueprint(document_bp)

with app.app_context():
    try:
        init_audit_db()
        init_birth_archive_db()
        init_death_archive_db()
        init_marriage_archive_db()
        init_roles_db()
        print("[INIT] Database tables initialized successfully")
    except Exception as e:
        print(f"[INIT ERROR] Failed to initialize database tables: {e}")


@app.route('/api/health', methods=['GET'])
def health_check():
    return {"status": "healthy"}, 200


@app.route('/api/session', methods=['GET'])
def api_session():
    """Lightweight session probe used by PermissionContext on load/focus.
    Intentionally returns 200 even when logged out (authenticated: false)
    instead of 401, since 'not logged in yet' is a normal, expected state
    for this endpoint rather than an error condition."""
    username = session.get('username')
    if not username:
        return jsonify({"authenticated": False}), 200

    return jsonify({
        "authenticated": True,
        "username": username,
        "is_admin": is_admin(username),
        "permissions": get_user_permissions(username),
    }), 200


@app.route('/api/current-user', methods=['GET'])
def api_current_user():
    """Used by ChangePassword.jsx to know which account it's changing the
    password for. This one legitimately should 401 if there's no session,
    since ChangePassword requires being logged in to do anything useful."""
    username = session.get('username')
    if not username:
        return jsonify({"error": "Not logged in"}), 401

    return jsonify({
        "username": username,
        "is_admin": is_admin(username),
        "permissions": get_user_permissions(username),
    }), 200


@app.route('/api/test-session', methods=['GET', 'POST'])
def test_session():
    from flask import request
    if request.method == 'POST':
        data = request.get_json() or {}
        session['test_data'] = data.get('test', 'Session working!')
        return jsonify({"message": "Session data set", "session_id": session.get('_id', 'N/A')}), 200
    else:
        return jsonify({
            "session_data": dict(session),
            "session_id": session.get('_id', 'N/A'),
            "has_session": bool(session)
        }), 200


@app.errorhandler(404)
def not_found(error):
    return {"error": "Resource not found"}, 404


@app.errorhandler(500)
def internal_error(error):
    return {"error": "Internal server error"}, 500


if __name__ == "__main__":
    print("=" * 50)
    print("STARTING FLASK APPLICATION")
    print("=" * 50)
    print(f"SECRET_KEY: {'Set' if app.config['SECRET_KEY'] else 'Not Set'}")
    print(f"SESSION_TYPE: {app.config['SESSION_TYPE']}")
    print(f"SESSION_COOKIE_SAMESITE: {app.config['SESSION_COOKIE_SAMESITE']}")
    print(f"SESSION_COOKIE_SECURE: {app.config['SESSION_COOKIE_SECURE']}")
    print(f"IS_PRODUCTION (FLASK_ENV): {IS_PRODUCTION}")
    print(f"CORS Origins: {ALLOWED_ORIGINS}")
    print(f"Debug Mode: {app.debug}")
    print("=" * 50)

    app.run(debug=True, threaded=True, host='0.0.0.0', port=5000)