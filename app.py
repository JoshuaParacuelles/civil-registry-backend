# app.py
from dotenv import load_dotenv
load_dotenv()

import os
import sys
from datetime import timedelta, datetime, timezone
from flask import Flask, session, jsonify, request, g
from flask_cors import CORS
from flask_compress import Compress
from routes.sync import register_offline_replay
import time
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

from security import register_origin_check
from auth.login import login_bp
from auth.changepass import changepass_bp
from routes.marriage_death_birth import birth_bp, death_bp, marriage_bp
from routes.analytics import analytics_bp
from routes.notification import notifications_bp
from routes.external_scims import external_bp
from routes.document import document_bp
from routes.citizen_requests import citizen_requests_bp
from auth.birth_password import birth_archive_bp, init_birth_archive_db
from auth.Death_password import death_archive_bp, init_death_archive_db
from auth.marriage_password import marriage_auth_bp, init_marriage_archive_db
from logs.Audits import audit_bp, init_audit_db, record_action, mark_denial_logged
from auth.Rolemanagement import role_bp, init_roles_db
from routes.profile_routes import profile_bp
app = Flask(__name__)

# Compress JSON/HTML/CSS/JS responses. PDFs are not in the default mimetype
# list, so file downloads from document.py are left untouched.
app.config['COMPRESS_ALGORITHM'] = 'gzip'
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 1024
Compress(app)

# Render sets RENDER=true automatically, so production is detected even if
# FLASK_ENV was forgotten.
IS_PRODUCTION = (
    os.environ.get('FLASK_ENV', '').lower() == 'production'
    or bool(os.environ.get('RENDER'))
)

# Set by electron/main.cjs when the desktop app starts this backend. The
# Electron app runs on app://civil-registry (cross-site to http://127.0.0.1),
# so the session cookie must be SameSite=None; Secure, the same as production.
ELECTRON_MODE = os.environ.get('ELECTRON_MODE') == '1'
CROSS_SITE_COOKIES = IS_PRODUCTION or ELECTRON_MODE

# SECURITY: sessions are signed cookies, so SECRET_KEY is what stops anyone
# forging a login cookie. There must be NO guessable fallback in production.
_secret = os.environ.get('SECRET_KEY')
if not _secret:
    if IS_PRODUCTION:
        raise RuntimeError("SECRET_KEY must be set in production.")
    _secret = 'dev-only-secret-not-for-production'
app.config['SECRET_KEY'] = _secret

# Sessions use Flask's built-in signed-cookie session (no server-side files),
# so a Render restart or cold start no longer logs anyone out.
#
# Upper bound only. Flask applies this GLOBAL value when validating every
# session cookie's age, so it must never be changed per-login. The real
# per-session lifetime (24h, or 7 days for "remember me") is stored inside
# each session and enforced by enforce_session_expiry() below.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

app.config['SESSION_COOKIE_SECURE'] = CROSS_SITE_COOKIES
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None' if CROSS_SITE_COOKIES else 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = os.environ.get('SESSION_COOKIE_DOMAIN') or None


@app.before_request
def enforce_session_expiry():
    """Per-session lifetime, kept inside the session itself.

    login.py stamps each session with `ttl` (seconds: 24h normally, 7 days for
    "remember me") and this hook keeps `last_seen` current, expiring the
    session after `ttl` seconds of inactivity. Sessions created before this
    change have no ttl/last_seen; they simply pick up the defaults below, so
    nobody is logged out by the deploy itself."""
    if 'username' not in session:
        return
    now = datetime.now(timezone.utc).timestamp()
    ttl = session.get('ttl', 24 * 3600)
    if now - session.get('last_seen', now) > ttl:
        # Written before session.clear(), while the identity is still available.
        record_action(
            "SESSION_EXPIRED",
            "Session expired due to inactivity",
            status="DENIED",
            resource_type="session",
        )
        session.clear()
        return
    session['last_seen'] = now
    session.permanent = True


ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:5000',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:5174',
    'app://civil-registry',   # Electron desktop app
]

extra_origins = os.environ.get('CORS_EXTRA_ORIGINS', '')
if extra_origins:
    ALLOWED_ORIGINS.extend([o.strip() for o in extra_origins.split(',') if o.strip()])

CORS(app,
     supports_credentials=True,
     origins=ALLOWED_ORIGINS,
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'Cache-Control', 'Pragma',
                    'X-Offline-Op-Id', 'X-Offline-Created-At'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
     expose_headers=['Content-Type', 'Set-Cookie', 'X-Data-Source', 'X-Document-Api'],
     max_age=86400
)

# SECURITY (CSRF): cookies are SameSite=None in production, so reject
# state-changing requests from browser origins that aren't in ALLOWED_ORIGINS.
register_origin_check(app, ALLOWED_ORIGINS)

# Offline replay: idempotency (X-Offline-Op-Id) + real timestamps (X-Offline-Created-At).
register_offline_replay(app)

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
app.register_blueprint(citizen_requests_bp)
app.register_blueprint(profile_bp)

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


@app.route('/', methods=['GET'])
def index():
    """Friendly root route so opening https://civil-registry.onrender.com/
    in a browser shows a status message instead of the 404 JSON error.
    This backend is API-only; the actual app lives on the Vercel frontend."""
    return {"status": "ok", "service": "civil-registry API"}, 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """Heartbeat used by the frontend's connectivityService.js.

    Returns 200 whenever Flask answers, so the browser knows the server is
    reachable. The 'db' field reports whether Supabase answered. A database
    hiccup no longer makes the device look offline.
    No login required and no data is returned."""
    db_ok = False
    for attempt in range(2):
        try:
            supabase.table("users").select("id").limit(1).execute()
            db_ok = True
            break
        except Exception as e:
            print(f"[HEALTH] Supabase check attempt {attempt + 1} failed: {e}", flush=True)
            time.sleep(0.3)
    return jsonify({
        "ok": True,
        "server": True,
        "db": db_ok,
        "status": "healthy" if db_ok else "degraded",
    }), 200


@app.after_request
def log_unauthorized(resp):
    """Generic audit entry for 401/403 responses that no route guard has
    already recorded. Guards that log their own denial call
    mark_denial_logged() first, so each refused request yields one row.

    A 401 with no logged-in user is not audited (it is usually an anonymous
    probe and would flood the table). A 401 from a session that was logged in
    is recorded."""
    if resp.status_code == 403 and not g.get("_denial_logged"):
        record_action(
            "ACCESS_DENIED",
            "Request denied by authentication or authorization check",
            status="DENIED",
            resource_type="route",
            resource_id=request.path,
            meta={"route": request.path, "method": request.method},
        )
    elif resp.status_code == 401 and not g.get("_denial_logged") and session.get("username"):
        record_action(
            "ACCESS_DENIED",
            "Session rejected by authentication check",
            status="DENIED",
            resource_type="route",
            resource_id=request.path,
            meta={"route": request.path, "method": request.method},
        )

    if resp.status_code == 401:
        cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
        print(
            f"[401] {request.method} {request.path} "
            f"cookie_received={request.cookies.get(cookie_name) is not None} "
            f"has_username={'username' in session} pid={os.getpid()}",
            flush=True,
        )
    return resp


@app.after_request
def api_cache_defaults(resp):
    """Safe default: API responses are never stored by browsers or the Vercel
    edge unless a route sets its own Cache-Control explicitly."""
    if request.path.startswith('/api/') and 'Cache-Control' not in resp.headers:
        resp.headers['Cache-Control'] = 'private, no-store'
    return resp


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
    print("SESSION_TYPE: signed cookie (Flask default)")
    print(f"ELECTRON_MODE: {ELECTRON_MODE}")
    print(f"SESSION_COOKIE_SAMESITE: {app.config['SESSION_COOKIE_SAMESITE']}")
    print(f"SESSION_COOKIE_SECURE: {app.config['SESSION_COOKIE_SECURE']}")
    print(f"IS_PRODUCTION: {IS_PRODUCTION}")
    print(f"CORS Origins: {ALLOWED_ORIGINS}")
    print("=" * 50)

    # Debug mode (Werkzeug debugger = remote code execution) is OFF unless you
    # explicitly set FLASK_DEBUG=1 on your own machine.
    app.run(
        debug=os.environ.get('FLASK_DEBUG') == '1',
        threaded=True,
        host='0.0.0.0',
        port=int(os.environ.get('API_PORT', 5000)),
    )