# supabase_client.py
import base64
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

try:
    from supabase import create_client, Client
except ImportError as e:
    print("=" * 60)
    print("[SUPABASE_CLIENT] FATAL: could not import 'supabase' package.")
    print(f"[SUPABASE_CLIENT] Underlying error: {e}")
    print(f"[SUPABASE_CLIENT] sys.path[0] = {sys.path[0]}")
    print("=" * 60)
    raise

# Load .env from this file's folder (not the current terminal folder),
# and override any stale variables already set in Windows.
ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(ENV_PATH, override=True)

url = os.environ.get("SUPABASE_URL", "").strip()
key = os.environ.get("SUPABASE_KEY", "").strip()


def describe_key(k: str) -> str:
    """Describe the key type without printing the key itself."""
    if k.startswith("sb_secret_"):
        return "SECRET (correct for backend)"
    if k.startswith("sb_publishable_"):
        return "PUBLISHABLE (wrong for backend, needs secret key)"
    if k.startswith("eyJ"):
        try:
            payload = k.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            role = json.loads(base64.urlsafe_b64decode(payload)).get("role")
            return f"LEGACY JWT, role={role} (backend needs service_role)"
        except Exception:
            return "LEGACY JWT (role unknown)"
    return "UNKNOWN"


print(f"[SUPABASE_CLIENT] .env path: {ENV_PATH} (exists: {ENV_PATH.exists()})")
print(f"[SUPABASE_CLIENT] SUPABASE_URL set: {bool(url)}")
print(f"[SUPABASE_CLIENT] SUPABASE_KEY set: {bool(key)}, length: {len(key)}")
if key:
    print(f"[SUPABASE_CLIENT] SUPABASE_KEY type: {describe_key(key)}")

if not url or not key:
    raise ValueError(
        "SUPABASE_URL and SUPABASE_KEY must be set in the backend .env file. "
        f"URL set: {bool(url)}, KEY set: {bool(key)}."
    )

try:
    supabase: Client = create_client(url, key)
    print(f"[SUPABASE_CLIENT] Client created successfully. URL: {url}")
except Exception as e:
    print("=" * 60)
    print(f"[SUPABASE_CLIENT] FATAL: create_client() raised {type(e).__name__}: {e}")
    print("=" * 60)
    raise