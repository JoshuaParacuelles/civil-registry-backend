# supabase_client.py
import os
import sys

try:
    from supabase import create_client, Client
except ImportError as e:
    print("=" * 60)
    print("[SUPABASE_CLIENT] FATAL: could not import 'supabase' package.")
    print(f"[SUPABASE_CLIENT] Underlying error: {e}")
    print(f"[SUPABASE_CLIENT] sys.path[0] = {sys.path[0]}")
    print("=" * 60)
    raise

url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")

if not url or not key:
    raise ValueError(
        "SUPABASE_URL and SUPABASE_KEY must be set in environment variables. "
        f"URL set: {bool(url)}, KEY set: {bool(key)}. "
        "Check that load_dotenv() ran BEFORE this module is imported."
    )

try:
    supabase: Client = create_client(url, key)
    print(f"[SUPABASE_CLIENT] Client created successfully. URL: {url}")
except Exception as e:
    print("=" * 60)
    print(f"[SUPABASE_CLIENT] FATAL: create_client() raised {type(e).__name__}: {e}")
    print("=" * 60)
    raise