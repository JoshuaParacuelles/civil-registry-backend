"""
Run this once to fix the admin account's password hash.
"""

from dotenv import load_dotenv
load_dotenv()

from werkzeug.security import generate_password_hash
from supabase_client import supabase

# ---- CONFIG: change these if needed ----
USERNAME = "admin"
NEW_PASSWORD = "admin123"
# -----------------------------------------

def main():
    print(f"[FIX] Looking up user '{USERNAME}'...")

    response = supabase.table('users').select('*').eq('username', USERNAME).execute()
    users = response.data

    if not users:
        print(f"[FIX] ERROR: No user found with username '{USERNAME}'.")
        print("[FIX] Double-check the username exists in your 'users' table.")
        return

    user = users[0]
    print(f"[FIX] Found user: id={user.get('id')}, columns={list(user.keys())}")

    # Find the password column, same logic as login.py
    password_column = None
    for col in ['password_hash', 'password', 'pass_hash', 'hashed_password', 'pwd']:
        if col in user:
            password_column = col
            break

    if not password_column:
        print("[FIX] ERROR: Could not find a password column in the users table.")
        return

    print(f"[FIX] Using password column: '{password_column}'")
    print(f"[FIX] Old value: {user.get(password_column)}")

    new_hash = generate_password_hash(NEW_PASSWORD)

    update_response = supabase.table('users')\
        .update({password_column: new_hash})\
        .eq('id', user['id'])\
        .execute()

    if update_response.data:
        print(f"[FIX] SUCCESS: Updated '{password_column}' for user '{USERNAME}'.")
        print(f"[FIX] New hash: {new_hash}")
        print(f"[FIX] You can now log in with username='{USERNAME}' password='{NEW_PASSWORD}'")
    else:
        print("[FIX] WARNING: Update call returned no data. Check Supabase RLS policies")
        print("[FIX] (row-level security may be blocking the update from this client/key).")


if __name__ == "__main__":
    main()