# auth/offline_record.py
# Builds the encrypted offline unlock record. The browser decrypts it with the
# user's password (PBKDF2-SHA256 -> AES-GCM), so the server never keeps a key.
import base64
import json
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Must match ITER in src/offline/adapters/offlineLogin.js (and crypto.js).
OFFLINE_ITER = 210000
CHECK = "ok"


def build_offline_record(password: str, profile: dict) -> dict:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=OFFLINE_ITER,
    )
    key = kdf.derive(password.encode("utf-8"))

    iv = os.urandom(12)
    payload = json.dumps({"check": CHECK, "profile": profile}).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(iv, payload, None)

    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "iter": OFFLINE_ITER,
        "blob": {
            "iv": base64.b64encode(iv).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        },
        "savedAt": int(time.time() * 1000),
    }