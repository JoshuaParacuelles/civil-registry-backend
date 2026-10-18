import copy
import json
import os
import threading
import time
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_DATA_FILE = os.path.join(BASE_DIR, "local_data.json")

_lock = threading.RLock()

DEFAULT_SECTIONS = {
    "birth_active": [], "birth_archived": [],
    "marriage_active": [], "marriage_archived": [],
    "death_active": [], "death_archived": [],
    "documents": {},          # keyed by "<username>:<active|archived>"
    "synced_at": None,
}


def _fresh_defaults():
    # deepcopy so callers never mutate the shared template.
    return copy.deepcopy(DEFAULT_SECTIONS)


def _backup_corrupt_file():
    """Move an unreadable file aside so the next write cannot destroy it."""
    try:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        backup = f"{LOCAL_DATA_FILE}.corrupt-{stamp}"
        os.replace(LOCAL_DATA_FILE, backup)
        print(f"[LOCAL DATA] Corrupt file moved to {backup}", flush=True)
    except Exception as e:
        print(f"[LOCAL DATA] Could not back up corrupt file: {e}", flush=True)


def load():
    with _lock:
        data = _fresh_defaults()
        if not os.path.exists(LOCAL_DATA_FILE):
            return data
        try:
            with open(LOCAL_DATA_FILE, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            parsed = json.loads(raw) if raw else {}
            if not isinstance(parsed, dict):
                raise ValueError("top-level JSON is not an object")
        except Exception as e:
            print(f"[LOCAL DATA] Could not read {LOCAL_DATA_FILE}: {e}", flush=True)
            _backup_corrupt_file()
            return data

        for key, default in DEFAULT_SECTIONS.items():
            parsed.setdefault(key, copy.deepcopy(default))
        return parsed


def _write(data):
    data["synced_at"] = datetime.now(timezone.utc).isoformat()
    tmp = LOCAL_DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    last_err = None
    for attempt in range(5):
        try:
            os.replace(tmp, LOCAL_DATA_FILE)
            return
        except PermissionError as e:
            last_err = e
            time.sleep(0.1 * (attempt + 1))
    raise last_err


def save_section(section, rows):
    with _lock:
        data = load()
        data[section] = rows
        _write(data)


def save_key(section, key, value):
    with _lock:
        data = load()
        if not isinstance(data.get(section), dict):
            data[section] = {}
        data[section][key] = value
        _write(data)