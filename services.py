import secrets
import string
from datetime import datetime

from crypto_utils import derive_key, encrypt_text, decrypt_text, password_score
from db import get_db

_KEY_CACHE = {}

def unlock_user_key(user_id, master_password):
    
    salt = f"vaultlock-user-{user_id}".encode()
    _KEY_CACHE[user_id] = derive_key(master_password, salt)

def get_user_key(user_id):
    key = _KEY_CACHE.get(user_id)
    if not key:
        raise PermissionError("Vault is locked. Please sign in again.")
    return key

def record_audit(user_id, action, details=""):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (user_id, action, details, created_at) VALUES (?, ?, ?, ?)",
        (user_id, action, details, datetime.utcnow().isoformat())
    )
    db.commit()

def create_entry(user_id, title, username, password, website, category, notes):
    key = get_user_key(user_id)
    now = datetime.utcnow().isoformat()
    db = get_db()

    db.execute("""
        INSERT INTO entries
        (user_id, title_enc, username_enc, password_enc, website_enc,
         category_enc, notes_enc, created_at, updated_at, last_changed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        encrypt_text(key, title),
        encrypt_text(key, username),
        encrypt_text(key, password),
        encrypt_text(key, website),
        encrypt_text(key, category),
        encrypt_text(key, notes),
        now, now, now
    ))
    db.commit()
    record_audit(user_id, "CREATE", f"Created credential: {title}")

def decrypt_row(row, key):
    return {
        "id": row["id"],
        "title": decrypt_text(key, row["title_enc"]),
        "username": decrypt_text(key, row["username_enc"]),
        "password": decrypt_text(key, row["password_enc"]),
        "website": decrypt_text(key, row["website_enc"]),
        "category": decrypt_text(key, row["category_enc"]),
        "notes": decrypt_text(key, row["notes_enc"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_changed_at": row["last_changed_at"],
    }

def list_entries(user_id):
    key = get_user_key(user_id)
    rows = get_db().execute(
        "SELECT * FROM entries WHERE user_id = ? ORDER BY updated_at DESC", (user_id,)
    ).fetchall()
    return [decrypt_row(row, key) for row in rows]

def get_entry(user_id, entry_id):
    key = get_user_key(user_id)
    row = get_db().execute(
        "SELECT * FROM entries WHERE id = ? AND user_id = ?", (entry_id, user_id)
    ).fetchone()
    return decrypt_row(row, key) if row else None

def update_entry(user_id, entry_id, title, username, password, website, category, notes):
    key = get_user_key(user_id)
    now = datetime.utcnow().isoformat()
    db = get_db()

    existing = db.execute(
        "SELECT id FROM entries WHERE id = ? AND user_id = ?", (entry_id, user_id)
    ).fetchone()
    if not existing:
        return False

    db.execute("""
        UPDATE entries SET
        title_enc = ?, username_enc = ?, password_enc = ?, website_enc = ?,
        category_enc = ?, notes_enc = ?, updated_at = ?, last_changed_at = ?
        WHERE id = ? AND user_id = ?
    """, (
        encrypt_text(key, title),
        encrypt_text(key, username),
        encrypt_text(key, password),
        encrypt_text(key, website),
        encrypt_text(key, category),
        encrypt_text(key, notes),
        now, now, entry_id, user_id
    ))
    db.commit()
    record_audit(user_id, "UPDATE", f"Updated credential: {title}")
    return True

def delete_entry(user_id, entry_id):
    db = get_db()
    row = db.execute(
        "SELECT id FROM entries WHERE id = ? AND user_id = ?", (entry_id, user_id)
    ).fetchone()
    if not row:
        return False

    db.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (entry_id, user_id))
    db.commit()
    record_audit(user_id, "DELETE", f"Deleted credential ID {entry_id}")
    return True

def generate_secure_password(length=20):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value)
            and any(c in "!@#$%^&*()-_=+" for c in value)
        ):
            return value

def calculate_health(entries):
    total = len(entries)
    weak = 0
    reused = 0
    old = 0

    password_map = {}
    now = datetime.utcnow()

    for entry in entries:
        pwd = entry["password"]
        if password_score(pwd) <= 3:
            weak += 1
        password_map.setdefault(pwd, 0)
        password_map[pwd] += 1

        try:
            changed = datetime.fromisoformat(entry["last_changed_at"])
            if (now - changed).days >= 180:
                old += 1
        except ValueError:
            pass

    reused = sum(count - 1 for count in password_map.values() if count > 1)

    issues = weak + reused + old
    score = 100 if total == 0 else max(0, round(100 - (issues / total) * 35))

    return {
        "score": score,
        "total": total,
        "weak": weak,
        "reused": reused,
        "old": old
    }

def get_audit_log(user_id):
    rows = get_db().execute(
        "SELECT action, details, created_at FROM audit_log "
        "WHERE user_id = ? ORDER BY id DESC LIMIT 50", (user_id,)
    ).fetchall()
    return [dict(row) for row in rows]
