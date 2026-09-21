import base64
import hashlib
import re
import secrets
import string

from cryptography.fernet import Fernet, InvalidToken
def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    PBKDF2-HMAC-SHA256 derives a 32-byte key from the master password.
    A unique salt is required per vault in a production design.
    """
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        600_000,
        dklen=32
    )
    return base64.urlsafe_b64encode(raw)

def encrypt_text(key: bytes, value: str | None) -> bytes | None:
    if value is None:
        return None
    return Fernet(key).encrypt(value.encode("utf-8"))

def decrypt_text(key: bytes, value: bytes | None) -> str:
    if value is None:
        return ""
    try:
        return Fernet(key).decrypt(value).decode("utf-8")
    except InvalidToken:
        raise ValueError("Unable to decrypt vault data. The unlock key may be invalid.")

def verify_password_strength(password: str):
    if len(password) < 12:
        return False, "Master password must be at least 12 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Master password needs at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Master password needs at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Master password needs at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Master password needs at least one special character."
    return True, "Strong password."

def password_score(password: str) -> int:
    score = 0
    if len(password) >= 12: score += 1
    if len(password) >= 16: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"\d", password): score += 1
    if re.search(r"[^A-Za-z0-9]", password): score += 1
    return min(score, 6)
