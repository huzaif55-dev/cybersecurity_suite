import os
import re
import math
import secrets
import string
import hashlib
from datetime import datetime, timezone
from cryptography.fernet import Fernet

from config import Config
from models import db, PasswordEntry

def get_or_create_vault_key():
    key_path = Config.VAULT_KEY_PATH
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read().strip()
    key = Fernet.generate_key()
    with open(key_path, "wb") as f:
        f.write(key)
    return key

VAULT_KEY = get_or_create_vault_key()
fernet = Fernet(VAULT_KEY)

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "welcome", "admin", "letmein",
    "monkey", "password123", "secret", "trustno1", "login", "iloveyou"
}

def encrypt_password(plain_text: str) -> str:
    return fernet.encrypt(plain_text.encode("utf-8")).decode("utf-8")

def decrypt_password(cipher_text: str) -> str:
    try:
        return fernet.decrypt(cipher_text.encode("utf-8")).decode("utf-8")
    except Exception:
        return "[Decryption Error]"

def analyze_password(password: str) -> dict:
    if not password:
        return {
            "score": 0,
            "strength": "Empty",
            "strength_class": "secondary",
            "entropy_bits": 0,
            "crack_time": "Instant",
            "criteria": [],
            "tips": ["Enter a password to analyze its cryptographic strength."],
        }

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password))

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 33

    # Shannon Entropy calculation: H = L * log2(R)
    entropy_bits = round(length * math.log2(pool_size), 1) if pool_size > 0 else 0

    # Common password check
    is_common = password.lower() in COMMON_PASSWORDS or any(c in password.lower() for c in ["12345", "password", "qwerty"])

    criteria = [
        {"name": "Minimum 12 Characters", "passed": length >= 12, "desc": f"Current: {length} chars"},
        {"name": "Uppercase Letter (A-Z)", "passed": has_upper, "desc": "Contains capital letters"},
        {"name": "Lowercase Letter (a-z)", "passed": has_lower, "desc": "Contains small letters"},
        {"name": "Number (0-9)", "passed": has_digit, "desc": "Contains numeric digits"},
        {"name": "Special Character (!@#$...)", "passed": has_symbol, "desc": "Contains punctuation/symbols"},
        {"name": "Not in Common Password Dictionary", "passed": not is_common, "desc": "Avoids widely breached patterns"},
    ]

    passed_count = sum(1 for c in criteria if c["passed"])

    # Score out of 100
    base_score = 0
    if length >= 16: base_score += 35
    elif length >= 12: base_score += 25
    elif length >= 8: base_score += 15
    else: base_score += 5

    type_count = sum([has_lower, has_upper, has_digit, has_symbol])
    base_score += type_count * 15

    if length < 8:
        base_score = min(base_score, 30)
    if length < 6:
        base_score = min(base_score, 15)

    if is_common:
        base_score = min(base_score, 20)

    score = min(100, max(5, base_score))

    if score >= 85:
        strength = "Very Strong"
        strength_class = "success"
    elif score >= 65:
        strength = "Strong"
        strength_class = "info"
    elif score >= 45:
        strength = "Moderate"
        strength_class = "warning"
    elif score >= 25:
        strength = "Weak"
        strength_class = "danger"
    else:
        strength = "Very Weak"
        strength_class = "danger"

    # Crack time estimation at 10^10 guesses/sec (GPU brute-force rig)
    guesses = (pool_size ** length) if pool_size > 0 else 0
    seconds = guesses / 1e10

    if seconds < 0.1:
        crack_time = "Instant (< 1 second)"
    elif seconds < 60:
        crack_time = f"{round(seconds, 1)} seconds"
    elif seconds < 3600:
        crack_time = f"{round(seconds / 60, 1)} minutes"
    elif seconds < 86400:
        crack_time = f"{round(seconds / 3600, 1)} hours"
    elif seconds < 31536000:
        crack_time = f"{round(seconds / 86400, 1)} days"
    elif seconds < 31536000 * 100:
        crack_time = f"{round(seconds / 31536000, 1)} years"
    elif seconds < 31536000 * 1000000:
        crack_time = f"{round(seconds / (31536000 * 1000), 1)} thousand years"
    else:
        crack_time = "Trillions of Centuries"

    # Suggestions/Tips
    tips = []
    if length < 14:
        tips.append("Increase length to at least 14-16 characters for exponentially greater resistance against brute-force.")
    if not has_symbol:
        tips.append("Add special characters like $, %, #, or @ to drastically expand key space.")
    if not has_upper or not has_lower:
        tips.append("Mix both uppercase and lowercase characters.")
    if not has_digit:
        tips.append("Incorporate numbers throughout the string, not just at the end.")
    if is_common:
        tips.append("Warning: This string contains common breached sequences. Avoid predictable words.")
    if not tips:
        tips.append("Excellent password! Store it securely in this vault and never reuse it on other services.")

    return {
        "score": score,
        "strength": strength,
        "strength_class": strength_class,
        "entropy_bits": entropy_bits,
        "crack_time": crack_time,
        "criteria": criteria,
        "passed_count": passed_count,
        "tips": tips,
    }

def generate_strong_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True) -> str:
    chars = ""
    guaranteed = []

    if use_lower:
        chars += string.ascii_lowercase
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        chars += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        chars += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*-_=+"
        chars += symbols
        guaranteed.append(secrets.choice(symbols))

    if not chars:
        chars = string.ascii_letters + string.digits
        guaranteed.append(secrets.choice(string.ascii_letters))

    remaining_len = max(0, length - len(guaranteed))
    password_chars = guaranteed + [secrets.choice(chars) for _ in range(remaining_len)]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)

def suggest_passwords_from_input(base_input: str) -> list:
    """Generate 3 smart, high-entropy suggestions based on a user input / keyword."""
    clean = (base_input or "").strip()
    if not clean:
        clean = "CyberShield"

    suggestions = []

    # 1. Hardened Leetspeak + Salt + Symbols
    leet_map = {"a": "@", "e": "3", "i": "!", "o": "0", "s": "$", "t": "7"}
    hardened_base = "".join(leet_map.get(c.lower(), c.upper() if i % 2 == 0 else c.lower()) for i, c in enumerate(clean[:10]))
    salt1 = secrets.token_hex(2).upper()
    sym1 = secrets.choice(["#", "$", "&", "*", "!"])
    sym2 = secrets.choice(["^", "_", "=", "@", "?"])
    suggestion_1 = f"{sym1}{hardened_base}{sym2}{salt1}9"
    suggestions.append({
        "label": "Hardened Leet-Transform",
        "type": "Memorable & Salted",
        "password": suggestion_1,
        "analysis": analyze_password(suggestion_1),
    })

    # 2. Cryptographic Hash-Derived Expansion (High-Entropy Token)
    h = hashlib.sha256((clean + secrets.token_hex(8)).encode("utf-8")).hexdigest()
    # Interleave upper, lower, symbols, and digits
    parts = [
        clean[:4].capitalize(),
        h[:4].upper(),
        secrets.choice(["!", "@", "#", "$", "%"]),
        h[4:8],
        secrets.choice(["&", "*", "^", "_"]),
        h[8:12].upper(),
    ]
    suggestion_2 = "".join(parts)
    suggestions.append({
        "label": "Cryptographic Hash-Expanded",
        "type": "Maximum Entropy",
        "password": suggestion_2,
        "analysis": analyze_password(suggestion_2),
    })

    # 3. Diceware-style Passphrase with Input as Core
    word_pool = ["Vault", "Cipher", "Matrix", "Shield", "Falcon", "Anchor", "Aurora", "Beacon", "Zenith", "Quantum"]
    w1 = secrets.choice(word_pool)
    w2 = secrets.choice(word_pool)
    num = secrets.randbelow(900) + 100
    sym = secrets.choice(["-", "_", ".", "#"])
    suggestion_3 = f"{clean.capitalize()}{sym}{w1}{sym}{num}{sym}{w2}!"
    suggestions.append({
        "label": "Multi-Token Passphrase",
        "type": "High Recall & Length",
        "password": suggestion_3,
        "analysis": analyze_password(suggestion_3),
    })

    return suggestions

def save_password_entry(name: str, service_for: str, username: str, plain_password: str, category="General", notes="") -> PasswordEntry:
    encrypted = encrypt_password(plain_password)
    entry = PasswordEntry(
        name=name.strip(),
        service_for=service_for.strip(),
        username=username.strip() if username else "",
        encrypted_password=encrypted,
        category=category.strip() if category else "General",
        notes=notes.strip() if notes else "",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.session.add(entry)
    db.session.commit()
    return entry

def update_password_entry(entry_id: int, name: str, service_for: str, username: str, plain_password: str = None, category="General", notes="") -> PasswordEntry:
    entry = PasswordEntry.query.get_or_404(entry_id)
    entry.name = name.strip()
    entry.service_for = service_for.strip()
    entry.username = username.strip() if username else ""
    if plain_password and plain_password.strip():
        entry.encrypted_password = encrypt_password(plain_password.strip())
    entry.category = category.strip() if category else "General"
    entry.notes = notes.strip() if notes else ""
    entry.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return entry

def delete_password_entry(entry_id: int) -> bool:
    entry = PasswordEntry.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    return True

def get_all_passwords():
    entries = PasswordEntry.query.order_by(PasswordEntry.updated_at.desc()).all()
    results = []
    for e in entries:
        decrypted = decrypt_password(e.encrypted_password)
        results.append({
            "id": e.id,
            "name": e.name,
            "service_for": e.service_for,
            "username": e.username,
            "plain_password": decrypted,
            "category": e.category,
            "notes": e.notes,
            "created_at": e.created_at.strftime("%Y-%m-%d %H:%M"),
            "updated_at": e.updated_at.strftime("%Y-%m-%d %H:%M"),
            "strength": analyze_password(decrypted),
        })
    return results

def seed_sample_passwords_if_empty():
    if PasswordEntry.query.count() == 0:
        samples = [
            ("Work GitHub", "github.com", "dev@company.org", "G!tH#b_Sec98$Xq", "Development", "2FA backup keys in safe"),
            ("Personal Email", "mail.proton.me", "user@proton.me", "Pr0t0n*Sh1eld_2026!#", "Personal", "Primary recovery address"),
            ("AWS Production Console", "aws.amazon.com", "root-ops", "K7#mP9$vL2@qR8*zT1!", "Work", "Requires YubiKey hardware token"),
        ]
        for name, svc, user, pwd, cat, notes in samples:
            save_password_entry(name, svc, user, pwd, cat, notes)
