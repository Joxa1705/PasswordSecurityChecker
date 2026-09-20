"""
Password Security Checker V3.1
Security analysis core.

This module contains the security logic without any Tkinter GUI code.
Keeping the security logic separate makes the project easier to test,
maintain, and extend.
"""

import hashlib
import math
import secrets
import string

import requests


def generate_password(length=16):

    characters = (
        string.ascii_letters
        + string.digits
        + string.punctuation
    )

    while True:

        password = "".join(
            secrets.choice(characters)
            for _ in range(length)
        )

        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in string.punctuation for c in password)
        ):
            return password


# =========================================================
# COMMON PASSWORD CHECK
# =========================================================


def is_common_password(password):

    common_passwords = {
        "password", "passw0rd", "password1", "password123",
        "123456", "1234567", "12345678", "123456789",
        "1234567890", "123123", "111111", "000000",
        "qwerty", "qwerty123", "qwertyuiop",
        "admin", "admin123", "administrator",
        "letmein", "welcome", "welcome123",
        "iloveyou", "abc123", "football", "monkey",
        "dragon", "master", "login", "secret",
        "sunshine", "princess", "654321"
    }

    normalized = password.strip().lower()

    if normalized in common_passwords:
        return True

    if len(normalized) >= 4 and len(set(normalized)) == 1:
        return True

    for block_size in range(1, len(normalized) // 2 + 1):
        if len(normalized) % block_size == 0:
            block = normalized[:block_size]
            if block * (len(normalized) // block_size) == normalized:
                return True

    return False


def detect_weak_pattern(password, username=""):

    if not password:
        return False

    normalized = password.lower()
    findings = []

    # Keyboard patterns
    keyboard_patterns = (
        "qwerty", "qwertyuiop", "asdf", "asdfghjkl",
        "zxcv", "zxcvbnm", "qaz", "wsx", "edc",
        "qazwsx", "1qaz2wsx"
    )

    if any(pattern in normalized for pattern in keyboard_patterns):
        findings.append("Keyboard pattern")

    # Sequential numbers
    number_sequences = (
        "0123", "1234", "2345", "3456", "4567", "5678",
        "6789", "9876", "8765", "7654", "6543", "5432",
        "4321", "3210"
    )

    if any(sequence in normalized for sequence in number_sequences):
        findings.append("Sequential numbers")

    # Sequential letters
    alphabet = string.ascii_lowercase
    for i in range(len(alphabet) - 3):
        sequence = alphabet[i:i + 4]
        if sequence in normalized or sequence[::-1] in normalized:
            findings.append("Sequential letters")
            break

    # Repeated characters
    for i in range(len(normalized) - 2):
        if normalized[i] == normalized[i + 1] == normalized[i + 2]:
            findings.append("Repeated characters")
            break

    # Repeated blocks, e.g. abcabc or 1212
    for block_size in range(2, len(normalized) // 2 + 1):
        if len(normalized) % block_size == 0:
            block = normalized[:block_size]
            if block * (len(normalized) // block_size) == normalized:
                findings.append("Repeated sequence")
                break

    # Year/date-like patterns
    for year in range(1900, 2101):
        if str(year) in normalized:
            findings.append("Year/date-like pattern")
            break

    # Common password variations such as P@ssw0rd
    substitutions = str.maketrans({
        "0": "o", "1": "i", "3": "e", "4": "a",
        "5": "s", "7": "t", "@": "a", "$": "s"
    })
    normalized_variant = normalized.translate(substitutions)

    common_roots = (
        "password", "admin", "welcome", "letmein", "qwerty",
        "monkey", "dragon", "football", "iloveyou", "secret"
    )

    if any(root in normalized_variant for root in common_roots):
        findings.append("Common password variation")

    # Username similarity
    username_clean = username.strip().lower()
    if username_clean and len(username_clean) >= 3:
        if username_clean == normalized:
            findings.append("Password equals username")
        elif username_clean in normalized:
            findings.append("Contains username")

    return list(dict.fromkeys(findings))


# =========================================================
# ENTROPY
# =========================================================


def calculate_entropy(password):

    pool = 0

    if any(c.islower() for c in password):
        pool += 26

    if any(c.isupper() for c in password):
        pool += 26

    if any(c.isdigit() for c in password):
        pool += 10

    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)

    if pool == 0:
        return 0

    return round(
        len(password) * math.log2(pool),
        2
    )


# =========================================================
# HIBP BREACH CHECK
# =========================================================


def check_password_breach(password):

    try:

        sha1_hash = hashlib.sha1(
            password.encode("utf-8")
        ).hexdigest().upper()

        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = (
            "https://api.pwnedpasswords.com/range/"
            + prefix
        )

        headers = {
            "Add-Padding": "true",
            "User-Agent": "Password-Security-Checker"
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code != 200:
            return None, 0

        for line in response.text.splitlines():

            parts = line.split(":")

            if len(parts) != 2:
                continue

            returned_suffix = parts[0]
            count = int(parts[1])

            if returned_suffix == suffix:
                return True, count

        return False, 0

    except requests.Timeout:
        return None, 0

    except requests.RequestException:
        return None, 0

    except (ValueError, TypeError, UnicodeError):
        return None, 0

    except Exception:
        return None, 0


# =========================================================
# RISK LEVEL
# =========================================================


def get_risk_level(
    score,
    common,
    breach_found,
    breach_count,
    weak_pattern=False
):

    if breach_found is True:
        return "HIGH"

    if score <= 2:
        return "HIGH"

    if common:
        return "HIGH"

    if weak_pattern and score < 5:
        return "MEDIUM"

    if score in (3, 4):
        return "MEDIUM"

    return "LOW"


def calculate_security_health(result):

    health = int((result["score"] / 5) * 100)

    if result.get("weak_pattern"):
        health -= 10

    if result["common"]:
        health -= 20

    if result["breach_found"] is True:
        health -= 35
    elif result["breach_found"] is None:
        health -= 5

    return max(0, min(100, health))


# =========================================================
# PASSWORD ANALYSIS
# =========================================================


def analyze_password(password, username=""):

    score = 0

    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1

    if score == 5:
        strength = "STRONG"
    elif score >= 3:
        strength = "MEDIUM"
    else:
        strength = "WEAK"

    entropy = calculate_entropy(password)
    common = is_common_password(password)
    pattern_details = detect_weak_pattern(password, username)
    weak_pattern = bool(pattern_details)

    breach_found, breach_count = check_password_breach(password)

    risk = get_risk_level(
        score,
        common,
        breach_found,
        breach_count,
        weak_pattern
    )

    result = {
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "common": common,
        "weak_pattern": weak_pattern,
        "pattern_details": pattern_details,
        "breach_found": breach_found,
        "breach_count": breach_count,
        "risk": risk
    }

    result["health"] = calculate_security_health(result)
    return result


# =========================================================
# PERSISTENT ANALYTICS
# =========================================================
