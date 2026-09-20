import secrets
import string
import getpass
import math
import hashlib
import requests


# ==============================
# PASSWORD HISTORY
# ==============================
history = []


# ==============================
# GENERATE STRONG PASSWORD
# ==============================
def generate_password(length, use_special):

    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    numbers = string.digits
    special = "!@#$%^&*"

    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(numbers)
    ]

    if use_special:
        password.append(secrets.choice(special))

    characters = uppercase + lowercase + numbers

    if use_special:
        characters += special

    for _ in range(length - len(password)):
        password.append(secrets.choice(characters))

    secrets.SystemRandom().shuffle(password)

    return "".join(password)


# ==============================
# COMMON PASSWORD CHECK
# ==============================
def is_common_password(password):

    common_passwords = [
        "123456",
        "password",
        "12345678",
        "qwerty",
        "admin",
        "111111",
        "123456789",
        "password123",
        "123123",
        "abc123",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "iloveyou",
        "football",
        "000000",
        "654321",
        "passw0rd",
        "qwerty123"
    ]

    return password.lower() in common_passwords


# ==============================
# ENTROPY CALCULATOR
# ==============================
def calculate_entropy(password):

    character_pool = 0

    if any(char.islower() for char in password):
        character_pool += 26

    if any(char.isupper() for char in password):
        character_pool += 26

    if any(char.isdigit() for char in password):
        character_pool += 10

    if any(not char.isalnum() for char in password):
        character_pool += 32

    if character_pool == 0:
        return 0

    entropy = len(password) * math.log2(character_pool)

    return round(entropy, 2)


# ==============================
# STRENGTH METER
# ==============================
def show_strength_meter(score):

    filled = score * 2
    empty = 10 - filled

    meter = "█" * filled + "░" * empty
    percentage = score * 20

    print("Strength Meter:")
    print(f"[{meter}] {percentage}%")


# ==============================
# SHOW ENTROPY
# ==============================
def show_entropy(password):

    entropy = calculate_entropy(password)

    print("Password Entropy:")
    print("----------------------------")
    print("Estimated entropy:", entropy, "bits")

    if entropy < 28:
        print("Entropy level: Very Low")

    elif entropy < 36:
        print("Entropy level: Low")

    elif entropy < 60:
        print("Entropy level: Moderate")

    elif entropy < 80:
        print("Entropy level: High")

    else:
        print("Entropy level: Very High")


# ==============================
# BREACH CHECK
# ==============================
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

    except requests.RequestException:

        return None, 0


# ==============================
# GET RISK LEVEL
# ==============================
def get_risk_level(score, common, breach_found, breach_count):

    # Breached passwords are considered high risk
    if breach_found is True:
        return "HIGH"

    # Very weak passwords
    if score <= 2:
        return "HIGH"

    # Common passwords
    if common:
        return "HIGH"

    # Medium passwords
    if score == 3:
        return "MEDIUM"

    if score == 4:
        return "MEDIUM"

    return "LOW"


# ==============================
# SHOW BREACH CHECK
# ==============================
def show_breach_check(password):

    print("\nBreach Check:")
    print("----------------------------")

    found, count = check_password_breach(password)

    if found is True:

        print("⚠️ Password found in known breaches!")
        print("Times seen:", count)
        print("Recommendation: Choose a different password.")

    elif found is False:

        print("✓ Password not found in known breaches.")

    else:

        print("⚠️ Breach check could not be completed.")
        print("Please check your internet connection.")

    return found, count


# ==============================
# DETAILED SECURITY REPORT
# ==============================
def show_detailed_report(
    password,
    score,
    strength,
    common,
    breach_found,
    breach_count
):

    entropy = calculate_entropy(password)

    risk_level = get_risk_level(
        score,
        common,
        breach_found,
        breach_count
    )

    print("\n================================")
    print("     DETAILED SECURITY REPORT")
    print("================================")

    print("\nPassword Strength:", strength)
    print("Security Score:", score, "/ 5")
    print("Entropy:", entropy, "bits")

    print("\nBreach Status:")

    if breach_found is True:

        print("⚠️ FOUND")
        print("Times Seen:", breach_count)

    elif breach_found is False:

        print("✓ NOT FOUND")

    else:

        print("⚠️ UNKNOWN")

    print("\nRisk Level:", risk_level)

    print("\nRecommendations:")
    print("----------------------------")

    recommendation_found = False

    if breach_found is True:

        print("- Change this password immediately")
        print("- Never reuse a breached password")
        recommendation_found = True

    if common:

        print("- Avoid common passwords")
        recommendation_found = True

    if len(password) < 12:

        print("- Consider using at least 12 characters")
        recommendation_found = True

    if score < 5:

        if not any(
            char.isupper()
            for char in password
        ):
            print("- Add an uppercase letter")

        if not any(
            char.islower()
            for char in password
        ):
            print("- Add a lowercase letter")

        if not any(
            char.isdigit()
            for char in password
        ):
            print("- Add a number")

        if not any(
            not char.isalnum()
            for char in password
        ):
            print("- Add a special character")

        recommendation_found = True

    if not recommendation_found:

        print("✓ No major security issues detected.")

    print("\n================================")


# ==============================
# PASSWORD SECURITY CHECK
# ==============================
def check_password(password):

    common = is_common_password(password)

    has_length = len(password) >= 8

    has_uppercase = any(
        char.isupper()
        for char in password
    )

    has_lowercase = any(
        char.islower()
        for char in password
    )

    has_number = any(
        char.isdigit()
        for char in password
    )

    has_special = any(
        not char.isalnum()
        for char in password
    )

    score = 0

    if has_length:
        score += 1

    if has_uppercase:
        score += 1

    if has_lowercase:
        score += 1

    if has_number:
        score += 1

    if has_special:
        score += 1

    if score == 5:
        strength = "STRONG"

    elif score >= 3:
        strength = "MEDIUM"

    else:
        strength = "WEAK"

    # ==============================
    # BASIC SECURITY REPORT
    # ==============================

    print("\n================================")
    print("       SECURITY REPORT")
    print("================================")

    print(
        "\nPassword length:",
        len(password),
        "characters"
    )

    print("\nSecurity Score:", score, "/ 5")
    print("Password Strength:", strength)

    print()

    show_strength_meter(score)

    print()

    show_entropy(password)

    # ==============================
    # SECURITY CHECKS
    # ==============================

    print("\nSecurity Checks:")
    print("----------------------------")

    if has_length:
        print("✓ Length")
    else:
        print("✗ Length")

    if has_uppercase:
        print("✓ Uppercase")
    else:
        print("✗ Uppercase")

    if has_lowercase:
        print("✓ Lowercase")
    else:
        print("✗ Lowercase")

    if has_number:
        print("✓ Number")
    else:
        print("✗ Number")

    if has_special:
        print("✓ Special character")
    else:
        print("✗ Special character")

    # ==============================
    # COMMON PASSWORD
    # ==============================

    if common:

        print("\n⚠️ WARNING")
        print("This is a very common password.")
        print("It may be easy for attackers to guess.")

    # ==============================
    # BREACH CHECK
    # ==============================

    breach_found, breach_count = show_breach_check(
        password
    )

    # ==============================
    # RECOMMENDATIONS
    # ==============================

    print("\nRecommendations:")
    print("----------------------------")

    recommendation_found = False

    if not has_length:

        print("- Use at least 8 characters")
        recommendation_found = True

    if not has_uppercase:

        print("- Add an uppercase letter")
        recommendation_found = True

    if not has_lowercase:

        print("- Add a lowercase letter")
        recommendation_found = True

    if not has_number:

        print("- Add a number")
        recommendation_found = True

    if not has_special:

        print("- Add a special character")
        recommendation_found = True

    if common:

        print("- Avoid common passwords")
        recommendation_found = True

    if not recommendation_found:

        print(
            "✓ Your password meets all basic "
            "security checks!"
        )

    print("================================")

    # ==============================
    # DETAILED REPORT
    # ==============================

    show_detailed_report(
        password,
        score,
        strength,
        common,
        breach_found,
        breach_count
    )

    return score, strength, common


# ==============================
# ACCOUNT SECURITY CHECK
# ==============================
def account_security_check():

    print("\n================================")
    print("      ACCOUNT SECURITY CHECK")
    print("================================")

    username = input(
        "\nEnter your username: "
    ).strip()

    if not username:

        print("❌ Username cannot be empty.")
        return

    password = getpass.getpass(
        "Enter your password: "
    )

    print("\nUsername Security:")
    print("----------------------------")

    username_safe = True

    if len(username) >= 4:

        print("✓ Username length is acceptable")

    else:

        print("✗ Username is too short")
        username_safe = False

    if username.lower() == password.lower():

        print(
            "⚠️ Username and password are the same"
        )

        username_safe = False

    else:

        print(
            "✓ Username and password are different"
        )

    if username.lower() in password.lower():

        print(
            "⚠️ Password contains your username"
        )

        username_safe = False

    else:

        print(
            "✓ Password does not contain your username"
        )

    print("\nPassword Security:")
    print("----------------------------")

    score, strength, common = check_password(
        password
    )

    print("\n================================")
    print("       ACCOUNT RESULT")
    print("================================")

    if (
        username_safe
        and strength == "STRONG"
        and not common
    ):

        print("✓ Account security looks good.")

    else:

        print(
            "⚠️ Account security needs improvement."
        )

    print("================================")


# ==============================
# PASSWORD HISTORY
# ==============================
def show_history():

    print("\n===============================")
    print("       PASSWORD HISTORY")
    print("===============================")

    if len(history) == 0:

        print("\nNo password checks yet.")
        return

    for number, result in enumerate(
        history,
        start=1
    ):

        score = result["score"]
        strength = result["strength"]
        common = result["common"]

        print(
            f"{number}. "
            f"Score: {score}/5 - {strength}"
        )

        if common:

            print(
                "   ⚠️ Common password detected"
            )


# ==============================
# MAIN PROGRAM
# ==============================
while True:

    print("\n===============================")
    print("   PASSWORD SECURITY CHECKER")
    print("===============================")

    print("\n1. Check a password")
    print("2. Generate a strong password")
    print("3. Password history")
    print("4. Account Security Check")
    print("5. Exit")

    choice = input(
        "\nChoose an option: "
    )

    # ==============================
    # OPTION 1
    # ==============================
    if choice == "1":

        password = getpass.getpass(
            "\nEnter your password: "
        )

        print(
            "\nYour password has been received."
        )

        score, strength, common = check_password(
            password
        )

        history.append({
            "score": score,
            "strength": strength,
            "common": common
        })

    # ==============================
    # OPTION 2
    # ==============================
    elif choice == "2":

        length_input = input(
            "\nHow long should the password be? "
        )

        if not length_input.isdigit():

            print(
                "❌ Please enter a number."
            )

            continue

        length = int(length_input)

        if length < 8:

            print(
                "❌ Password should be at least "
                "8 characters long."
            )

            continue

        special_choice = input(
            "Include special characters? (y/n): "
        ).lower()

        if special_choice == "y":

            use_special = True

        elif special_choice == "n":

            use_special = False

        else:

            print(
                "❌ Please enter y or n."
            )

            continue

        generated_password = generate_password(
            length,
            use_special
        )

        print(
            "\nSuggested strong password:"
        )

        print(generated_password)

    # ==============================
    # OPTION 3
    # ==============================
    elif choice == "3":

        show_history()

    # ==============================
    # OPTION 4
    # ==============================
    elif choice == "4":

        account_security_check()

    # ==============================
    # OPTION 5
    # ==============================
    elif choice == "5":

        print(
            "\nThank you for using "
            "Password Security Checker!"
        )

        break

    # ==============================
    # INVALID OPTION
    # ==============================
    else:

        print(
            "\n❌ Invalid option. "
            "Please choose 1, 2, 3, 4, or 5."
        )