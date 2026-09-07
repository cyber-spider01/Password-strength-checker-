import math
import re
import secrets
import string

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "admin", 
    "welcome", "password123", "abc123", "letmein", "iloveyou"
}

def calculate_entropy(password):
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        pool_size += 32

    if pool_size == 0 or len(password) == 0:
        return 0.0

    # Entropy = Length * log2(Pool Size)
    return round(len(password) * math.log2(pool_size), 2)

def evaluate_password(password):
    issues = []
    
    if password.lower() in COMMON_PASSWORDS:
        return {
            "score": 0,
            "rating": "Very Weak (Blacklisted)",
            "entropy": 0.0,
            "feedback": ["This is one of the most commonly breached passwords!"]
        }

    # Length check
    if len(password) < 8:
        issues.append("Too short (aim for at least 12 characters).")
    elif len(password) < 12:
        issues.append("Decent length, but 12+ characters is recommended.")

    # Character composition checks
    if not re.search(r"[a-z]", password):
        issues.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        issues.append("Add uppercase letters.")
    if not re.search(r"[0-9]", password):
        issues.append("Add numeric digits (0-9).")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        issues.append("Add special symbols (!@#$%^&*...).")

    # Repetition check (3 identical chars in a row)
    if re.search(r"(.)\1\1", password):
        issues.append("Avoid repeating characters (e.g., 'aaa' or '111').")

    entropy = calculate_entropy(password)

    # Score assignment based on entropy and length
    if entropy < 30 or len(password) < 6:
        rating = "Very Weak"
        score = 1
    elif entropy < 50:
        rating = "Weak"
        score = 2
    elif entropy < 70:
        rating = "Moderate"
        score = 3
    elif entropy < 90:
        rating = "Strong"
        score = 4
    else:
        rating = "Very Strong"
        score = 5

    return {
        "score": score,
        "rating": rating,
        "entropy": entropy,
        "feedback": issues if issues else ["No major weaknesses detected!"]
    }

def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Ensure it contains at least one of each category
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#$%^&*()-_=+" for c in password)):
            return password

def main():
    print("=" * 50)
    print("      Password Strength & Entropy Analyzer      ")
    print("=" * 50)

    while True:
        print("\n1. Check a Password")
        print("2. Generate a Secure Password")
        print("3. Exit")
        
        choice = input("Select an option (1-3): ").strip()
        
        if choice == "1":
            pwd = input("\nEnter password to test: ").strip()
            if not pwd:
                print("[!] Password cannot be empty.")
                continue

            result = evaluate_password(pwd)
            print("\n" + "-" * 40)
            print(f"Rating:        {result['rating']} ({result['score']}/5)")
            print(f"Entropy:       {result['entropy']} bits")
            print("Suggestions:")
            for issue in result["feedback"]:
                print(f"  • {issue}")
            print("-" * 40)

        elif choice == "2":
            try:
                length_input = input("Enter length (default 16, min 8): ").strip()
                length = int(length_input) if length_input else 16
                length = max(length, 8)
                generated = generate_strong_password(length)
                entropy = calculate_entropy(generated)
                print(f"\nGenerated: {generated}")
                print(f"Entropy:   {entropy} bits (Very Strong)")
            except ValueError:
                print("[!] Please enter a valid number.")

        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("[!] Invalid option.")

if __name__ == "__main__":
    main()