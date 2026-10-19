
import re
import math
import sqlite3
import hashlib
import hmac
import secrets
import string
import os


class PasswordAnalyzer:

    def __init__(self, db_name="passwords.db"):
        # Connect to the SQLite database
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()

        # Create a table to store password hashes
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS used_passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_hash TEXT NOT NULL
            )
        """)
        self.conn.commit()

        # Common weak passwords
        self.common_passwords = {
            "password", "123456", "123456789", "qwerty",
            "admin", "welcome", "111111", "password123",
            "iloveyou", "secret"
        }

    def calculate_entropy(self, password):
        """Estimate password entropy in bits."""

        charset_size = 0

        if re.search(r"[a-z]", password):
            charset_size += 26

        if re.search(r"[A-Z]", password):
            charset_size += 26

        if re.search(r"\d", password):
            charset_size += 10

        if re.search(r"[^a-zA-Z0-9]", password):
            charset_size += 33

        if not password or charset_size == 0:
            return 0

        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)

    def analyze(self, password):
        """Analyze password length, complexity, and strength."""

        feedback = []
        score = 0

        # Check for common weak passwords
        if password.lower() in self.common_passwords:
            return (
                "Extremely Weak",
                ["This is a commonly used password. Choose a unique one."]
            )

        # Check password length
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
            feedback.append(
                "Use at least 12 characters for better security."
            )
        else:
            feedback.append(
                "Password is too short. Use at least 8 characters."
            )

        # Check uppercase letters
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add at least one uppercase letter (A-Z).")

        # Check lowercase letters
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add at least one lowercase letter (a-z).")

        # Check numbers
        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Add at least one number (0-9).")

        # Check special characters
        if re.search(r"[^a-zA-Z0-9]", password):
            score += 1
        else:
            feedback.append(
                "Add at least one special character (!, @, #, etc.)."
            )

        # Calculate estimated entropy
        entropy = self.calculate_entropy(password)

        if entropy < 40:
            feedback.append(
                f"Low estimated entropy ({entropy} bits). "
                "Use a longer, less predictable password."
            )

        # Determine password strength
        if len(password) < 8:
            strength = "Weak"
        elif score >= 6 and entropy >= 60:
            strength = "Strong"
        elif score >= 4 and entropy >= 40:
            strength = "Moderate"
        else:
            strength = "Weak"

        return strength, feedback

    def check_reuse(self, password):
        """Check whether a password matches a stored password hash."""

        self.cursor.execute(
            "SELECT password_hash FROM used_passwords"
        )
        rows = self.cursor.fetchall()

        password_bytes = password.encode("utf-8")

        for row in rows:
            stored_data = row[0].split("$")

            if len(stored_data) != 3:
                continue

            algorithm, salt_hex, hash_hex = stored_data

            if algorithm != "pbkdf2_sha256":
                continue

            try:
                salt = bytes.fromhex(salt_hex)
                expected_hash = bytes.fromhex(hash_hex)
            except ValueError:
                continue

            actual_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password_bytes,
                salt,
                600000
            )

            if hmac.compare_digest(actual_hash, expected_hash):
                return True

        return False

    def save_password(self, password):
        """Hash and store a password without saving plaintext."""

        password_bytes = password.encode("utf-8")

        # Generate a random salt for the password
        salt = os.urandom(16)

        # Derive a secure password hash using PBKDF2
        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password_bytes,
            salt,
            600000
        )

        # Store algorithm name, salt, and hash
        stored_value = (
            "pbkdf2_sha256$"
            + salt.hex()
            + "$"
            + hashed.hex()
        )

        try:
            self.cursor.execute(
                "INSERT INTO used_passwords (password_hash) VALUES (?)",
                (stored_value,)
            )
            self.conn.commit()
            return True

        except sqlite3.Error:
            self.conn.rollback()
            return False

    def suggest_password(self):
        """Generate a random 16-character password suggestion."""

        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*"

        # Include at least one character from every category
        characters = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]

        all_characters = lowercase + uppercase + digits + special

        # Add 12 more randomly selected characters
        for _ in range(12):
            characters.append(secrets.choice(all_characters))

        # Shuffle the characters securely
        secrets.SystemRandom().shuffle(characters)

        return "".join(characters)

    def close(self):
        """Close the database connection."""
        self.conn.close()


def main():
    analyzer = PasswordAnalyzer()

    try:
        print("=" * 45)
        print("       PASSWORD STRENGTH ANALYZER")
        print("=" * 45)

        user_password = input(
            "Enter a password to analyze: "
        )

        # Analyze password strength
        strength, feedback = analyzer.analyze(user_password)
        entropy = analyzer.calculate_entropy(user_password)

        print("\n--- Analysis Results ---")
        print("Strength Rating :", strength)
        print("Estimated Entropy:", entropy, "bits")
        print("Password Length :", len(user_password), "characters")

        # Display suggestions
        if feedback:
            print("\nSuggestions for Improvement:")

            for tip in feedback:
                print("-", tip)
        else:
            print("\nYour password meets the basic checks.")

        # Suggest an alternative if the password is not strong
        if strength != "Strong":
            print("\nSuggested stronger password:")
            print(analyzer.suggest_password())
            print("Keep any password you choose private and secure.")

        # Check whether the password was used previously
        if analyzer.check_reuse(user_password):
            print("\nWARNING: This password matches a previously")
            print("stored password. Please choose a different one.")

        else:
            print("\nThis password does not match stored passwords.")

            choice = input(
                "\nStore its password hash for future reuse checks? (y/n): "
            ).strip().lower()

            if choice == "y":
                if analyzer.save_password(user_password):
                    print("Password hash saved successfully.")
                else:
                    print("Could not save the password hash.")

        print("\nAnalysis completed.")

    finally:
        analyzer.close()


if __name__ == "__main__":
    main()
