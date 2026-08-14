#!/usr/bin/env python3
"""
pwaudit - password strength check + hash type identifier, in one script.

Two things I keep needing during assessments and never remember where I
last put the script for: a quick "how bad is this password" check, and a
"what hash format is this" guess when I find a leaked credential dump.

Usage:
    python3 pwaudit.py check "Summer2023!"
    python3 pwaudit.py identify '$2b$12$KIXQ4t1y5z...'
    python3 pwaudit.py hash "hello world" --algo sha256
"""

import argparse
import hashlib
import math
import re
import sys

# Small embedded list of frequently-seen weak passwords. Not a substitute
# for a real wordlist like rockyou.txt - this is just enough to catch the
# obvious stuff without shipping a multi-MB file in the repo.
COMMON_PASSWORDS = {
    "123456", "123456789", "password", "12345678", "qwerty", "12345",
    "111111", "1234567", "letmein", "abc123", "sunshine", "iloveyou",
    "admin", "welcome", "monkey", "login", "princess", "qwerty123",
    "solo", "passw0rd", "starwars", "dragon", "football", "master",
    "hello", "freedom", "whatever", "trustno1", "shadow", "superman",
    "michael", "ninja", "mustang", "password1", "123123", "000000",
    "1234", "12345678910", "changeme", "test123", "summer2023", "winter2024",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def entropy_bits(pw):
    """Rough Shannon-style entropy estimate based on character pool size, not
    a formal measure - good enough for a relative strength score."""
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"[0-9]", pw):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        pool += 33
    if pool == 0:
        return 0.0
    return len(pw) * math.log2(pool)


def has_keyboard_walk(pw, min_run=4):
    low = pw.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_run + 1):
            run = row[i:i + min_run]
            if run in low or run[::-1] in low:
                return True
    return False


def has_sequential_run(pw, min_run=4):
    low = pw.lower()
    for i in range(len(low) - min_run + 1):
        chunk = low[i:i + min_run]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return True
    return False


def has_repeated_run(pw, min_run=4):
    for i in range(len(pw) - min_run + 1):
        if len(set(pw[i:i + min_run])) == 1:
            return True
    return False


def check_password(pw):
    issues = []
    if len(pw) < 8:
        issues.append("shorter than 8 characters")
    if pw.lower() in COMMON_PASSWORDS:
        issues.append("appears on a common-password list")
    if not re.search(r"[A-Z]", pw):
        issues.append("no uppercase letters")
    if not re.search(r"[a-z]", pw):
        issues.append("no lowercase letters")
    if not re.search(r"[0-9]", pw):
        issues.append("no digits")
    if not re.search(r"[^a-zA-Z0-9]", pw):
        issues.append("no symbols")
    if has_keyboard_walk(pw):
        issues.append("contains a keyboard-walk pattern (e.g. qwerty, asdf)")
    if has_sequential_run(pw):
        issues.append("contains a sequential run (e.g. abcd, 1234)")
    if has_repeated_run(pw):
        issues.append("contains a repeated-character run (e.g. aaaa)")

    bits = entropy_bits(pw)
    if bits < 28:
        rating = "very weak"
    elif bits < 36:
        rating = "weak"
    elif bits < 60:
        rating = "reasonable"
    elif bits < 80:
        rating = "strong"
    else:
        rating = "very strong"

    # a common-password hit overrides everything else
    if pw.lower() in COMMON_PASSWORDS:
        rating = "very weak"

    return rating, bits, issues


HASH_SIGNATURES = [
    (re.compile(r"^\$2[aby]\$\d{2}\$"), "bcrypt"),
    (re.compile(r"^\$1\$"), "md5crypt (Unix)"),
    (re.compile(r"^\$5\$"), "sha256crypt (Unix)"),
    (re.compile(r"^\$6\$"), "sha512crypt (Unix)"),
    (re.compile(r"^\$argon2(id|i|d)\$"), "argon2"),
    (re.compile(r"^\$pbkdf2"), "pbkdf2 (passlib-style)"),
    (re.compile(r"^[0-9a-fA-F]{32}$"), "MD5 or NTLM (32 hex chars, ambiguous without context)"),
    (re.compile(r"^[0-9a-fA-F]{40}$"), "SHA-1 (40 hex chars)"),
    (re.compile(r"^[0-9a-fA-F]{56}$"), "SHA-224 (56 hex chars)"),
    (re.compile(r"^[0-9a-fA-F]{64}$"), "SHA-256 (64 hex chars)"),
    (re.compile(r"^[0-9a-fA-F]{96}$"), "SHA-384 (96 hex chars)"),
    (re.compile(r"^[0-9a-fA-F]{128}$"), "SHA-512 (128 hex chars)"),
]


def identify_hash(value):
    matches = [name for pattern, name in HASH_SIGNATURES if pattern.match(value.strip())]
    return matches


def cmd_check(args):
    rating, bits, issues = check_password(args.password)
    print(f"password : {args.password!r}")
    print(f"rating   : {rating}  (~{bits:.1f} bits of entropy, rough estimate)")
    if issues:
        print("issues   :")
        for i in issues:
            print(f"  - {i}")
    else:
        print("issues   : none found")


def cmd_identify(args):
    matches = identify_hash(args.value)
    if not matches:
        print("No confident match. Could be a keyed/salted format this script doesn't "
              "recognize, or just random-looking data. Check length and any prefix by hand.")
        return
    print(f"Possible match(es) for {args.value[:50]!r}{'...' if len(args.value) > 50 else ''}:")
    for m in matches:
        print(f"  - {m}")


def cmd_hash(args):
    algo = args.algo.lower()
    if algo not in hashlib.algorithms_available:
        print(f"[!] Unknown algorithm: {algo}", file=sys.stderr)
        sys.exit(1)
    h = hashlib.new(algo)
    h.update(args.text.encode())
    print(h.hexdigest())


def main():
    ap = argparse.ArgumentParser(description="Password strength checker and hash format identifier.")
    sub = ap.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="rate a password's strength")
    p_check.add_argument("password")
    p_check.set_defaults(func=cmd_check)

    p_id = sub.add_parser("identify", help="guess the algorithm behind a hash string")
    p_id.add_argument("value")
    p_id.set_defaults(func=cmd_identify)

    p_hash = sub.add_parser("hash", help="hash a string with a given algorithm")
    p_hash.add_argument("text")
    p_hash.add_argument("--algo", default="sha256", help="hashlib algorithm name (default: sha256)")
    p_hash.set_defaults(func=cmd_hash)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
