"""Synthetic fixture: weak/misused cryptography.
Adapted from the weak-crypto sample already used in demo_security_agents.py
for continuity with existing manual verification in this repo."""

import hashlib
import random
import base64
from Crypto.Cipher import AES


def hash_password(password: str) -> str:
    # VULNERABLE: MD5 is not a password hash -- no salt, trivially crackable.
    return hashlib.md5(password.encode()).hexdigest()


def generate_reset_token() -> str:
    # VULNERABLE: random.randint uses the Mersenne Twister, not
    # cryptographically secure -- predictable password-reset tokens.
    return str(random.randint(100000, 999999))


def encrypt_data(data: str) -> str:
    # VULNERABLE: base64 is an encoding, not encryption -- provides zero
    # confidentiality.
    return base64.b64encode(data.encode()).decode()


def encrypt_message(message: bytes) -> bytes:
    # VULNERABLE: ECB mode leaks plaintext patterns (identical blocks ->
    # identical ciphertext), and the key is hardcoded in source.
    key = b"hardcoded_key123"
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message)


def verify_file_integrity(content: bytes) -> str:
    # VULNERABLE: SHA1 is broken for collision resistance.
    return hashlib.sha1(content).hexdigest()
