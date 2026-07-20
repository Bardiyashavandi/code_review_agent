"""Synthetic fixture: correct use of the `secrets` module for
security-sensitive randomness -- the safe counterpart to weak_crypto.py's
`random.randint` token generator."""

import hashlib
import secrets


def generate_password_reset_token() -> str:
    # Safe: secrets.token_urlsafe is backed by os.urandom -- cryptographically
    # secure, unlike random.randint used in weak_crypto.py.
    return secrets.token_urlsafe(32)


def generate_session_id() -> str:
    return secrets.token_hex(16)


def hash_for_deduplication(content: bytes) -> str:
    # Safe: SHA-256 used only for content-addressable deduplication (not
    # for password storage or a security boundary), which is a legitimate
    # non-security use of a fast hash.
    return hashlib.sha256(content).hexdigest()
