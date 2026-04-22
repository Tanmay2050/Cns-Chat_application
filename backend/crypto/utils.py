"""
Server-side crypto utilities (reference / audit only).
Private keys NEVER touch the server.
"""
import hashlib
import base64


def verify_sha256(plaintext: str, provided_hash: str) -> bool:
    return hashlib.sha256(plaintext.encode()).hexdigest() == provided_hash


def safe_b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode()


def safe_b64decode(s: str) -> bytes:
    return base64.b64decode(s + '==')
