from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


def hash_password(password: str) -> str:
    """Hashes a plain-text password using Argon2id."""
    ph = PasswordHasher()
    return ph.hash(password)

def verify_password(hashed_password: str, plain_password: str) -> bool:
    """Verifies a plain-text password against a stored Argon2id hash."""
    try:
        ph = PasswordHasher()
        return ph.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False