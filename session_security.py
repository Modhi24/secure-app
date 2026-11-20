"""Encrypt Flask session data while retaining Flask's cookie handling."""

from cryptography.fernet import Fernet, InvalidToken
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import BadSignature


class EncryptedSessionSerializer:
    def __init__(self, key, serializer):
        self.cipher = Fernet(key)
        self.serializer = serializer

    def dumps(self, data):
        # Fernet protects both the confidentiality and integrity of the session.
        payload = self.serializer.dumps(data).encode("utf-8")
        return self.cipher.encrypt(payload).decode("ascii")

    def loads(self, token, max_age=None):
        try:
            payload = self.cipher.decrypt(token.encode("ascii"), ttl=max_age)
        except (InvalidToken, UnicodeEncodeError) as exc:
            # Flask treats invalid, expired, and old-format cookies as empty sessions.
            raise BadSignature("Invalid session cookie") from exc
        return self.serializer.loads(payload.decode("utf-8"))


class EncryptedSessionInterface(SecureCookieSessionInterface):
    def __init__(self, key):
        self.encrypted_serializer = EncryptedSessionSerializer(key, self.serializer)

    def get_signing_serializer(self, app):
        # Flask uses this hook for cookie serialization and still handles flags and deletion.
        return self.encrypted_serializer
