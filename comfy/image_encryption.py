import os
import tempfile
import base64
import getpass
import json
import secrets
import sys
from contextlib import contextmanager

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from comfy.cli_args import args


NONCE_SIZE = 12
PBKDF2_ITERATIONS = 600_000
_salt = None


def initialize_image_encryption() -> None:
    if args.encrypt_uploaded_images:
        _get_salt()


def _get_salt() -> bytes:
    global _salt
    if _salt is not None:
        return _salt
    if not args.encrypt_uploaded_images:
        raise RuntimeError("Uploaded image encryption is disabled.")
    if not sys.stdin.isatty():
        raise RuntimeError("Encrypted uploaded images require an interactive terminal to enter their salt.")

    salt = getpass.getpass("Encrypted uploaded image Salt: ")
    confirmation = getpass.getpass("Confirm encrypted uploaded image Salt: ")
    if not salt:
        raise RuntimeError("Encrypted uploaded image Salt cannot be empty.")
    if salt != confirmation:
        raise RuntimeError("Encrypted uploaded image Salt confirmation does not match.")
    _salt = salt.encode()
    return _salt


def _derive_key(code: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_get_salt(),
        iterations=PBKDF2_ITERATIONS,
    ).derive(code)


def is_encrypted_image_file(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as file:
            payload = json.load(file)
            return isinstance(payload.get("code"), str) and isinstance(payload.get("data"), str)
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return False


def encrypt_image_file(path: str) -> None:
    if is_encrypted_image_file(path):
        return

    with open(path, "rb") as file:
        plaintext = file.read()

    code = secrets.token_bytes(32)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(_derive_key(code)).encrypt(nonce, plaintext, None)
    temporary_path = f"{path}.encrypting"
    with open(temporary_path, "w", encoding="utf-8") as file:
        json.dump({"code": base64.b64encode(code).decode("ascii"), "data": base64.b64encode(nonce + ciphertext).decode("ascii")}, file, separators=(",", ":"))
    os.replace(temporary_path, path)


def decrypt_image_file(path: str) -> bytes:
    with open(path, "rb") as file:
        contents = file.read()
    try:
        payload = json.loads(contents)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return contents
    if not isinstance(payload.get("code"), str) or not isinstance(payload.get("data"), str):
        return contents

    encrypted = base64.b64decode(payload["data"])
    nonce = encrypted[:NONCE_SIZE]
    ciphertext = encrypted[NONCE_SIZE:]

    return AESGCM(_derive_key(base64.b64decode(payload["code"]))).decrypt(nonce, ciphertext, None)


@contextmanager
def decrypted_image_path(path: str):
    if not is_encrypted_image_file(path):
        yield path
        return

    suffix = os.path.splitext(path)[1]
    with tempfile.NamedTemporaryFile(suffix=suffix) as file:
        file.write(decrypt_image_file(path))
        file.flush()
        yield file.name
