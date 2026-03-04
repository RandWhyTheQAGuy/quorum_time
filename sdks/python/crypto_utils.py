"""
uml001.crypto_utils
===================
Python equivalent of crypto_utils.cpp.

Cryptographic primitives used across the UML-001 stack.

Algorithms
----------
- SHA-256                      (hashlib)
- HMAC-SHA-256                 (hmac + hashlib)
- Ed25519 sign / verify        (cryptography >= 2.6)
- AES-256-GCM encrypt/decrypt  (cryptography)
- Base64 encode / decode       (base64)
- CSPRNG bytes                 (os.urandom)
- Constant-time comparison     (hmac.compare_digest)
- Secure zeroisation           (ctypes memset)

All public functions mirror the C++ signatures as closely as Python allows.
``bytes`` parameters accept ``bytes | bytearray``.  Hex parameters are plain
``str`` containing lowercase hex digits.

Security notes
--------------
- ``constant_time_equals`` uses ``hmac.compare_digest`` (timing-safe).
- ``secure_zero`` overwrites a bytearray in-place via ctypes; it is the
  closest Python equivalent of ``OPENSSL_cleanse``.
- Private keys are never logged or included in exception messages.
"""

import base64
import ctypes
import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _to_bytes(name: str, value: bytes | bytearray) -> bytes:
    if isinstance(value, bytearray):
        return bytes(value)
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes or bytearray, got {type(value).__name__}")
    return value


# ---------------------------------------------------------------------------
# SHA-256
# ---------------------------------------------------------------------------

def sha256_raw(data: bytes | bytearray) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(_to_bytes("data", data)).digest()


def sha256_hex(data: str | bytes | bytearray) -> str:
    """Return the lowercase hex-encoded SHA-256 digest of *data*.

    *data* may be a ``str`` (UTF-8), ``bytes``, or ``bytearray``.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return sha256_raw(data).hex()


# ---------------------------------------------------------------------------
# HMAC-SHA-256
# ---------------------------------------------------------------------------

def hmac_sha256_hex(payload: str, key_hex: str) -> str:
    """Return lowercase hex HMAC-SHA-256 of *payload* using *key_hex*.

    Mirrors ``hmac_sha256_hex(payload, key_hex)`` from crypto_utils.cpp.

    Parameters
    ----------
    payload:
        The message to authenticate (UTF-8 encoded before MAC).
    key_hex:
        HMAC key as a hex string (32 bytes / 64 hex chars recommended).
    """
    key = bytes.fromhex(key_hex)
    mac = hmac.new(key, payload.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


# ---------------------------------------------------------------------------
# CSPRNG
# ---------------------------------------------------------------------------

def secure_random_bytes(length: int) -> bytes:
    """Return *length* cryptographically random bytes via ``os.urandom``."""
    if length <= 0:
        raise ValueError("length must be a positive integer")
    return os.urandom(length)


def generate_random_bytes_hex(length: int) -> str:
    """Return *length* random bytes as a lowercase hex string.

    Mirrors ``generate_random_bytes_hex(length)`` from crypto_utils.h.
    """
    return secure_random_bytes(length).hex()


# ---------------------------------------------------------------------------
# Constant-time comparison
# ---------------------------------------------------------------------------

def constant_time_equals(a: bytes | bytearray, b: bytes | bytearray) -> bool:
    """Timing-safe byte equality.  Uses ``hmac.compare_digest``."""
    return hmac.compare_digest(_to_bytes("a", a), _to_bytes("b", b))


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------

def base64_encode(data: bytes | bytearray) -> str:
    """Return standard Base64 (no newlines) of *data*."""
    return base64.b64encode(_to_bytes("data", data)).decode("ascii")


def base64_decode(encoded: str) -> bytes:
    """Decode a standard Base64 string.  Raises ``ValueError`` on bad input."""
    try:
        return base64.b64decode(encoded)
    except Exception as exc:
        raise ValueError("Base64 decode failed") from exc


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------

def ed25519_generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 key pair.

    Returns
    -------
    (private_key_bytes, public_key_bytes)
        Each element is 32 raw bytes.
    """
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, pub_raw


def ed25519_sign(private_key: bytes | bytearray, message: bytes | bytearray) -> bytes:
    """Sign *message* with a raw 32-byte Ed25519 *private_key*.

    Returns the 64-byte signature.
    """
    private_key = _to_bytes("private_key", private_key)
    message = _to_bytes("message", message)
    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    return priv.sign(message)


def ed25519_verify(
    public_key: bytes | bytearray,
    message: bytes | bytearray,
    signature: bytes | bytearray,
) -> bool:
    """Verify an Ed25519 *signature* over *message* with a raw 32-byte *public_key*.

    Returns ``True`` if valid, ``False`` otherwise.  Never raises on a bad signature.
    """
    public_key = _to_bytes("public_key", public_key)
    message = _to_bytes("message", message)
    signature = _to_bytes("signature", signature)
    if len(public_key) != 32:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key)
        pub.verify(signature, message)
        return True
    except (InvalidSignature, Exception):
        return False


def ed25519_sign_hex(private_key_hex: str, message: str | bytes) -> str:
    """Sign and return the signature as a hex string."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    return ed25519_sign(bytes.fromhex(private_key_hex), message).hex()


def ed25519_verify_hex(public_key_hex: str, message: str | bytes, sig_hex: str) -> bool:
    """Verify using hex-encoded key and signature."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    return ed25519_verify(
        bytes.fromhex(public_key_hex), message, bytes.fromhex(sig_hex)
    )


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------

@dataclass
class AESGCMResult:
    """Mirrors the C++ ``AESGCMResult`` struct."""
    ciphertext: bytes   # encrypted data (without tag)
    nonce: bytes        # 12-byte random nonce
    tag: bytes          # 16-byte GCM authentication tag


def aes256_gcm_encrypt(
    key: bytes | bytearray,
    plaintext: bytes | bytearray,
    aad: bytes | bytearray = b"",
) -> AESGCMResult:
    """AES-256-GCM authenticated encryption.

    Parameters
    ----------
    key:
        32-byte (256-bit) encryption key.
    plaintext:
        Data to encrypt.
    aad:
        Additional authenticated data (authenticated but not encrypted).

    Returns
    -------
    AESGCMResult
        Contains separate ``ciphertext``, ``nonce`` (12 bytes), and
        ``tag`` (16 bytes) fields, mirroring the C++ struct.
    """
    key = _to_bytes("key", key)
    plaintext = _to_bytes("plaintext", plaintext)
    aad = _to_bytes("aad", aad)
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad or None)
    # The cryptography library appends the 16-byte tag at the end
    return AESGCMResult(
        ciphertext=ct_with_tag[:-16],
        nonce=nonce,
        tag=ct_with_tag[-16:],
    )


def aes256_gcm_decrypt(
    key: bytes | bytearray,
    ciphertext: bytes | bytearray,
    nonce: bytes | bytearray,
    tag: bytes | bytearray,
    aad: bytes | bytearray = b"",
) -> bytes:
    """AES-256-GCM authenticated decryption.

    Raises ``ValueError`` if the authentication tag does not match.
    """
    key = _to_bytes("key", key)
    ciphertext = _to_bytes("ciphertext", ciphertext)
    nonce = _to_bytes("nonce", nonce)
    tag = _to_bytes("tag", tag)
    aad = _to_bytes("aad", aad)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad or None)
    except Exception as exc:
        raise ValueError("AES-GCM authentication failed") from exc


# ---------------------------------------------------------------------------
# Secure zeroisation
# ---------------------------------------------------------------------------

def secure_zero(buf: bytearray) -> None:
    """Overwrite *buf* in-place with zeros.

    Only works on ``bytearray`` (mutable).  This is the closest Python
    equivalent of ``OPENSSL_cleanse`` from the C++ implementation.
    """
    if not isinstance(buf, bytearray):
        raise TypeError("secure_zero requires a mutable bytearray")
    if len(buf) == 0:
        return
    addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
    ctypes.memset(addr, 0, len(buf))
