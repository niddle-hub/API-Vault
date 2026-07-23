import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    Fernet = None

    class InvalidToken(Exception):
        pass


PBKDF2_ITERATIONS = 100_000
AES_GCM_PREFIX = b"AG1"
_POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")
_AES_GCM_SCRIPT = r"""
$ErrorActionPreference = "Stop"
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$key = [Convert]::FromBase64String($payload.key)
$aes = [Security.Cryptography.AesGcm]::new($key, 16)
try {
    if ($payload.operation -eq "encrypt") {
        $plaintext = [Convert]::FromBase64String($payload.plaintext)
        $nonce = [byte[]]::new(12)
        [Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        $ciphertext = [byte[]]::new($plaintext.Length)
        $tag = [byte[]]::new(16)
        $aes.Encrypt($nonce, $plaintext, $ciphertext, $tag)
        @{
            nonce = [Convert]::ToBase64String($nonce)
            ciphertext = [Convert]::ToBase64String($ciphertext)
            tag = [Convert]::ToBase64String($tag)
        } | ConvertTo-Json -Compress
    } else {
        $nonce = [Convert]::FromBase64String($payload.nonce)
        $ciphertext = [Convert]::FromBase64String($payload.ciphertext)
        $tag = [Convert]::FromBase64String($payload.tag)
        $plaintext = [byte[]]::new($ciphertext.Length)
        $aes.Decrypt($nonce, $ciphertext, $tag, $plaintext)
        [Convert]::ToBase64String($plaintext)
    }
} finally {
    $aes.Dispose()
}
"""


def generate_salt() -> bytes:
    return os.urandom(16)


def derive_key(password: str, salt: bytes) -> bytes:
    raw_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw_key)


def create_password_verifier(encryption_key: bytes) -> str:
    return hmac.new(
        encryption_key,
        b"api-holder-master-password-verifier",
        hashlib.sha256,
    ).hexdigest()


def verify_password(encryption_key: bytes, expected_verifier: str) -> bool:
    return hmac.compare_digest(
        create_password_verifier(encryption_key),
        expected_verifier,
    )


def encrypt_value(key: bytes, plaintext: str) -> bytes:
    if Fernet is not None:
        return Fernet(key).encrypt(plaintext.encode("utf-8"))
    return _encrypt_with_windows_aes_gcm(key, plaintext)


def decrypt_value(key: bytes, encrypted: bytes) -> str:
    if encrypted.startswith(AES_GCM_PREFIX):
        return _decrypt_with_windows_aes_gcm(key, encrypted)
    if Fernet is None:
        raise InvalidToken("The cryptography package is required for Fernet data.")
    return Fernet(key).decrypt(encrypted).decode("utf-8")


def _run_aes_gcm(payload):
    if _POWERSHELL is None:
        raise RuntimeError(
            "Install the cryptography package; no AES-GCM provider is available."
        )

    encoded_script = base64.b64encode(
        _AES_GCM_SCRIPT.encode("utf-16-le")
    ).decode("ascii")
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    result = subprocess.run(
        [_POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
        creationflags=creation_flags,
    )
    if result.returncode != 0:
        raise InvalidToken("AES-GCM operation failed.")
    return result.stdout.strip()


def _encrypt_with_windows_aes_gcm(key: bytes, plaintext: str) -> bytes:
    result = json.loads(
        _run_aes_gcm(
            {
                "operation": "encrypt",
                "key": base64.b64encode(base64.urlsafe_b64decode(key)).decode("ascii"),
                "plaintext": base64.b64encode(
                    plaintext.encode("utf-8")
                ).decode("ascii"),
            }
        )
    )
    return AES_GCM_PREFIX + b"." + b".".join(
        result[name].encode("ascii")
        for name in ("nonce", "tag", "ciphertext")
    )


def _decrypt_with_windows_aes_gcm(key: bytes, encrypted: bytes) -> str:
    try:
        nonce, tag, ciphertext = encrypted[len(AES_GCM_PREFIX) + 1 :].split(b".", 2)
        result = _run_aes_gcm(
            {
                "operation": "decrypt",
                "key": base64.b64encode(base64.urlsafe_b64decode(key)).decode("ascii"),
                "nonce": nonce.decode("ascii"),
                "tag": tag.decode("ascii"),
                "ciphertext": ciphertext.decode("ascii"),
            }
        )
        return base64.b64decode(result).decode("utf-8")
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InvalidToken("Invalid AES-GCM token.") from error
