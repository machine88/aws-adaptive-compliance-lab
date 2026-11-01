"""Local synthetic recipients shared by encryption tests; never uses real credentials or Keychain."""
import hashlib
from pathlib import Path
import shutil
import subprocess


def synthetic_recipient(root):
    """Create a disposable RSA recipient and return its normalized public certificate identity.

    Inputs:
        root: Existing private temporary directory owned and cleaned by the calling test.
    Outputs:
        tuple: OpenSSL executable, public certificate path, test-only private key path and PEM
            SHA-256 fingerprint. Creates synthetic files; never accesses AWS or real recipients.
    """
    root = Path(root)
    binary = "/opt/homebrew/opt/openssl@3/bin/openssl"
    if not Path(binary).exists():
        binary = shutil.which("openssl")
    cert, key = root / "public.pem", root / "synthetic-only.key"
    subprocess.run([binary, "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", str(key),
                    "-out", str(cert), "-days", "1", "-subj", "/CN=synthetic-recovery-test"],
                   check=True, capture_output=True, timeout=30)
    normalized = subprocess.run([binary, "x509", "-in", str(cert), "-outform", "PEM"],
                                check=True, capture_output=True, timeout=5).stdout
    return binary, cert, key, hashlib.sha256(normalized).hexdigest()
