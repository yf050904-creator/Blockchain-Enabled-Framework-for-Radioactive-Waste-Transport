"""
Certificate-based identity: RSA key pairs + admin-signed certificates.
No passwords or secrets in code; keys and certs stored under certs/.
"""
from __future__ import annotations

import base64
import json
import os
import time
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Default directory for keys and certificates (admin manages issuance).
DEFAULT_CERTS_DIR = "certs"
# Certificate validity (seconds); 10 years for demo.
CERT_VALIDITY_SEC = 10 * 365 * 24 * 3600
RSA_KEY_SIZE = 2048

# Default usernames to bootstrap (no passwords; identity from cert only).
BOOTSTRAP_USERS = [
    ("admin", "ADMIN", None),
    ("transporter", "TRANSPORTER", "TransporterOrg"),
    ("regulatorA", "REGULATOR", "RegulatorA"),
    ("regulatorB", "REGULATOR", "RegulatorB"),
]


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """Generate RSA key pair; return (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_message(private_pem: bytes, message: bytes) -> bytes:
    """Sign message with private key; return raw signature bytes."""
    private_key = serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signature


def verify_signature(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    """Verify signature with public key. Returns True if valid."""
    try:
        public_key = serialization.load_pem_public_key(
            public_pem, backend=default_backend()
        )
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def certificate_payload(sub: str, role: str, org_id: Optional[str], pub_pem: str) -> Dict:
    """Build payload dict for a certificate (signed by admin)."""
    now = time.time()
    return {
        "sub": sub,
        "role": role,
        "org_id": org_id,
        "pub": pub_pem,
        "iat": now,
        "exp": now + CERT_VALIDITY_SEC,
    }


def create_certificate(admin_private_pem: bytes, payload: Dict) -> Dict:
    """Sign payload with admin key; return cert dict { payload, signature_b64 }."""
    payload_str = json.dumps(payload, sort_keys=True)
    message = payload_str.encode("utf-8")
    signature = sign_message(admin_private_pem, message)
    return {
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def verify_certificate(admin_public_pem: bytes, cert: Dict) -> Optional[Dict]:
    """
    Verify cert signature with admin public key; check expiry.
    Returns payload dict if valid, else None.
    """
    try:
        payload = cert.get("payload")
        sig_b64 = cert.get("signature_b64")
        if not payload or not sig_b64:
            return None
        payload_str = json.dumps(payload, sort_keys=True)
        message = payload_str.encode("utf-8")
        signature = base64.b64decode(sig_b64)
        if not verify_signature(admin_public_pem, message, signature):
            return None
        if time.time() > payload.get("exp", 0):
            return None
        return payload
    except Exception:
        return None


def load_pem_file(path: str) -> Optional[bytes]:
    """Load PEM file; return content or None."""
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def save_pem_file(path: str, data: bytes) -> None:
    _ensure_dir(os.path.dirname(path))
    with open(path, "wb") as f:
        f.write(data)


def save_cert_file(path: str, cert: Dict) -> None:
    _ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=0)


def load_cert_file(path: str) -> Optional[Dict]:
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class CertStore:
    """
    Store keys and certificates under certs_dir.
    Admin key pair: admin_private.pem, admin_public.pem.
    Per user: {username}_private.pem, {username}_public.pem, {username}_cert.json.
    Identity is verified by validating certificate signature (admin) and optional
    proof of private key (sign challenge).
    """

    def __init__(self, certs_dir: str = DEFAULT_CERTS_DIR) -> None:
        self.certs_dir = certs_dir
        self._admin_private: Optional[bytes] = None
        self._admin_public: Optional[bytes] = None

    def _path(self, name: str, ext: str) -> str:
        return os.path.join(self.certs_dir, f"{name}{ext}")

    def ensure_dir(self) -> None:
        _ensure_dir(self.certs_dir)

    def load_admin_keys(self) -> bool:
        """Load admin key pair from disk. Returns True if both exist."""
        priv = load_pem_file(self._path("admin_private", ".pem"))
        pub = load_pem_file(self._path("admin_public", ".pem"))
        if priv and pub:
            self._admin_private = priv
            self._admin_public = pub
            return True
        return False

    def bootstrap_if_needed(self) -> None:
        """Create admin key pair and default user certs if not present."""
        self.ensure_dir()
        if not self.load_admin_keys():
            admin_priv, admin_pub = generate_rsa_keypair()
            save_pem_file(self._path("admin_private", ".pem"), admin_priv)
            save_pem_file(self._path("admin_public", ".pem"), admin_pub)
            self._admin_private = admin_priv
            self._admin_public = admin_pub

        for username, role, org_id in BOOTSTRAP_USERS:
            cert_path = self._path(username, "_cert.json")
            if os.path.isfile(cert_path):
                continue
            priv_path = self._path(username, "_private.pem")
            pub_path = self._path(username, "_public.pem")
            if not os.path.isfile(priv_path):
                priv_pem, pub_pem = generate_rsa_keypair()
                save_pem_file(priv_path, priv_pem)
                save_pem_file(pub_path, pub_pem)
            else:
                pub_pem = load_pem_file(pub_path)
                if not pub_pem:
                    continue
            pub_str = pub_pem.decode("utf-8")
            payload = certificate_payload(username, role, org_id, pub_str)
            cert = create_certificate(self._admin_private, payload)
            save_cert_file(cert_path, cert)

    def get_admin_public_pem(self) -> Optional[bytes]:
        if self._admin_public is None:
            self.load_admin_keys()
        return self._admin_public

    def get_admin_private_pem(self) -> Optional[bytes]:
        if self._admin_private is None:
            self.load_admin_keys()
        return self._admin_private

    def issue_certificate(self, username: str, role: str, org_id: Optional[str]) -> bool:
        """
        Generate key pair for user and issue certificate (admin signs).
        Returns True on success. Overwrites existing cert for this username.
        """
        if not self._admin_private:
            self.load_admin_keys()
        if not self._admin_private:
            return False
        priv_pem, pub_pem = generate_rsa_keypair()
        priv_path = self._path(username, "_private.pem")
        pub_path = self._path(username, "_public.pem")
        cert_path = self._path(username, "_cert.json")
        save_pem_file(priv_path, priv_pem)
        save_pem_file(pub_path, pub_pem)
        payload = certificate_payload(username, role, org_id, pub_pem.decode("utf-8"))
        cert = create_certificate(self._admin_private, payload)
        save_cert_file(cert_path, cert)
        return True

    def reissue_certificate(self, username: str, role: str, org_id: Optional[str]) -> bool:
        """Re-issue certificate with new role/org (keeps existing public key)."""
        if not self._admin_private:
            self.load_admin_keys()
        if not self._admin_private:
            return False
        pub_path = self._path(username, "_public.pem")
        pub_pem = load_pem_file(pub_path)
        if not pub_pem:
            return False
        cert_path = self._path(username, "_cert.json")
        payload = certificate_payload(username, role, org_id, pub_pem.decode("utf-8"))
        cert = create_certificate(self._admin_private, payload)
        save_cert_file(cert_path, cert)
        return True

    def remove_certificate(self, username: str) -> bool:
        """Remove user cert and keys (deregister). Returns True if removed."""
        removed = False
        for ext in ("_cert.json", "_private.pem", "_public.pem"):
            path = self._path(username, ext)
            if os.path.isfile(path):
                try:
                    os.remove(path)
                    removed = True
                except OSError:
                    pass
        return removed

    def get_identity(self, username: str) -> Optional[Dict]:
        """
        Load certificate for username, verify with admin public key.
        Returns payload dict (sub, role, org_id, pub, iat, exp) or None.
        """
        cert_path = self._path(username, "_cert.json")
        cert = load_cert_file(cert_path)
        if not cert:
            return None
        admin_pub = self.get_admin_public_pem()
        if not admin_pub:
            return None
        return verify_certificate(admin_pub, cert)

    def verify_identity_with_signature(
        self, username: str, message: bytes, signature_b64: str
    ) -> Optional[Dict]:
        """
        Verify certificate and that signature of message was made by user's private key.
        Returns payload if both checks pass.
        """
        payload = self.get_identity(username)
        if not payload:
            return None
        try:
            pub_pem = payload.get("pub", "").encode("utf-8")
            signature = base64.b64decode(signature_b64)
            if not verify_signature(pub_pem, message, signature):
                return None
            return payload
        except Exception:
            return None

    def list_usernames(self) -> List[str]:
        """List usernames that have a certificate."""
        result = []
        for f in os.listdir(self.certs_dir):
            if f.endswith("_cert.json"):
                result.append(f[: -len("_cert.json")])
        return result
