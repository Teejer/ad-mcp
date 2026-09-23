"""Sealed privileged credentials for on-demand escalation.

Use case: the MCP service account (e.g. svc_adMCPService) is intentionally
low-privilege, but some tools occasionally need a higher-privilege bind (to
read ACL-hidden GPO objects, audit group memberships, etc.). An operator
encrypts that account's password once, locally, with an RSA public key, and
pastes the sealed blob into the server config (AD_SEALED_CREDS_FILE). The
private key never lives on the MCP host — it stays wherever the operator
generated the keypair — so anything that compromises this machine or the MCP
traffic cannot recover the password.

Seal format (base64 of JSON):
    {"v": 1, "kid": "<key id>", "u": "<sAMAccountName or UPN>",
     "u_dn": "<optional bind DN>", "c": "<base64 rsa-oaep-sha256(password)>",
     "exp": "<optional ISO expiry>"}

The password is sealed directly with RSA-OAEP(SHA-256). Because a sealed
secret is replayable for as long as the key exists, keep the privileged
account scoped to exactly what the MCP tools do (read / group-write only)
and rotate by re-sealing (and updating AD_SEALED_CREDS_FILE, a hot-reloaded
plain file). The kid lets you rotate keys without invalidating old seals:
public keys are loaded from a directory or a single PEM file
(AD_SEAL_PUBLIC_KEY).

CLI:
    python -m ad_mcp.seal --pubkey seal_pub.pem --user svc_admcp_admin \
        --dn "CN=admcp-admin,OU=...,DC=wei,DC=local"
    # prompts for password, prints the sealed blob to paste into config

    python -m ad_mcp.seal --genkeys seal_pub.pem seal_priv.pem
    # generate a fresh keypair (keep the private key OFF this host)
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SEAL_VERSION = 1


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------


def generate_keypair(private_path: str, public_path: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(private_path).write_bytes(private)
    os.chmod(private_path, 0o600)
    Path(public_path).write_bytes(public)
    os.chmod(public_path, 0o644)


def _key_id(public_key) -> str:
    """Short stable fingerprint of a public key (for kid routing)."""
    import hashlib

    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()[:12]


def load_public_keys(location: str) -> dict[str, Any]:
    """Load {kid: RSAPublicKey} from a PEM file or every *.pem in a dir."""
    out: dict[str, Any] = {}
    path = Path(location)
    files = sorted(path.glob("*.pem")) if path.is_dir() else ([path] if path.is_file() else [])
    for f in files:
        try:
            pub = serialization.load_pem_public_key(f.read_bytes())
        except Exception:
            continue
        out[_key_id(pub)] = pub
    return out


def looks_sealed(secret: str) -> bool:
    """Heuristic: our seals are base64 of a JSON object containing "kid"."""
    try:
        raw = base64.b64decode(secret.encode(), validate=True)
        payload = json.loads(raw)
        return isinstance(payload, dict) and payload.get("v") == SEAL_VERSION and "kid" in payload
    except Exception:
        return False


def load_private_keys(location: str) -> dict[str, Any]:
    """Load {kid: RSAPrivateKey} from a PEM file or every *.pem in a dir.
    Passphrases are not supported; use an unencrypted PEM with 0600 perms."""
    out: dict[str, Any] = {}
    path = Path(location)
    files = sorted(path.glob("*.pem")) if path.is_dir() else ([path] if path.is_file() else [])
    for f in files:
        try:
            key = serialization.load_pem_private_key(f.read_bytes(), password=None)
        except Exception:
            continue
        out[_key_id(key.public_key())] = key
    return out


def default_key_location() -> str:
    """Conventional private-key location on the server host."""
    return str(Path.home() / ".config" / "ad-mcp" / "seal_private.pem")

# ---------------------------------------------------------------------------
# Seal / unseal
# ---------------------------------------------------------------------------

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def seal(password: str, public_key, user: str, dn: str = "", expires_days: int | None = None) -> str:
    """Encrypt a password for a specific public key; returns the portable
    sealed blob (base64). This is the operator-side function."""
    payload = {
        "v": SEAL_VERSION,
        "kid": _key_id(public_key),
        "u": user,
        "u_dn": dn,
        "c": base64.b64encode(public_key.encrypt(password.encode("utf-8"), _OAEP)).decode(),
    }
    if expires_days:
        exp = datetime.fromtimestamp(time.time() + expires_days * 86400, tz=timezone.utc)
        payload["exp"] = exp.isoformat()
    return base64.b64encode(json.dumps(payload).encode()).decode()


@dataclass
class Unsealed:
    username: str
    dn: str
    password: str


class SealError(RuntimeError):
    pass


def unsealed_to_dict(blob: str) -> dict[str, str]:
    try:
        payload = json.loads(base64.b64decode(blob.encode()))
    except Exception as exc:
        raise SealError(f"not a valid sealed blob: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("v") != SEAL_VERSION:
        raise SealError("unsupported seal version")
    return payload


def unseal(blob: str, keys: dict[str, Any]) -> Unsealed:
    """Server-side: decrypt a sealed blob with the matching private key."""
    payload = unsealed_to_dict(blob)
    if "exp" in payload:
        try:
            exp = datetime.fromisoformat(payload["exp"])
            if exp.timestamp() < time.time():
                raise SealError(f"seal expired at {payload['exp']}")
        except ValueError:
            pass
    kid = payload.get("kid")
    if kid not in keys:
        raise SealError(
            f"no private key for seal kid '{kid}'. Configure AD_SEAL_KEY_FILE or "
            "AD_SEAL_KEY_DIR with the private key that matches the public key "
            "this seal was made with."
        )
    try:
        password = keys[kid].decrypt(base64.b64decode(payload["c"]), _OAEP).decode()
    except Exception as exc:  # InvalidTag etc. — wrong key, don't leak detail
        raise SealError("seal could not be decrypted (wrong private key?)") from exc
    return Unsealed(username=payload.get("u", ""), dn=payload.get("u_dn", ""), password=password)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ad-mcp-seal", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkeys", help="generate an RSA keypair (move the PRIVATE half off this host)")
    g.add_argument("public", help="public key PEM to write (give this to the MCP host)")
    g.add_argument("private", help="private key PEM to write (keep OFF the MCP host)")

    s = sub.add_parser("seal", help="seal a password with a public key")
    s.add_argument("--pubkey", required=True, help="public key PEM")
    s.add_argument("--user", required=True, help="sAMAccountName/UPN of the privileged account")
    s.add_argument("--dn", default="", help="optional full bind DN")
    s.add_argument("--expires-days", type=int, default=0, help="optional expiry")
    s.add_argument("--password", default="", help="password (else prompted securely)")

    u = sub.add_parser("unseal", help="test-decrypt a seal (needs the private key)")
    u.add_argument("--key", required=True, help="private key PEM")
    u.add_argument("--seal", required=True, help="sealed blob from `seal`")
    u.add_argument("--show-password", action="store_true", help="print the password too")

    a = ap.parse_args(argv)

    if a.cmd == "genkeys":
        generate_keypair(a.private, a.public)
        print(f"public key:  {a.public}   (give this to the MCP host)")
        print(f"private key: {a.private} (move OFF the MCP host, chmod 600)")
        return 0

    if a.cmd == "seal":
        pub = serialization.load_pem_public_key(Path(a.pubkey).read_bytes())
        pw = a.password or getpass.getpass("password: ")
        print(seal(pw, pub, a.user, a.dn, a.expires_days or None))
        return 0

    if a.cmd == "unseal":
        key = serialization.load_pem_private_key(Path(a.key).read_bytes(), password=None)
        keys = {_key_id(key.public_key()): key}
        out = unseal(a.seal, keys)
        print(f"user: {out.username}\ndn:   {out.dn}")
        if a.show_password:
            print(f"password: {out.password}")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
