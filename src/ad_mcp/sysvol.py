"""SYSVOL reader for Group Policy objects.

GPO *settings* are not in LDAP: they live in the domain's SYSVOL share at
\\\\<domain>\\SYSVOL\\<domain>\\Policies\\<GUID>\\  (GPT.INI, Machine/ and
User/ hives). This module reads those files over SMB with the same service
account used for LDAP, and decodes the two main on-disk formats:

- GptTmpl.inf  : ini-style security policy (rights, security options)
- Registry.pol : binary POL files (policy + preferences; UTF-16 key paths)

Authentication note: the SMB logon name is the user's sAMAccountName, which
may differ from the CN in the bind DN (e.g. CN=adMCPService logs on as
svc_adMCPService). Callers must resolve it from AD first.
"""

from __future__ import annotations

import io
import logging
import struct
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

POL_MAGIC = b"PREG"

# Registry value types (winreg), used as the first ';' field of a pol record
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7


@dataclass
class SysvolCreds:
    server: str          # DNS domain name hosting \\server\SYSVOL, e.g. wei.local
    username: str        # sAMAccountName (NOT the CN)
    password: str
    domain: str          # netBIOS/UPN suffix for NTLM, e.g. wei.local
    base: str            # r"\\server\SYSVOL\<dns-domain>"


class SysvolClient:
    """Lazily-authenticated read-only view over the SYSVOL share."""

    def __init__(self, creds: SysvolCreds | None = None):
        self.creds = creds
        self._registered = False

    def configure(self, creds: SysvolCreds) -> None:
        self.creds = creds
        self._registered = False

    def _ensure_session(self) -> None:
        if not self.creds:
            raise RuntimeError(
                "SYSVOL access not configured: set AD_SYSVOL_USER (sAMAccountName) "
                "or let the server resolve it from AD_BIND_DN, plus a password "
                "(AD_SYSVOL_PASSWORD, defaulting to AD_BIND_PASSWORD)."
            )
        if not self._registered:
            import logging as _logging

            _logging.getLogger("smbclient").setLevel(_logging.WARNING)
            _logging.getLogger("smbprotocol").setLevel(_logging.WARNING)
            from smbclient import register_session

            register_session(
                self.creds.server,
                username=self.creds.username,
                password=self.creds.password,
            )
            self._registered = True

    def _path(self, *parts: str) -> str:
        return "\\".join([self.creds.base, *[p.strip("\\") for p in parts]])

    def is_dir(self, *parts: str) -> bool:
        self._ensure_session()
        from smbclient import path as smbpath

        return smbpath.isdir(self._path(*parts))

    def listdir(self, *parts: str) -> list[str]:
        self._ensure_session()
        from smbclient import listdir

        return sorted(listdir(self._path(*parts)))

    def read_bytes(self, *parts: str) -> bytes:
        self._ensure_session()
        from smbclient import open_file

        try:
            with open_file(self._path(*parts), "rb") as fh:
                return fh.read()
        except OSError as exc:
            # SMB "no such file" (STATUS_OBJECT_NAME_NOT_FOUND) surfaces as a
            # bare OSError on smbprotocol <1.18; normalize it for callers.
            if "0xc0000034" in str(exc) or "No such file" in str(exc):
                raise FileNotFoundError(str(exc)) from exc
            raise

    def read_text(self, *parts: str) -> str:
        raw = self.read_bytes(*parts)
        for enc in ("utf-16", "utf-8", "latin-1"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, UnicodeError):
                continue
        return raw.decode("latin-1", errors="replace")

    def test(self) -> dict[str, Any]:
        """Connect and return the number of policy folders visible."""
        self._ensure_session()
        try:
            dirs = self.listdir("Policies")
            return {"sysvol_base": self.creds.base, "user": self.creds.username,
                    "policy_dirs": len(dirs)}
        except Exception as exc:  # noqa: BLE001 - report as data, not stack
            return {"sysvol_base": self.creds.base, "user": self.creds.username,
                    "error": str(exc)}


# ---------------------------------------------------------------------------
# Registry.pol decoding
# ---------------------------------------------------------------------------


def _read_sz(buf: io.BytesIO) -> str:
    raw = buf.read(2)
    if len(raw) < 2:
        raise ValueError("truncated POL string")
    n = struct.unpack("<H", raw)[0]
    data = buf.read(n)
    if len(data) < n:
        raise ValueError("truncated POL string data")
    return data.decode("utf-16-le", errors="replace").rstrip("\x00")


def parse_pol(data: bytes) -> list[dict[str, Any]]:
    """Decode a Registry.pol blob into entries.

    Record layout (verified against real SYSVOL files): file is "PReg" +
    u32 version, then records of the form::

        "[" key NUL value_name NUL ( ";" u32_tag [u32_len <bytes>] )* "]"

    i.e. ';' (0x3B) separates every field. A simple policy entry carries two
    ";"-fields (value type u32, value size u32) followed by the raw payload
    bytes (NUL-padded to an even length). Entries written by certificate
    policies instead carry triplets (u32 1, u32 len, <bytes>) describing
    cert stores; those are surfaced as {store, entries}.

    Each policy entry: {key, value_name, value, value_type, kind}.
    """
    magic = data[:4]
    # Real GPO files use the "PReg" magic; tolerate case variants.
    if magic.upper() not in (b"PREG",):
        raise ValueError(f"not a PREG file (magic {magic!r})")
    pos = 8  # skip magic + u32 version
    end = len(data)
    out: list[dict[str, Any]] = []

    SEP = 0x3B   # ';' u16 field separator used by the real encoder

    def read_nt(p: int) -> tuple[str, int]:
        """NUL-terminated UTF-16LE string starting at p."""
        q = p
        while q + 1 < end and data[q:q + 2] != b"\x00\x00":
            q += 2
        s = data[p:q].decode("utf-16-le", errors="replace")
        return s, q + 2

    TERM = b"\x3b\x00\x5d\x00"  # the literal ';' ']' u16 pair closing a record

    while pos + 2 <= end:
        marker = data[pos:pos + 2]
        if marker == b"\\\x00":
            # legacy security-descriptor record
            close = data.find(b"]\x00", pos)
            if close == -1:
                break
            pos = close + 2
            continue
        if marker != b"[\x00":
            break  # desync: stop with what we have
        pos += 2
        try:
            key, pos = read_nt(pos)
            value_name, pos = read_nt(pos)
            # The record's body runs until the literal 'SEP ]' terminator
            # pair. This framing is safe: real payloads may contain 0x3b /
            # 0x5d bytes, but the byte-identical 4-byte pair never appears
            # inside them in practice, and every empty record is exactly
            # body(2 zero groups) + terminator.
            term = data.find(TERM, pos)
            body_end = term if term != -1 else end
            body = data[pos:body_end]
            # header: strictly-consumed (SEP u16 + u32) groups
            fields: list[int] = []
            q = 0
            while q + 6 <= len(body):
                (tag,) = struct.unpack_from("<H", body, q)
                if tag != SEP:
                    break
                (v,) = struct.unpack_from("<I", body, q + 2)
                fields.append(v)
                q += 6
            # Trailing non-zero groups after (type, size) are not header
            # fields: for cert-store REG_BINARY records the third group is a
            # blob-kind marker that belongs to the value region. But only
            # drop a marker when the declared payload does NOT fit starting
            # right after the (type, size) groups (otherwise it is a real
            # header field).
            while (len(fields) > 2 and fields[-1] != 0
                   and q + fields[1] > len(body) + 2):
                fields.pop()
                q -= 6
        except (struct.error, IndexError):
            break  # truncated / unparseable record; return what we have
        value_type = fields[0] if fields else None
        size = fields[1] if len(fields) >= 2 else 0
        raw = body[q:q + size] if size else b""
        # For REG_BINARY cert-store records (type 3) the value region opens
        # with a ';' u32 blob-kind marker ahead of the cert-entry stream;
        # consume it so the payload starts on the first (tag, len) pair.
        # Note: odd-size payloads put the payload's last two bytes over the
        # terminator's ';' u16 (u32 low = 0x5D), so only consume a group
        # whose u32 low half is not 0x5D.
        blob_kind = None
        if value_type == REG_BINARY and size:
            while q + 6 <= len(body) + 2:
                (tag,) = struct.unpack_from("<H", body, q)
                if tag != SEP:
                    break
                (v,) = struct.unpack_from("<I", body, q + 2)
                if (v & 0xFFFF) == 0x5D:
                    break
                blob_kind = v
                q += 6
            raw = body[q:q + size] if size else b""
        # value names written by the real encoder look like ';' or ';Blob':
        # the string's NUL terminator absorbs the following field separator.
        if value_name.startswith(";"):
            value_name = value_name[1:]
        value_name = value_name or "(default)"
        out.append({
            "key": key.replace("Machine\\", "").replace("User\\", ""),
            "value_name": value_name,
            "value": _decode_pol_value(raw, value_type),
            "value_type": value_type,
            "kind": {REG_SZ: "string", REG_EXPAND_SZ: "expanding",
                     REG_BINARY: "binary", REG_DWORD: "dword",
                     REG_MULTI_SZ: "multi-string"}.get(
                         value_type, f"type:{value_type}"),
        })
        if term == -1:
            break  # unterminated final record
        pos = term + 4
    return out


def _decode_cert_blob(raw: bytes) -> dict[str, Any]:
    """Decode the cert-entry stream inside a cert-store REG_BINARY value.

    Entries are (tag u32, len u32, <bytes>) pairs, each NUL-padded to an
    even length, with a reserved u32 (observed 0x20) preceding every entry
    after the first. Tags seen in the wild: 1 = SHA-1 thumbprint,
    2 = DER-encoded certificate, 3 = DPAPI-protected blob (private key).
    Decoding is bounded to the declared slice and never overruns it.
    """
    entries: list[dict[str, Any]] = []
    result: dict[str, Any] = {"entries": entries}
    q = 0
    first = True
    while q + 8 <= len(raw):
        if not first:
            # reserved/flags u32 between entries (skip it, value not defined)
            q += 4
        first = False
        if q + 8 > len(raw):
            break
        (tag,) = struct.unpack_from("<I", raw, q)
        (ln,) = struct.unpack_from("<I", raw, q + 4)
        if ln > len(raw) - q - 8 or tag > 0x1000:
            break  # desync: keep what we decoded so far
        q += 8
        data = raw[q:q + ln]
        q += ln
        if ln % 2 == 1 and q < len(raw) and raw[q] == 0:
            q += 1
        entry: dict[str, Any] = {"tag": tag, "length": ln}
        if tag == 1 and ln == 20:
            entry["thumbprint"] = data.hex()
            result.setdefault("thumbprint", data.hex())
        elif data[:2] == b"\x30\x82" or (data[:1] == b"\x30" and ln > 100):
            # DER-encoded certificate (tag numbering is not stable across
            # encoders: recognise it by the ASN.1 SEQUENCE header instead)
            entry["kind"] = "certificate_der"
            result.setdefault("certificate_der", data.hex())
        elif tag == 3:
            entry["kind"] = "dpapi_blob"
            entry["note"] = ("DPAPI-encrypted blob (machine-scoped; decrypts "
                             "only on the target machine)")
        else:
            entry["hex"] = data[:64].hex()
        entries.append(entry)
    return result


def _decode_pol_value(raw: bytes | None, value_type: int | None) -> Any:
    """Decode a Registry.pol payload given its registry value type."""
    if raw is None:
        return None
    if value_type in (REG_SZ, REG_EXPAND_SZ):
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    if value_type == REG_DWORD and len(raw) >= 4:
        return struct.unpack("<I", raw[:4])[0]
    if value_type == REG_MULTI_SZ:
        parts = raw.decode("utf-16-le", errors="replace").split("\x00")
        return [p for p in parts if p][:50]
    if value_type == REG_BINARY:
        decoded = _decode_cert_blob(raw)
        if decoded["entries"]:
            return decoded
    return raw.hex()


# ---------------------------------------------------------------------------
# GPT.INI / security template
# ---------------------------------------------------------------------------


def parse_gpt_ini(text: str) -> dict[str, Any]:
    """[General] Version=NN ; also flags for MachineExt/UserExt presence."""
    out: dict[str, Any] = {}
    section = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif "=" in line:
            k, _, v = line.partition("=")
            out[f"{section}.{k.strip()}" if section else k] = v.strip()
    ver = out.get("General.Version")
    if ver is not None:
        try:
            ver_i = int(ver)
            out["version_sysvol"] = ver_i >> 16
            out["version_ad_expected"] = None  # filled by caller from LDAP
            out["version_major"] = ver_i >> 16
            out["version_minor"] = ver_i & 0xFFFF
        except ValueError:
            pass
    return out


def parse_security_ini(text: str) -> dict[str, dict[str, str]]:
    """Parse GptTmpl.inf (security template) into {section: {key: value}},
    skipping ';' comments and preserving SDDL strings as-is."""
    out: dict[str, dict[str, str]] = {}
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            out.setdefault(section, {})
        elif "=" in line and section:
            k, _, v = line.partition("=")
            out[section][k.strip()] = v.strip()
    return out


# Well-known GptTmpl sections/keys worth surfacing to an LLM caller.
RIGHTS_SECTION = "Privilege Rights"
SECURITY_OPTIONS_SECTION = "Registry Values"

# Common machine-side Registry.pol key prefixes -> friendly category
POLICY_CATEGORIES = [
    ("SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Update", "Windows Update"),
    ("SOFTWARE\\Policies\\Microsoft\\Windows\\Firewall", "Windows Firewall"),
    ("SOFTWARE\\Policies\\Microsoft\\Windows\\GpoMachine", "GPO internals"),
    ("SOFTWARE\\Policies\\Microsoft\\Windows\\System", "System/CSE registration"),
    ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy", "GPO internals"),
    ("SOFTWARE\\Policies\\Microsoft\\Crypto\\RSA", "Ransomware/SAM-Rijndael countermeasure"),
    ("SOFTWARE\\Policies\\Microsoft\\Windows\\LAPS", "LAPS"),
    ("SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog", "Event Log"),
    ("SOFTWARE\\Policies\\Microsoft\\Windows\\Terminal Services", "Remote Desktop"),
    ("SOFTWARE\\Policies\\Microsoft\\SystemCertificates", "Certificate stores (code signing / trust)"),
    ("SYSTEM\\CurrentControlSet", "System service config"),
]
