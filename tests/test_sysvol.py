"""Unit tests for the Registry.pol / GPT.INI parsers (no network needed).

Run:  python tests/test_sysvol.py
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ad_mcp import sysvol  # noqa: E402

FAILURES: list[str] = []
PASSED = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSED
    if cond:
        PASSED += 1
    else:
        FAILURES.append(f"{name}: {detail}")
        print(f"FAIL {name}: {detail}")


# A minimal PREG file built to the layout verified against real SYSVOL files:
#   "PReg" u32 ver, then "[" key NUL name NUL (";" u32)* value ";" "]" ends.
def _rec(key: str, name: str, fields: list[int], value: bytes = b"") -> bytes:
    out = b"[\x00"
    out += key.encode("utf-16-le") + b"\x00\x00"
    out += name.encode("utf-16-le") + b"\x00\x00"
    for f in fields:
        out += b"\x3b\x00" + struct.pack("<I", f)
    out += value
    out += b"\x3b\x00\x5d\x00"  # ';' u16 + ']' u16 terminator
    return out


def _pol(records: list[bytes]) -> bytes:
    return b"PReg" + struct.pack("<I", 1) + b"".join(records)


def test_empty_entries():
    data = _pol([
        _rec(r"Software\Policies\Test", ";", [0, 0]),
        _rec(r"Software\Policies\Test2", ";", [0, 0]),
    ])
    entries = sysvol.parse_pol(data)
    check("empty/count", len(entries) == 2, str(len(entries)))
    if len(entries) == 2:
        check("empty/key", entries[0]["key"] == r"Software\Policies\Test")
        check("empty/vname", entries[0]["value_name"] == "(default)",
              entries[0]["value_name"])
        # value_type 0 => "delete" marker in the summary, but the raw payload
        # decodes to an empty value, not None
        check("empty/value", entries[0]["value"] in (None, ""), repr(entries[0]["value"]))


def test_string_and_dword():
    hello = "hello".encode("utf-16-le") + b"\x00\x00"
    data = _pol([
        _rec(r"Software\Policies\A", "Name", [1, len(hello)], hello),
        _rec(r"Software\Policies\A", "Count", [4, 4], struct.pack("<I", 42)),
    ])
    entries = sysvol.parse_pol(data)
    check("sz/count", len(entries) == 2, str(len(entries)))
    if len(entries) == 2:
        check("sz/value", entries[0]["value"] == "hello", repr(entries[0]["value"]))
        check("sz/type", entries[0]["value_type"] == 1)
        check("dword/value", entries[1]["value"] == 42, repr(entries[1]["value"]))


def test_cert_blob():
    # Type-3 record: SEP+u32(kind) marker then a cert-entry stream:
    # (tag u32, len u32, bytes), with a reserved u32 between entries.
    thumb = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")
    der = b"\x30\x82fake-der-payload"
    value = struct.pack("<II", 1, len(thumb)) + thumb
    value += struct.pack("<I", 0x20)  # reserved
    value += struct.pack("<II", 1, len(der)) + der
    rec = _rec(r"Software\Policies\Microsoft\SystemCertificates"
               r"\TrustedPublisher\Certificates\0123", ";Blob",
               [3, len(value), 3], value)
    entries = sysvol.parse_pol(_pol([rec]))
    check("blob/count", len(entries) == 1, str(len(entries)))
    if entries:
        v = entries[0]["value"]
        check("blob/thumbprint", isinstance(v, dict) and v.get("thumbprint") == thumb.hex(),
              repr(v)[:120])
        if isinstance(v, dict):
            kinds = [e.get("kind", "thumbprint") for e in v.get("entries", [])]
            check("blob/kinds", kinds == ["thumbprint", "certificate_der"], str(kinds))


def test_multi_sz():
    raw = ("alpha\x00beta\x00").encode("utf-16-le")
    data = _pol([_rec(r"Software\Policies\M", "List", [7, len(raw)], raw)])
    entries = sysvol.parse_pol(data)
    check("multisz", entries and entries[0]["value"] == ["alpha", "beta"],
          repr(entries[0]["value"]) if entries else "no entries")


def test_bad_magic():
    try:
        sysvol.parse_pol(b"XXXX" + b"\x00" * 20)
        check("bad_magic", False, "no exception raised")
    except ValueError:
        check("bad_magic", True)


def test_gpt_ini():
    parsed = sysvol.parse_gpt_ini("[General]\nVersion=65536\ndisplayName=X\n")
    check("gpt/major", parsed.get("version_major") == 1, str(parsed))
    check("gpt/minor", parsed.get("version_minor") == 0)
    check("gpt/name", parsed.get("General.displayName") == "X", str(parsed))


if __name__ == "__main__":
    for fn in (test_empty_entries, test_string_and_dword, test_cert_blob,
               test_multi_sz, test_bad_magic, test_gpt_ini):
        fn()
    print(f"{PASSED} checks passed, {len(FAILURES)} failed")
    sys.exit(1 if FAILURES else 0)
