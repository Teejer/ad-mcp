"""Load configuration from environment variables.

If an OpenCode-style config file (mcp-config.json, {"mcpServers": {..., "env":
{...}}}) exists next to this package and the core AD_* variables are not
already set, its env block is loaded as defaults. Real environment variables
always win, so OpenCode's own `environment` block overrides the file — which
is what makes `{env:AD_BIND_PASSWORD}` substitution work.
"""

from __future__ import annotations

import calendar
import json
import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ldap3 import ALL, BASE, ROUND_ROBIN, SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

_CONFIG_CANDIDATES = [
    Path(__file__).resolve().parent.parent.parent / "mcp-config.json",  # repo root
    Path(__file__).resolve().parent / "mcp-config.json",
]

_PLACEHOLDER_RE = re.compile(r"\{env:([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_placeholders(value: str) -> str:
    """Resolve {env:NAME} markers against the process environment (empty
    string when the named variable is not set)."""

    def repl(m):
        return os.environ.get(m.group(1), "")

    return _PLACEHOLDER_RE.sub(repl, value) if value else value


def _load_config_file_values() -> dict[str, str]:
    """AD_* values from the local mcp-config.json (if present), with
    {env:NAME} markers resolved against the process environment."""
    for path in _CONFIG_CANDIDATES:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text())
            servers = data.get("mcpServers") or data.get("mcp", {}).get("servers") or {}
            for srv in servers.values():
                return {
                    k: _expand_placeholders(str(v))
                    for k, v in (srv.get("env") or {}).items()
                    if k.startswith("AD_")
                }
        except Exception:
            pass
        break
    return {}


def _env(name: str, file_defaults: dict[str, str]) -> str:
    """Resolution order: real environment (placeholders expanded) > local
    mcp-config.json value. Empty/unresolvable means unset."""
    v = _expand_placeholders(os.environ.get(name, "")).strip()
    if not v or re.fullmatch(r"\{env:[A-Za-z_][A-Za-z0-9_]*\}", v):
        v = (file_defaults.get(name) or "").strip()
    return v

DEFAULT_USER_ATTRS = [
    "cn",
    "sAMAccountName",
    "displayName",
    "givenName",
    "sn",
    "mail",
    "userPrincipalName",
    "description",
    "title",
    "department",
    "company",
    "office",
    "telephoneNumber",
    "mobile",
    "manager",
    "memberOf",
    "userAccountControl",
    "pwdLastSet",
    "lastLogonTimestamp",
    "badPasswordTime",
    "badPwdCount",
    "lockoutTime",
    "whenCreated",
    "distinguishedName",
    "objectGUID",
]

DEFAULT_COMPUTER_ATTRS = [
    "cn",
    "dNSHostName",
    "description",
    "operatingSystem",
    "operatingSystemVersion",
    "operatingSystemServicePack",
    "lastLogonTimestamp",
    "whenCreated",
    "userAccountControl",
    "memberOf",
    "managedBy",
    "distinguishedName",
    "objectGUID",
]

DEFAULT_GROUP_ATTRS = [
    "cn",
    "sAMAccountName",
    "description",
    "groupType",
    "member",
    "memberOf",
    "whenCreated",
    "distinguishedName",
    "objectGUID",
]

# userAccountControl flag bits worth surfacing
UAC_FLAGS = {
    0x0002: "ACCOUNTDISABLE",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0800: "DONT_EXPIRE_PASSWORD",
    0x1000: "MNS_LOGON_ACCOUNT",
    0x2000: "SMARTCARD_REQUIRED",
    0x4000: "TRUSTED_FOR_DELEGATION",
    0x8000: "NOT_DELEGATED",
    0x20000: "DONT_REQ_PREAUTH",
    0x40000: "PASSWORD_EXPIRED",
    0x80000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x0200000: "PARTIAL_SECRETS_GROUP",
    0x0400000: "DONT_TRUST_AUTH_FOR_DELEGATION",
}

GROUP_TYPE_FLAGS = {
    0x00000001: "SYSTEM",
    0x00000002: "GLOBAL",
    0x00000004: "DOMAIN_LOCAL",
    0x00000008: "UNIVERSAL",
    0x00000010: "APP_BASIC",
    0x00000020: "APP_QUERY",
    0x80000000: "SECURITY",
}

# Well-known privileged groups that write operations refuse to touch,
# and which get_privileged_groups reports on.
PROTECTED_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "backup operators",
    "server operators",
    "print operators",
    "account operators",
    "cert publishers",
    "dnsadmins",
    "organization management",
    "protected users",
    "hyper-v administrators",
    "rdcstrongusers",
    "administrative accounts",
}


@dataclass
class Config:
    hosts: list[str]
    port: int
    use_ssl: bool
    bind_dn: str
    bind_password: str
    base_dn: str
    allow_self_signed: bool = True
    ca_certs_file: str = ""
    page_size: int = 200
    max_results: int = 100
    search_timeout: int = 30
    allow_writes: bool = False
    write_whitelist_ous: list[str] = field(default_factory=list)
    protected_groups: set[str] = field(default_factory=lambda: set(PROTECTED_GROUPS))
    sysvol_enabled: bool = True
    sysvol_user: str = ""     # sAMAccountName override (CN may differ)
    sysvol_password: str = ""
    # privileged escalation (see seal.py). Values may be {file:path} or
    # {env:VAR} references; they are resolved lazily so rotation does not
    # require a server restart (the privileged bind is short-lived).
    priv_dn: str = ""
    priv_seal: str = ""       # sealed blob OR plaintext password (discouraged)
    priv_seal_format: str = "auto"  # auto | sealed | plain
    seal_key_file: str = ""
    seal_key_dir: str = ""


def _resolve_secret(value: str) -> str:
    """Expand {file:/path}, {env:VAR} and {plain:text} references. Anything
    else is returned as-is (treated as a literal secret, e.g. the main bind
    password, which is how the server has always worked).

    {file:...} paths support $VAR / ${VAR} expansion (from the process
    environment) plus ~. This makes systemd credentials portable:
    AD_PRIV_SEAL={file:$CREDENTIALS_DIRECTORY/adpriv} — systemd sets
    CREDENTIALS_DIRECTORY per unit, and a systemd-run child inherits it
    (including when spawned as an MCP stdio server)."""
    if not value:
        return value
    m = re.fullmatch(r"\{(file|env|plain):(.*)\}", value.strip(), re.DOTALL)
    if not m:
        return value
    kind, arg = m.group(1), m.group(2).strip()
    if kind == "file":
        path = os.path.expandvars(arg)
        if "$" in path:  # unmatched $VAR -> treat as unset secret
            return ""
        try:
            return Path(path).expanduser().read_text().strip()
        except OSError:
            return ""
    if kind == "env":
        return os.environ.get(arg, "")
    return arg


def load_config() -> Config:
    fd = _load_config_file_values()

    def env(name: str) -> str:
        """Plain (non-secret) values: the *real* environment wins over the
        config file when it carries a usable value; an empty or unexpanded
        OpenCode placeholder ({env:X} that resolved to nothing) falls back to
        the file."""
        v = _expand_placeholders(os.environ.get(name, "")).strip()
        if v and not re.fullmatch(r"\{env:[A-Za-z_][A-Za-z0-9_]*\}", v):
            return v
        return (fd.get(name) or "").strip()

    def env_secret(name: str) -> str:
        """env() plus final secret resolution. Resolution order:
        1. real environment value (if a live secret/reference)
        2. config-file value (if a live secret/reference)
        3. the raw env value as a last resort
        This keeps per-session overrides winning over mcp-config.json while
        letting the file supply secrets the environment does not carry."""
        def live(v: str) -> bool:
            if not v:
                return False
            if re.fullmatch(r"\{file:.*\}|\{plain:.*\}", v) or \
               re.fullmatch(r"\{env:[A-Za-z_][A-Za-z0-9_]*\}", v):
                return bool(_resolve_secret(v))
            return True

        v = env(name)  # already env-var-first, file fallback for empties
        if live(v):
            return _resolve_secret(v) if v else ""
        fv = (fd.get(name) or "").strip()
        if live(fv):
            return _resolve_secret(fv)
        return _resolve_secret(v)

    def env_bool(name: str, default: bool) -> bool:
        v = env(name)
        if not v:
            return default
        return v.lower() in {"1", "true", "yes", "on"}

    hosts = [h.strip() for h in re.split(r"[,; ]+", env("AD_HOSTS")) if h.strip()]
    required = {
        "AD_HOSTS": "DC host(s)",
        "AD_BIND_DN": "service account DN",
        "AD_BIND_PASSWORD": "service account password",
        "AD_BASE_DN": "search base DN",
    }
    missing = [k for k in required if not env(k)]
    if missing:
        raise RuntimeError(
            "Missing required configuration: " + ", ".join(missing)
            + ". Set them in the environment or in mcp-config.json (see README.md)."
        )

    # AD_PORT default follows the *effective* SSL setting: an explicit
    # AD_USE_SSL wins over the file's port, so derive the default after SSL.
    use_ssl = env_bool("AD_USE_SSL", False)
    port = int(env("AD_PORT") or ("636" if use_ssl else "389"))

    return Config(
        hosts=hosts,
        port=port,
        use_ssl=use_ssl,
        bind_dn=env("AD_BIND_DN"),
        bind_password=env_secret("AD_BIND_PASSWORD"),
        base_dn=env("AD_BASE_DN"),
        allow_self_signed=env_bool("AD_ALLOW_SELF_SIGNED", True),
        ca_certs_file=env("AD_CA_CERTS_FILE"),
        page_size=int(env("AD_PAGE_SIZE") or "200"),
        max_results=int(env("AD_MAX_RESULTS") or "100"),
        search_timeout=int(env("AD_SEARCH_TIMEOUT") or "30"),
        allow_writes=env_bool("AD_ALLOW_WRITES", False),
        write_whitelist_ous=[ou.strip() for ou in env("AD_WRITE_OUS").split(",") if ou.strip()],
        sysvol_enabled=env_bool("AD_SYSVOL", True),
        sysvol_user=env("AD_SYSVOL_USER"),
        sysvol_password=env_secret("AD_SYSVOL_PASSWORD") or env_secret("AD_BIND_PASSWORD"),
        priv_dn=env("AD_PRIV_DN"),
        # resolved lazily at escalation time (_resolve_priv_creds): the
        # {file:$CREDENTIALS_DIRECTORY/...} reference must keep its form here
        # because CREDENTIALS_DIRECTORY only exists in the systemd-spawned
        # process environment, not at config load in other contexts.
        priv_seal=env("AD_PRIV_SEAL"),
        priv_seal_format=(env("AD_PRIV_SEAL_FORMAT") or "auto"),
        seal_key_file=env("AD_SEAL_KEY_FILE"),
        seal_key_dir=env("AD_SEAL_KEY_DIR"),
    )


# ---------------------------------------------------------------------------
# Helpers (pure, unit-testable)
# ---------------------------------------------------------------------------


def _cn_of(dn: str) -> str:
    try:
        parsed = parse_dn(dn.strip())
        if parsed:
            return parsed[0][1]
    except Exception:
        pass
    return dn


def _is_dn(text: str) -> bool:
    """True if every RDN uses a DN attribute type (CN/OU/DC), not just any
    text that parse_dn can split (e.g. 'john.doe, Engineering')."""
    try:
        parsed = parse_dn(text.strip())
    except Exception:
        return False
    return bool(parsed) and all(
        r[0].strip().upper() in {"CN", "OU", "DC"} and r[1].strip() for r in parsed
    )


def _normalize_dn(dn: str) -> str:
    """Lowercase + strip spaces for comparison (not RFC-exact, good enough)."""
    return dn.lower().replace(" ", "")


def _sanitize(term: str) -> str:
    return escape_filter_chars(term.strip())


def _uac_decoded(value) -> dict[str, Any]:
    try:
        uac = int(value)
    except (TypeError, ValueError):
        return {}
    flags = [name for bit, name in UAC_FLAGS.items() if uac & bit]
    return {
        "value": uac,
        "flags": flags,
        "enabled": not bool(uac & 0x0002),
        "password_never_expires": bool(uac & 0x0800),
        "locked": bool(uac & 0x0010),
    }


def _group_type_decoded(value) -> dict[str, Any]:
    try:
        gt = int(value)
    except (TypeError, ValueError):
        return {}
    gt &= 0xFFFFFFFF  # groupType is a signed 32-bit bitmask (MS-ADTS 3.1.1.5.3)
    # 0x2 global, 0x4 domain-local, 0x8 universal; 0x80000000 = security,
    # otherwise distribution.
    if gt & 0x4:
        scope = "DOMAIN_LOCAL"
    elif gt & 0x2:
        scope = "GLOBAL"
    elif gt & 0x8:
        scope = "UNIVERSAL"
    else:
        scope = "UNKNOWN"
    flags = [name for bit, name in GROUP_TYPE_FLAGS.items() if gt & bit]
    return {
        "value": gt,
        "flags": flags,
        "scope": scope,
        "security": bool(gt & 0x80000000),
    }


def _ad_timestamp(value) -> str | None:
    """Convert AD lastLogonTimestamp/pwdLastSet values to ISO-8601 UTC.

    Handles datetime objects, ISO strings, and raw FILETIME integers
    (100-ns intervals since 1601-01-01). Zero/epoch means 'never'.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return None if value.year <= 1601 else value.isoformat()
    s = str(value).strip()
    if not s:
        return None
    if not s.isdigit():
        try:
            dt = datetime.fromisoformat(s)
            return None if dt.year <= 1601 else dt.isoformat()
        except ValueError:
            return None
    try:
        ts = int(s)
    except ValueError:
        return None
    if ts <= 0:
        return None
    unix_seconds = ts / 10_000_000 - 11644473600
    if unix_seconds <= 0:
        return None
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).isoformat()


def _filetime_days_ago(days: int) -> int:
    """Windows FILETIME value for `days` days before now."""
    now_unix = calendar.timegm(datetime.now(timezone.utc).utctimetuple())
    return int((now_unix - days * 86400 + 11644473600) * 10_000_000)


def _validate_dn(dn: str, base_dn: str, cfg: Config, for_write: bool = False) -> str:
    """Ensure dn is inside the configured base (and write whitelist if enabled).

    Returns the dn. Raises ValueError on violations.
    """
    dn = dn.strip()
    if any(c in dn for c in "\x00\r\n"):
        raise ValueError("Invalid characters in DN")
    try:
        parse_dn(dn)
    except Exception:
        raise ValueError(f"Malformed distinguished name: {dn}")
    norm, base = _normalize_dn(dn), _normalize_dn(base_dn)
    suffix = base.lstrip(",")
    if not (norm == base or norm.endswith("," + suffix)):
        raise ValueError(f"DN '{dn}' is not under the configured base '{base_dn}'")
    if for_write and cfg.write_whitelist_ous:
        if not any(norm == _normalize_dn(ou) or norm.endswith("," + _normalize_dn(ou).lstrip(","))
                   for ou in cfg.write_whitelist_ous):
            raise ValueError(f"DN '{dn}' is not inside a whitelisted write OU (AD_WRITE_OUS)")
    return dn


# ---------------------------------------------------------------------------
# LDAP layer
# ---------------------------------------------------------------------------


class _PrivContext:
    """Context manager: read-only connection as the privileged account.

    The elevated bind exists only inside the `with` block; the password is
    decrypted per-use (never cached) so seal/key rotation takes effect on the
    next call without restarting the server."""

    def __init__(self, client: "ADClient", creds: tuple[str, str] | None = None):
        self.client = client
        self.creds = creds
        self.conn: Connection | None = None

    def __enter__(self) -> Connection:
        creds = self.creds or self.client._resolve_priv_creds()
        self.conn = self.client._bind(self.client._pool_target(), read_only=True, creds=creds)
        return self.conn

    def __exit__(self, *exc) -> bool:
        if self.conn is not None:
            # unbind() can block behind an unread pending response; drop the
            # socket directly, a dedicated connection has no further owner.
            try:
                self.conn.close_socket(None)
            except Exception:
                pass
            self.conn = None
        return False


class ADClient:
    """Thin wrapper around ldap3 with server pooling, paging and result caps.

    Two connections share one server pool:
    - read connection: read_only=True, so even a bug (or a privileged bind
      account) can never issue a write through it.
    - write connection: created only when AD_ALLOW_WRITES=true.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._read_conn: Connection | None = None
        self._write_conn: Connection | None = None

    def _make_tls(self):
        if not self.cfg.use_ssl:
            return None
        import ssl as _ssl

        if self.cfg.allow_self_signed:
            # ldap3's Tls does not accept an SSLContext; use its native knobs.
            # validate=CERT_NONE disables hostname checking too (self-signed or
            # non-DC certs). Prefer CA-backed validation with AD certificates.
            return Tls(validate=_ssl.CERT_NONE)
        return Tls(
            validate=_ssl.CERT_REQUIRED,
            ca_certs_file=self.cfg.ca_certs_file or None,
        )

    def _pool_target(self):
        tls = self._make_tls()
        servers = [
            Server(host, port=self.cfg.port, use_ssl=self.cfg.use_ssl, get_info=None, tls=tls)
            for host in self.cfg.hosts
        ]
        return servers[0] if len(servers) == 1 else ServerPool(servers, pool_strategy=ROUND_ROBIN)

    def _bind(self, target, read_only: bool, creds: tuple[str, str] | None = None) -> Connection:
        user, password = creds if creds else (self.cfg.bind_dn, self.cfg.bind_password)
        conn = Connection(
            target,
            user=user,
            password=password,
            auto_range=True,  # AD returns >1500-valued attrs in chunks; ldap3 reassembles
            receive_timeout=self.cfg.search_timeout,
            lazy=False,
            read_only=read_only,
            # AD referrals point at hostnames resolvable only via DC DNS;
            # following them from a workstation crashes inside getaddrinfo.
            # Surface the referral as an error instead.
            auto_referrals=False,
        )
        if not conn.bind():
            err = conn.result.get("description", "unknown error")
            # A failed bind can leave unread bytes in the socket; unbind()
            # would block behind them (up to receive_timeout, or forever
            # against some servers). Drop the socket directly instead.
            try:
                conn.close_socket(None)
            except Exception:
                pass
            raise RuntimeError(f"LDAP bind failed for '{user}': {err}")
        return conn

    def priv_connection(self, creds: tuple[str, str] | None = None):
        """Short-lived, read-only connection as the privileged account.

        Use as a context manager: the bind is made on entry and unbound on
        exit, so the elevated session never lingers. Credentials come from
        AD_PRIV_DN + AD_PRIV_SEAL (sealed, decrypted with the private key at
        AD_SEAL_KEY_FILE) or any {file:}/{env:} secret reference, unless
        explicit ``creds`` are supplied by an already-authorised caller.
        """
        return _PrivContext(self, creds)

    def _resolve_priv_creds(self) -> tuple[str, str]:
        from . import seal as _seal

        dn = _resolve_secret(self.cfg.priv_dn)
        secret = _resolve_secret(self.cfg.priv_seal)
        if not dn or not secret:
            # A {file:}/{env:}-style AD_PRIV_SEAL whose source is absent is the
            # normal state when no privileged account is wired up yet, so this
            # must read as 'not configured', never as a credential error.
            raise PermissionError(
                "Privileged context not configured. Set AD_PRIV_DN and "
                "AD_PRIV_SEAL (sealed with 'ad-mcp-seal seal', or a systemd "
                "credential like {file:$CREDENTIALS_DIRECTORY/adpriv}). "
                "If a credential was expected, check that the unit has "
                "LoadCredential=adpriv:... and the file exists. See README.md."
            )
        fmt = self.cfg.priv_seal_format
        if fmt == "auto":
            fmt = "sealed" if _seal.looks_sealed(secret) else "plain"
        if fmt == "sealed":
            loc = self.cfg.seal_key_file or self.cfg.seal_key_dir or _seal.default_key_location()
            keys = _seal.load_private_keys(loc)
            if not keys:
                raise PermissionError(
                    f"no private keys loaded from '{loc}'. Set AD_SEAL_KEY_FILE "
                    "(or AD_SEAL_KEY_DIR) to the key matching the seal."
                )
            out = _seal.unseal(secret, keys)
            # DN wins over the seal's dn field (both are operator data)
            return dn, out.password
        return dn, secret

    def connect(self) -> Connection:
        """Read-only connection (created/rebound as needed)."""
        if self._read_conn is not None:
            try:
                if self._read_conn.bound:
                    return self._read_conn
            except Exception:
                self._read_conn = None
        self._read_conn = self._bind(self._pool_target(), read_only=True)
        return self._read_conn

    def write_conn(self) -> Connection:
        if not self.cfg.allow_writes:
            raise PermissionError("Write operations are disabled. Set AD_ALLOW_WRITES=true to enable.")
        if self._write_conn is not None:
            try:
                if self._write_conn.bound:
                    return self._write_conn
            except Exception:
                self._write_conn = None
        self._write_conn = self._bind(self._pool_target(), read_only=False)
        return self._write_conn

    def close(self, force: bool = False) -> None:
        # Unbinding a live connection whose DC socket has a pending response
        # blocks in recv() for up to receive_timeout (the Samba container
        # doesn't answer an unbind with unread data pending); that stall would
        # freeze the whole MCP session. When not forced (i.e. called from an
        # error path in a tool), only close connections whose server pool is
        # idle. The real disconnect happens at process exit or on explicit
        # rebuild.
        for attr in ("_read_conn", "_write_conn"):
            conn = getattr(self, attr, None)
            if conn is None:
                continue
            if not force:
                try:
                    if conn.sock is not None:
                        import select
                        r, _, _ = select.select([conn.sock], [], [], 0)
                        if r and conn.bound:
                            # unread response waiting: unbind() would block
                            conn.close_socket(None)
                            setattr(self, attr, None)
                            continue
                except Exception:
                    pass
            try:
                conn.unbind()
            except Exception:
                try:
                    conn.close_socket(None)
                except Exception:
                    pass
            setattr(self, attr, None)

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str] | str = ALL,
        scope=SUBTREE,
        size_limit: int | None = None,
    ) -> list[dict[str, Any]]:
        conn = self.connect()
        limit = min(size_limit or self.cfg.max_results, self.cfg.max_results)
        kwargs: dict[str, Any] = dict(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=scope,
            attributes=attributes,
        )

        def do_search(**extra) -> None:
            # Paged results only for SUBTREE/LEVEL (AD rejects the paged
            # control with BASE scope). Referrals are not followed
            # (auto_referrals=False): capture the referral and report it as a
            # helpful error instead of returning empty results.
            if self.cfg.page_size and scope != BASE:
                conn.search(size_limit=limit, **extra, **kwargs)
            else:
                conn.search(size_limit=limit, **extra, **kwargs)

        do_search(paged_size=min(self.cfg.page_size, limit)) if (self.cfg.page_size and scope != BASE) else do_search()
        result = conn.result
        if result.get("result") == 10:  # referral
            points = ", ".join(result.get("referrals") or []) or "unknown"
            raise RuntimeError(
                f"LDAP referral for base '{search_base}': this base is not held by the "
                f"connected naming context (refers to: {points}). Check AD_BASE_DN "
                "against the domain's defaultNamingContext (run test_connection to "
                "see the server's NC list)."
            )
        cookie = conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
        while cookie and len(conn.response) < limit:
            remaining = limit - len(conn.response)
            conn.search(
                size_limit=limit,
                paged_size=min(self.cfg.page_size, remaining),
                paged_cookie=cookie,
                **kwargs,
            )
            cookie = (
                conn.result.get("controls", {})
                .get("1.2.840.113556.1.4.319", {})
                .get("value", {})
                .get("cookie")
            )
        result = conn.result
        if result.get("result") != 0:
            raise RuntimeError(
                f"LDAP search failed ({result.get('description', 'error')}): base={search_base}"
            )
        return [e for e in conn.response if e.get("type") == "searchResEntry"][:limit]

    def get_entry(self, dn: str, attributes: list[str] | str = ALL) -> dict[str, Any] | None:
        entries = self.search(dn, "(objectClass=*)", attributes=attributes, scope=BASE, size_limit=1)
        return entries[0] if entries else None

    def modify_members(self, dn: str, add: list[str] | None = None, delete: list[str] | None = None) -> None:
        if not self.cfg.allow_writes:
            raise PermissionError("Write operations are disabled. Set AD_ALLOW_WRITES=true to enable.")
        # ldap3 format: {attribute: [(operation, [values]), ...]}
        # operation: 0=add, 1=delete
        changes: dict[str, list[tuple[int, list[str]]]] = {}
        if add:
            changes["member"] = [(0, add)]
        if delete:
            changes.setdefault("member", []).append((1, delete))
        if not changes:
            return
        conn = self.write_conn()
        if not conn.modify(dn, changes):
            raise RuntimeError(
                f"Modify failed on {dn}: {conn.result.get('description')} (code {conn.result.get('message')})"
            )


def _attrs(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize an ldap3 searchResEntry's attributes.

    Single-valued attributes are returned as scalars, multi-valued
    (memberOf, member, objectClass, servicePrincipalName, ...) as lists.
    """
    out: dict[str, Any] = {}
    for k, v in entry.get("attributes", {}).items():
        if isinstance(v, list):
            vals = [x.isoformat() if isinstance(x, datetime) else str(x) for x in v]
            out[k] = vals[0] if len(vals) == 1 and k not in MULTI_VALUED else (vals if vals else None)
        elif isinstance(v, bytes):
            out[k] = v.decode("utf-8", errors="replace")
        elif isinstance(v, datetime):
            out[k] = v.isoformat()
        elif v is not None:
            out[k] = str(v)
    return out


MULTI_VALUED = {
    "memberOf",
    "member",
    "objectClass",
    "servicePrincipalName",
    "msDS-PrincipalName",
}


def _get(a: dict[str, Any], key: str):
    """Read an attribute as a scalar (or None)."""
    v = a.get(key)
    if isinstance(v, list):
        return v[0] if len(v) == 1 else v
    return v


def _guid(entry: dict[str, Any]) -> str | None:
    try:
        raw = entry["raw_attributes"]["objectGUID"][0]
        if isinstance(raw, bytes):
            import uuid

            return str(uuid.UUID(bytes_le=raw))
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------------

# (unused inline filters kept local to each tool)
COMPUTER_BASE_FILTER = "(&(objectClass=computer)"
GROUP_BASE_FILTER = "(&(objectClass=group)"
USER_BASE_FILTER = "(&(objectClass=user)(objectCategory=person)"


def _resolve_entry(client: ADClient, cfg: Config, identity: str, base_filter: str, attrs: list[str]) -> dict[str, Any]:
    """Resolve one entry by exact DN, or by sAMAccountName (+ dNSHostName for
    computers)."""
    ident = identity.strip()
    if _is_dn(ident):
        entry = client.get_entry(ident, attrs)
        if entry is None:
            raise ValueError(f"No entry found at DN '{ident}'")
        return entry
    if "computer" in base_filter:
        name = ident[:-1] if ident.endswith("$") else ident
        n = _sanitize(name)
        flt = (
            base_filter
            + f"(|(sAMAccountName={n})(sAMAccountName={n}$)"
            + f"(dNSHostName={n})(dNSHostName={n}.*)"
            + f"(cn={n})))"
        )
    else:
        flt = base_filter + f"(sAMAccountName={_sanitize(ident)}))"
    entries = client.search(cfg.base_dn, flt, attrs, size_limit=2)
    if not entries:
        raise ValueError(f"No entry found matching '{ident}'")
    if len(entries) > 1:
        names = [_get(_attrs(e), "sAMAccountName") or _cn_of(e["dn"]) for e in entries]
        raise ValueError(f"Ambiguous '{ident}' matches {names}; pass a full DN instead")
    return entries[0]


def _resolve_user(client: ADClient, cfg: Config, identity: str) -> dict[str, Any]:
    ident = identity.strip()
    if _is_dn(ident):
        entry = client.get_entry(ident, DEFAULT_USER_ATTRS)
        if entry is None:
            raise ValueError(f"No entry found at DN '{ident}'")
        return entry
    flt = (
        "(&(objectClass=user)(objectCategory=person)(|"
        f"(sAMAccountName={_sanitize(ident)})(userPrincipalName={_sanitize(ident)})(mail={_sanitize(ident)})))"
    )
    entries = client.search(cfg.base_dn, flt, DEFAULT_USER_ATTRS, size_limit=2)
    if not entries:
        raise ValueError(f"No user found for '{identity}'")
    if len(entries) > 1:
        names = [_get(_attrs(e), "sAMAccountName") or _cn_of(e["dn"]) for e in entries]
        raise ValueError(f"Ambiguous '{identity}' matches {names}; pass a full DN instead")
    return entries[0]


def _expand_members(client: ADClient, dns: list[str], via: str, cap: int) -> list[dict[str, Any]] | dict[str, Any]:
    """Breadth-first nested group expansion over member DNs."""
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    frontier: list[tuple[str, str]] = [(dn, via) for dn in dns]
    while frontier and len(result) < cap:
        dn, source = frontier.pop(0)
        key = _normalize_dn(dn)
        if key in seen:
            continue
        seen.add(key)
        entry = client.get_entry(dn, ["cn", "sAMAccountName", "objectClass", "member"])
        if entry is None:
            result.append({"dn": dn, "name": _cn_of(dn), "via": source, "is_group": None})
            continue
        a = _attrs(entry)
        is_group = "group" in [c.lower() for c in a.get("objectClass", [])]
        result.append({
            "dn": entry["dn"],
            "name": _get(a, "cn") or _cn_of(dn),
            "sam_account_name": a.get("sAMAccountName"),
            "via": source,
            "is_group": is_group,
        })
        if is_group:
            for sub in a.get("member", []):
                if _normalize_dn(sub) not in seen:
                    frontier.append((sub, _get(a, "cn") or _cn_of(dn)))
    return result


def _user_summary(entry: dict[str, Any]) -> dict[str, Any]:
    a = _attrs(entry)
    uac = _uac_decoded(_get(a, "userAccountControl"))
    return {
        "dn": entry["dn"],
        "sam_account_name": _get(a, "sAMAccountName"),
        "display_name": _get(a, "displayName") or _get(a, "cn"),
        "mail": _get(a, "mail"),
        "upn": _get(a, "userPrincipalName"),
        "enabled": uac.get("enabled"),
        "department": _get(a, "department"),
        "title": _get(a, "title"),
        "last_logon": _ad_timestamp(_get(a, "lastLogonTimestamp")),
    }


def _group_summary(entry: dict[str, Any]) -> dict[str, Any]:
    a = _attrs(entry)
    members = a.get("member") or []
    return {
        "dn": entry["dn"],
        "sam_account_name": _get(a, "sAMAccountName"),
        "cn": _get(a, "cn"),
        "description": _get(a, "description"),
        "type": _group_type_decoded(_get(a, "groupType")),
        "member_count": len(members),
    }


def _computer_summary(entry: dict[str, Any]) -> dict[str, Any]:
    a = _attrs(entry)
    uac = _uac_decoded(_get(a, "userAccountControl"))
    return {
        "dn": entry["dn"],
        "name": _get(a, "dNSHostName") or _get(a, "cn"),
        "operating_system": _get(a, "operatingSystem"),
        "os_version": _get(a, "operatingSystemVersion"),
        "enabled": uac.get("enabled"),
        "last_logon": _ad_timestamp(_get(a, "lastLogonTimestamp")),
    }


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

from mcp.server.fastmcp import FastMCP  # noqa: E402

cfg = load_config()
client = ADClient(cfg)

mcp = FastMCP(
    name="ad-mcp",
    instructions=(
        f"Active Directory query server over LDAP. Base DN: {cfg.base_dn}. "
        f"Max results per query: {cfg.max_results}. "
        f"Writes: {'ENABLED (guarded)' if cfg.allow_writes else 'DISABLED'}.\n"
        "Use the specific tools (search_users, get_user, get_group_members, ...) "
        "in preference to raw_ldap_search. Times are ISO-8601 UTC; lastLogon "
        "values are replicated approximately (lastLogonTimestamp), so 'never' "
        "or coarse age is expected for idle accounts."
    ),
)




def _wrap(fn):
    """Turn exceptions into readable tool results instead of stack traces.

    Sync on purpose: the MCP SDK runs sync tools in its own worker pool, and a
    hand-rolled async wrapper here produced un-awaited coroutines and hung
    sessions. Keep this a plain function.
    """
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ValueError as e:
            return {"error": f"Input error: {e}"}
        except PermissionError as e:
            return {"error": f"Not allowed: {e}"}
        except LDAPException as e:
            _conn_safe_reset()
            return {"error": f"LDAP error: {e}"}
        except Exception as e:  # noqa: BLE001
            # never tear down the shared read connection from an error path:
            # unbind() can block behind an unread pending response and would
            # also kill a connection another in-flight request depends on.
            return {"error": f"{type(e).__name__}: {e}"}

    return wrapper


def _conn_safe_reset() -> None:
    """Drop the shared read connection after a connection-level failure
    without blocking: unbind() can stall behind an unread pending response,
    so prefer a raw socket close here."""
    conn = getattr(client, "_read_conn", None)
    if conn is not None:
        try:
            conn.close_socket(None)
        except Exception:
            pass
        client._read_conn = None


@mcp.tool()
@_wrap
def test_connection() -> dict[str, Any]:
    """Check LDAP connectivity and report the configured base entry.

    Also reads the rootDSE namingContexts. If AD_BASE_DN is not among them
    (e.g. a typo, or a domain you are not the right naming context for), the
    result includes a warning with the actual naming contexts so you can fix
    the configuration.
    """
    conn = client.connect()
    try:
        root = client.get_entry(cfg.base_dn, ["dnsRoot", "whenCreated", "objectClass"])
    except RuntimeError:
        root = None  # e.g. referral when base DN is wrong; the warning below explains

    # rootDSE probe (BASE search on "" never triggers referrals)
    conn.search("", "(objectClass=*)", search_scope=BASE,
                attributes=["defaultNamingContext", "namingContexts", "dnsHostName", "serverName"])
    rds = conn.response[0]["attributes"] if conn.response else {}
    ncs = rds.get("namingContexts") or []
    if isinstance(ncs, str):
        ncs = [ncs]

    def scalar(v):
        return v[0] if isinstance(v, list) and len(v) == 1 else v

    base_norm = _normalize_dn(cfg.base_dn)
    matches = any(_normalize_dn(nc) == base_norm for nc in ncs)
    out = {
        "connected": True,
        "hosts": cfg.hosts,
        "port": cfg.port,
        "ssl": cfg.use_ssl,
        "base_dn": cfg.base_dn,
        "base_entry": _attrs(root) if root else None,
        "writes_enabled": cfg.allow_writes,
        "server": scalar(rds.get("dnsHostName") or rds.get("serverName")),
        "default_naming_context": scalar(rds.get("defaultNamingContext")),
        "naming_contexts": [str(nc) for nc in ncs],
    }
    if not matches and ncs:
        out["warning"] = (
            f"AD_BASE_DN '{cfg.base_dn}' is not one of the server's naming contexts "
            f"({', '.join(ncs)}). Searches under this base will fail with a referral. "
            "Fix AD_BASE_DN (case/typo) or point AD_HOSTS at a DC for that domain."
        )
    return out


@mcp.tool()
@_wrap
def search_users(
    query: str | None = None,
    department: str | None = None,
    title: str | None = None,
    enabled: bool | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Search AD users. `query` is a substring match on name, sAMAccountName,
    mail or UPN. Optionally filter by exact department/title and enabled state."""
    conds = ["(objectClass=user)", "(objectCategory=person)"]
    if query:
        q = _sanitize(query)
        conds.append(
            f"(|(cn=*{q}*)(displayName=*{q}*)(sAMAccountName=*{q}*)"
            f"(mail=*{q}*)(givenName=*{q}*)(sn=*{q}*))"
        )
    if department:
        conds.append(f"(department={_sanitize(department)})")
    if title:
        conds.append(f"(title={_sanitize(title)})")
    if enabled is True:
        conds.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
    elif enabled is False:
        conds.append("(userAccountControl:1.2.840.113556.1.4.803:=2)")
    flt = "(&" + "".join(conds) + ")"
    return [_user_summary(e) for e in client.search(cfg.base_dn, flt, DEFAULT_USER_ATTRS, size_limit=limit)]


@mcp.tool()
@_wrap
def get_user(identity: str) -> dict[str, Any]:
    """Full details for one user by sAMAccountName, UPN, email, or DN.

    Includes decoded account flags, direct group memberships, last logon and
    password-last-set times."""
    entry = _resolve_user(client, cfg, identity)
    a = _attrs(entry)
    return {
        "dn": entry["dn"],
        "guid": _guid(entry),
        "sam_account_name": _get(a, "sAMAccountName"),
        "display_name": _get(a, "displayName"),
        "first_name": _get(a, "givenName"),
        "last_name": _get(a, "sn"),
        "mail": _get(a, "mail"),
        "upn": _get(a, "userPrincipalName"),
        "description": _get(a, "description"),
        "title": _get(a, "title"),
        "department": _get(a, "department"),
        "company": _get(a, "company"),
        "office": _get(a, "office"),
        "phone": _get(a, "telephoneNumber"),
        "mobile": _get(a, "mobile"),
        "manager": _get(a, "manager"),
        "account": _uac_decoded(_get(a, "userAccountControl")),
        "when_created": _get(a, "whenCreated"),
        "last_logon": _ad_timestamp(_get(a, "lastLogonTimestamp")),
        "password_last_set": _ad_timestamp(_get(a, "pwdLastSet")),
        "bad_password_count": _get(a, "badPwdCount"),
        "groups": [{"dn": dn, "name": _cn_of(dn)} for dn in (a.get("memberOf") or [])],
    }


@mcp.tool()
@_wrap
def get_user_groups(identity: str, recursive: bool = False) -> list[dict[str, Any]] | dict[str, Any]:
    """List groups a user belongs to. recursive=true also expands nested
    (parent) groups transitively."""
    entry = _resolve_user(client, cfg, identity)
    direct = _attrs(entry).get("memberOf") or []
    if not recursive:
        return [{"dn": dn, "name": _cn_of(dn), "nested": False} for dn in direct]

    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    frontier: list[tuple[str, int]] = [(dn, 0) for dn in direct]
    while frontier:
        dn, depth = frontier.pop(0)
        key = _normalize_dn(dn)
        if key in seen or depth > 10:
            continue
        seen.add(key)
        g = client.get_entry(dn, ["cn", "sAMAccountName", "memberOf"])
        name = _cn_of(dn)
        if g is not None:
            ga = _attrs(g)
            name = _get(ga, "cn") or name
            for parent in ga.get("memberOf") or []:
                if _normalize_dn(parent) not in seen:
                    frontier.append((parent, depth + 1))
        result.append({"dn": dn, "name": name, "nested": depth > 0})
    return result


@mcp.tool()
@_wrap
def list_groups(
    name_contains: str | None = None,
    security_only: bool | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]] | dict[str, Any]:
    """List AD groups with member counts. Optional name substring and
    security/distribution filter."""
    conds = ["(objectClass=group)"]
    if name_contains:
        conds.append(f"(cn=*{_sanitize(name_contains)}*)")
    if security_only is True:
        conds.append("(groupType:1.2.840.113556.1.4.803:=2147483648)")
    elif security_only is False:
        conds.append("(!(groupType:1.2.840.113556.1.4.803:=2147483648))")
    flt = "(&" + "".join(conds) + ")"
    attrs = ["cn", "sAMAccountName", "description", "groupType", "member"]
    return [_group_summary(e) for e in client.search(cfg.base_dn, flt, attrs, size_limit=limit)]


@mcp.tool()
@_wrap
def get_group(identity: str) -> dict[str, Any]:
    """Group details by sAMAccountName or DN, including direct members."""
    entry = _resolve_entry(client, cfg, identity, GROUP_BASE_FILTER, DEFAULT_GROUP_ATTRS)
    a = _attrs(entry)
    members = a.get("member") or []
    return {
        "dn": entry["dn"],
        "guid": _guid(entry),
        "cn": _get(a, "cn"),
        "sam_account_name": _get(a, "sAMAccountName"),
        "description": _get(a, "description"),
        "type": _group_type_decoded(_get(a, "groupType")),
        "when_created": _get(a, "whenCreated"),
        "member_count": len(members),
        "members": [{"dn": dn, "name": _cn_of(dn)} for dn in members],
    }


@mcp.tool()
@_wrap
def get_group_members(identity: str, recursive: bool = False, limit: int | None = None) -> list[dict[str, Any]] | dict[str, Any]:
    """List members of a group. recursive=true expands nested groups too
    (is_group=true marks intermediate groups; `via` names the path)."""
    entry = _resolve_entry(client, cfg, identity, GROUP_BASE_FILTER, DEFAULT_GROUP_ATTRS)
    a = _attrs(entry)
    group_name = _get(a, "cn") or _cn_of(entry["dn"])
    direct = a.get("member") or []
    if not recursive:
        cap = limit or cfg.max_results
        return [{"dn": dn, "name": _cn_of(dn), "via": group_name} for dn in direct[:cap]]
    return _expand_members(client, direct, group_name, min(limit or cfg.max_results, cfg.max_results))


@mcp.tool()
@_wrap
def search_computers(
    query: str | None = None,
    operating_system: str | None = None,
    enabled: bool | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Search computer accounts. `query` matches name/DNS hostname/description
    (substring). operating_system is a substring match, e.g. 'Windows Server'."""
    conds = ["(objectClass=computer)"]
    if query:
        q = _sanitize(query)
        conds.append(f"(|(cn=*{q}*)(dNSHostName=*{q}*)(description=*{q}*))")
    if operating_system:
        conds.append(f"(operatingSystem=*{_sanitize(operating_system)}*)")
    if enabled is True:
        conds.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
    elif enabled is False:
        conds.append("(userAccountControl:1.2.840.113556.1.4.803:=2)")
    flt = "(&" + "".join(conds) + ")"
    return [_computer_summary(e) for e in client.search(cfg.base_dn, flt, DEFAULT_COMPUTER_ATTRS, size_limit=limit)]


@mcp.tool()
@_wrap
def get_computer(identity: str) -> dict[str, Any]:
    """Full details for one computer by name, DNS hostname, or DN."""
    entry = _resolve_entry(client, cfg, identity, COMPUTER_BASE_FILTER, DEFAULT_COMPUTER_ATTRS)
    a = _attrs(entry)
    return {
        "dn": entry["dn"],
        "guid": _guid(entry),
        "name": _get(a, "dNSHostName") or _get(a, "cn"),
        "description": _get(a, "description"),
        "operating_system": _get(a, "operatingSystem"),
        "os_version": _get(a, "operatingSystemVersion"),
        "service_pack": _get(a, "operatingSystemServicePack"),
        "account": _uac_decoded(_get(a, "userAccountControl")),
        "when_created": _get(a, "whenCreated"),
        "last_logon": _ad_timestamp(_get(a, "lastLogonTimestamp")),
        "managed_by": _get(a, "managedBy"),
        "groups": [{"dn": dn, "name": _cn_of(dn)} for dn in (a.get("memberOf") or [])],
    }


@mcp.tool()
@_wrap
def is_user_in_group(identity: str, group: str, explain: bool = False) -> dict[str, Any]:
    """Check whether a user is a member of a group, directly or through
    nested groups.

    Returns is_member (true/false), direct (bool), and membership_paths:
    every distinct nesting path found, each as a list of group names from
    the user up to the target group, e.g.
    ["jdoe", "Helpdesk", "Tier2", "Domain Admins"].
    A direct membership is reported as ["jdoe", "<group>"].
    """
    user = _resolve_user(client, cfg, identity)
    grp = _resolve_entry(client, cfg, group, GROUP_BASE_FILTER, ["cn"])
    user_name = _get(_attrs(user), "sAMAccountName") or _cn_of(user["dn"])
    target_key = _normalize_dn(grp["dn"])
    user_key = _normalize_dn(user["dn"])

    # BFS over memberOf (user -> parent groups). Keep *all* edges so every
    # path can be reported, and cap search to stay cheap on big directories.
    edges: dict[str, list[str]] = {}  # child dn -> [parent dns]
    labels: dict[str, str] = {user_key: user_name, target_key: _cn_of(grp["dn"])}
    frontier = [user["dn"]]
    visited = {user_key}
    expansions = 0
    found_target = False
    while frontier and expansions < 500:
        dn = frontier.pop(0)
        key = _normalize_dn(dn)
        if key == target_key:
            found_target = True
            continue  # do not expand past the target group
        entry = client.get_entry(dn, ["cn", "distinguishedName", "memberOf"])
        expansions += 1
        parents = (_attrs(entry).get("memberOf") or []) if entry else []
        if entry and entry.get("dn"):
            key = _normalize_dn(entry["dn"])  # canonical case from server
        edges[key] = parents
        for p in parents:
            pk = _normalize_dn(p)
            if pk not in labels:
                labels[pk] = _cn_of(p)
            if pk not in visited:
                visited.add(pk)
                frontier.append(p)

    # Enumerate paths (DFS over the edge map, cycle-safe per path)
    paths: list[list[str]] = []

    def dfs(key: str, trail: list[str], seen: set[str]) -> None:
        if len(paths) >= 20:
            return
        if key == target_key:
            paths.append(list(trail))
            return
        for p in edges.get(key, []):
            pk = _normalize_dn(p)
            if pk in seen:
                continue
            seen.add(pk)
            trail.append(labels.get(pk, _cn_of(p)))
            dfs(pk, trail, seen)
            trail.pop()
            seen.discard(pk)

    dfs(user_key, [user_name], {user_key})

    direct = any(
        _normalize_dn(p) == target_key for p in edges.get(user_key, [])
    )
    result: dict[str, Any] = {
        "user": user["dn"],
        "group": grp["dn"],
        "is_member": found_target or direct or bool(paths),
        "direct": direct,
    }
    if explain or result["is_member"]:
        result["membership_paths"] = paths
    return result


@mcp.tool()
@_wrap
def list_ous(name_contains: str | None = None, limit: int | None = None) -> list[dict[str, Any]] | dict[str, Any]:
    """List organizational units under the base DN, with depth (0 = direct child)."""
    conds = ["(objectClass=organizationalUnit)"]
    if name_contains:
        conds.append(f"(ou=*{_sanitize(name_contains)}*)")
    flt = "(&" + "".join(conds) + ")"
    base_depth = len(cfg.base_dn.split(","))
    out = []
    for e in client.search(cfg.base_dn, flt, ["ou", "description", "whenCreated", "gPLink", "gPOptions"], size_limit=limit):
        a = _attrs(e)
        item = {
            "dn": e["dn"],
            "name": _get(a, "ou"),
            "description": _get(a, "description"),
            "depth": len(e["dn"].split(",")) - base_depth,
        }
        links = _parse_gplink(a.get("gPLink"))
        if links:
            item["gpo_links"] = len(links)
        if _get(a, "gPOptions") == 1:
            item["gpo_enforced_at_this_level"] = True
        out.append(item)
    out.sort(key=lambda x: (x["depth"], x["dn"]))
    return out


# ---------------------------------------------------------------------------
# GPO helpers
# ---------------------------------------------------------------------------


def _parse_gplink(value) -> list[dict[str, Any]]:
    """Parse a gPLink attribute value.

    Format: [LDAP://<DN>;<flags>][LDAP://<DN>;<flags>]...
    flags: 0 = normal, 1 = Enforced, 2 = No Override (0 and 1 are equivalent
    in practice; gPOptions=2 on the container also means No Override).
    Returns links in gPMC link order (index 0 = highest precedence).
    """
    if not value:
        return []
    raw = value if isinstance(value, str) else (value[0] if isinstance(value, list) else str(value))
    out = []
    for m in re.finditer(r"\[([^;\]]+)(?:;(\d+))?\]", raw):
        target, flags = m.group(1).strip(), int(m.group(2) or 0)
        dn = re.sub(r"(?i)^LDAP://", "", target)
        # The RDN is CN={<guid>}; anything after the guid is the rest of the DN.
        guid_m = re.match(r"(?i)^CN=(\{[0-9a-f-]+\})", dn)
        guid = guid_m.group(1) if guid_m else _cn_of(dn)
        out.append({
            "guid": guid,
            "flags": flags,
            "enforced": flags in (1, 2),
        })
    return out


def _gpo_definition_dn(guid: str) -> str:
    return f"CN={guid},CN=Policies,CN=System,{cfg.base_dn}"


def _container_chain(entry_dn: str) -> list[str]:
    """Ancestor DNs of an object, nearest container first, ending at the base
    DN. If the object sits directly under the domain root the list is just the
    base DN. Objects under a CN= leaf (e.g. CN=Computers) skip that container
    and rejoin the domain at the base DN's RDN depth."""
    parts = entry_dn.split(",")
    base_depth = len(cfg.base_dn.split(","))
    chain: list[str] = []
    for i in range(1, len(parts) - base_depth + 1):
        ancestor = ",".join(parts[i:])
        rdn = ancestor.split(",")[0]
        if rdn.upper().startswith("CN="):
            continue  # default containers (Computers, Users) hold no gPLink
        chain.append(ancestor)
    return chain


def _entry_via(conn: Connection, dn: str, attributes: list[str]) -> dict[str, Any] | None:
    """BASE-scope read of one entry through an arbitrary (already-bound)
    connection, in the same shape as ADClient.get_entry."""
    conn.search(search_base=dn, search_filter="(objectClass=*)",
                search_scope=BASE, attributes=attributes, size_limit=1)
    for e in conn.response:
        if e.get("type") == "searchResEntry":
            return {"dn": e["dn"], "attributes": e.get("attributes", {})}
    return None


def _gpo_info(guids: list[str], conn: Connection | None = None,
              get_one=None) -> dict[str, dict[str, Any]]:
    """Look up GPO definitions by GUID. Returns {guid_lower: info}.

    Reads each definition with a BASE search: the CN=Policies container under
    CN=System is typically deny-read for non-privileged accounts (so a SUBTREE
    enumeration silently returns nothing), while direct object reads on known
    DNs still succeed. Pass `conn` to read through a different (privileged)
    bind; hidden attributes become readable when that account has access.
    `get_one` lets callers route reads through a dedicated connection.
    """
    if not guids:
        return {}
    cn_map = {}
    attrs = [
        "cn",
        "displayName",
        "description",
        "versionNumber",
        "gPCMachineExtensionNames",
        "gPCUserExtensionNames",
        "gPCWQLFilter",
        "modificationTime",
        "whenCreated",
    ]
    for guid in dict.fromkeys(guids):  # dedupe, keep order
        try:
            if conn is not None:
                e = _entry_via(conn, _gpo_definition_dn(guid), attrs)
            elif get_one is not None:
                e = get_one(_gpo_definition_dn(guid), attrs)
            else:
                e = client.get_entry(_gpo_definition_dn(guid), attrs)
        except Exception:
            e = None
        if not e:
            continue
        a = _attrs(e)
        if not a.get("cn"):
            # The object exists but its attributes are hidden from this bind
            # account (ACE-level deny on 'Read all properties', or the GPO is
            # an orphaned link). Report it as such rather than as a blank GPO.
            cn_map[guid.lower()] = {
                "name": guid,
                "guid": guid,
                "dn": e["dn"],
                "description": None,
                "created": None,
                "modified": None,
                "wmi_filter": None,
                "computer_config": None,
                "user_config": None,
                "acl_hidden": True,
            }
            continue
        info = {
            "name": _get(a, "displayName") or guid,
            "guid": guid,
            "description": _get(a, "description"),
            "dn": e["dn"],
            "created": _get(a, "whenCreated"),
            "modified": _ad_timestamp(_get(a, "modificationTime")),
            "wmi_filter": _get(a, "gPCWQLFilter") or None,
            "computer_config": bool(_get(a, "gPCMachineExtensionNames")),
            "user_config": bool(_get(a, "gPCUserExtensionNames")),
        }
        ver = _get(a, "versionNumber")
        if ver is not None:
            try:
                v = int(ver)
                # versionNumber: high word = SYSVOL (client sees), low word = AD (editor's copy)
                info["version_sysvol"] = v >> 16
                info["version_ad"] = v & 0xFFFF
                info["in_sync"] = (v >> 16) == (v & 0xFFFF)
            except ValueError:
                pass
        cn_map[guid.lower()] = info
    return cn_map


def _read_gpo_links(identity: str, base_filter: str, include_inherited: bool,
                    escalate: bool = False) -> dict[str, Any]:
    """Shared OU-chain walk for get_computer_gpos / get_user_gpos."""
    entry = _resolve_entry(client, cfg, identity, base_filter,
                           ["cn", "distinguishedName", "operatingSystem", "sAMAccountName"])
    entry_dn = entry["dn"]
    chain = _container_chain(entry_dn)

    links = []
    for cont_dn in chain:
        cont = client.get_entry(cont_dn, ["gPLink", "gPOptions", "objectClass"])
        if not cont:
            continue
        a = _attrs(cont)
        no_override = _get(a, "gPOptions") == 2
        classes = [str(c).lower() for c in (a.get("objectClass") or [])]
        kind = "domain" if "domaindns" in classes or "domain" in classes else (
            "site" if "site" in classes else "ou")
        for link in _parse_gplink(a.get("gPLink")):
            links.append({**link, "linked_at": cont_dn, "container_kind": kind,
                          "container_no_override": no_override})

    if not include_inherited and chain:
        links = [l for l in links if l["linked_at"] == chain[0]]

    infos = {}
    escalator = ""
    escalated = False
    guids = [l["guid"] for l in links]
    if escalate and cfg.priv_dn:
        try:
            dn, password = client._resolve_priv_creds()
            # One dedicated privileged connection for the whole re-read: the
            # BASE reads run in a loop and must never interleave with other
            # traffic on a shared connection. _PrivContext keeps the elevated
            # bind alive only inside this block.
            with client.priv_connection(creds=(dn, password)) as pconn:
                infos = _gpo_info(guids, conn=pconn)
                esc = _entry_via(pconn, dn, ["sAMAccountName"]) if _is_dn(dn) else None
            escalator = (_get(_attrs(esc), "sAMAccountName") or dn) if esc else dn
            escalated = True
        except PermissionError:
            raise
        except Exception as exc:
            return {"error": f"escalation failed: {exc}"}
    if not infos:
        infos = _gpo_info(guids)
    return {"entry": entry, "chain": chain, "links": links, "infos": infos,
            "escalated": escalated, "escalator": escalator}


@mcp.tool()
@_wrap
def get_computer_gpos(identity: str, include_inherited: bool = True,
                      escalate: bool = False) -> dict[str, Any]:
    """List the Group Policy Objects that apply to a computer, in precedence
    order, with link location and Enforced/No-Override flags.

    Resolution walks the computer's OU chain up to the domain root and reads
    gPLink/gPOptions on each container (LDAP-only; no PowerShell or RPC).
    Returns the applicable GPOs plus any known caveats. WMI filters and
    'Apply Group Policy' ACEs are reported when readable but not evaluated.
    escalate=true re-reads the GPO definitions through the privileged account
    (AD_PRIV_DN), which can lift per-object ACL hides.
    """
    walk = _read_gpo_links(identity, COMPUTER_BASE_FILTER, include_inherited, escalate)
    if "error" in walk:
        return walk
    comp_dn = walk["entry"]["dn"]
    ca = _attrs(walk["entry"])
    chain, links, infos = walk["chain"], walk["links"], walk["infos"]

    out: list[dict[str, Any]] = []
    for l in links:
        info = infos.get(l["guid"].lower())
        if info is None:
            out.append({
                "name": l["guid"],
                "status": "missing (no GPO object at the expected DN — deleted link or cross-domain)",
                "guid": l["guid"],
                "linked_at": l["linked_at"],
                "enforced": l["enforced"],
            })
            continue
        if info.get("acl_hidden"):
            out.append({
                "name": l["guid"],
                "status": "hidden (the GPO exists but its attributes are ACL-hidden from this service account)",
                "guid": l["guid"],
                "linked_at": l["linked_at"],
                "enforced": l["enforced"],
            })
            continue
        out.append({
            "name": info["name"],
            "guid": info["guid"],
            "enabled_computer_config": info["computer_config"],
            "enabled_user_config": info["user_config"],
            "linked_at": l["linked_at"],
            "container_kind": l["container_kind"],
            "enforced": l["enforced"],
            "no_override": l["enforced"] or l["container_no_override"],
            "wmi_filter": info["wmi_filter"] or None,
            "in_sync": info.get("in_sync"),
            "modified": info.get("modified"),
            "description": info.get("description"),
        })

    result = {
        "computer": comp_dn,
        "os": _get(ca, "operatingSystem"),
        "container_chain": chain,
        "gpo_count": len(out),
        "gpos": out,
        "notes": [
            "Order is GPO precedence: index 0 wins conflicts (GPMC '1', then '2'...).",
            "enabled_* reflect extension data presence, not the security-descriptor "
            "'Apply Group Policy' ACEs; a GPO can be blocked by ACE or empty by SD.",
            "wmi_filter is the raw WQL string when set; it is not evaluated here.",
            "This is a link-inheritance view (gpresult /h equivalent from LDAP data only).",
        ],
    }
    if walk["escalated"]:
        result["escalated"] = True
        result["escalated_as"] = walk["escalator"]
    return result


@mcp.tool()
@_wrap
def list_gpos(name_contains: str | None = None, limit: int | None = None,
              escalate: bool = False) -> list[dict[str, Any]] | dict[str, Any]:
    """List the GPOs defined in the domain (those readable via container link
    data) with version/sync metadata. escalate=true reads the definitions
    through the privileged account (AD_PRIV_DN) so ACL-hidden GPOs appear.

    Note: direct enumeration of CN=Policies,CN=System is usually denied to
    non-privileged accounts, so this discovers GPOs by scanning gPLink on the
    domain and all OUs, then reading each definition directly. GPOs that are
    linked nowhere (or only on sites) will not appear here.
    """
    guids = _all_linked_guids()
    escalated_as = ""
    if escalate and cfg.priv_dn:
        with client.priv_connection() as pconn:
            infos = _gpo_info(guids, conn=pconn)
            esc = _entry_via(pconn, cfg.bind_dn, ["sAMAccountName"])
            escalated_as = (_get(_attrs(esc), "sAMAccountName") or cfg.priv_dn) if esc else cfg.priv_dn
    else:
        if escalate:
            return {"error": "escalation requested but no privileged account "
                             "is configured (see test_privileged)."}
        infos = _gpo_info(guids)
    out = []
    for guid in guids:
        info = infos.get(guid.lower())
        if info is None or info.get("acl_hidden"):
            continue  # unreadable definition; get_computer_gpos reports it
        if name_contains and name_contains.lower() not in (info["name"] or "").lower():
            continue
        out.append({
            "name": info["name"],
            "guid": info["guid"],
            "dn": info["dn"],
            "description": info["description"],
            "modified": info["modified"],
            "version_sysvol": info.get("version_sysvol"),
            "version_ad": info.get("version_ad"),
            "in_sync": info.get("in_sync"),
        })
    out.sort(key=lambda x: (x.get("name") or "").lower())
    return out[: limit or cfg.max_results]


def _all_linked_guids() -> list[str]:
    """GUIDs of every GPO linked on the domain root or any OU, in discovery
    order (domain first, then OUs depth-first). Deduped."""
    guids: list[str] = []
    seen: set[str] = set()

    def collect(container_dn: str) -> None:
        try:
            cont = client.get_entry(container_dn, ["gPLink"])
        except Exception:
            return
        if not cont:
            return
        for link in _parse_gplink(_attrs(cont).get("gPLink")):
            key = link["guid"].lower()
            if key not in seen:
                seen.add(key)
                guids.append(link["guid"])

    collect(cfg.base_dn)
    for e in client.search(cfg.base_dn, "(objectClass=organizationalUnit)", ["dn"],
                           size_limit=cfg.max_results):
        collect(e["dn"])
    return guids


@mcp.tool()
@_wrap
def get_gpo_links(name_contains: str | None = None, limit: int | None = None) -> list[dict[str, Any]] | dict[str, Any]:
    """Show which OUs/sites/domain a GPO is linked to, by scanning gPLink on
    every container. Optional name substring filter on the GPO display name."""
    containers = []
    # domain root
    root = client.get_entry(cfg.base_dn, ["gPLink", "gPOptions", "objectClass"])
    if root:
        containers.append(root)
    # all OUs (site objects need the site container; out of scope for v1)
    flt = "(objectClass=organizationalUnit)"
    for e in client.search(cfg.base_dn, flt, ["ou", "gPLink", "gPOptions"], size_limit=limit or cfg.max_results):
        containers.append(e)

    # collect link targets, then resolve names
    link_map: dict[str, list[dict[str, Any]]] = {}
    for c in containers:
        a = _attrs(c)
        no_override = _get(a, "gPOptions") == 2
        for link in _parse_gplink(a.get("gPLink")):
            link_map.setdefault(link["guid"].lower(), []).append({
                "linked_at": c["dn"],
                "flags": link["flags"],
                "enforced": link["enforced"],
                "no_override": link["enforced"] or no_override,
            })

    infos = _gpo_info(list(link_map.keys()))
    out = []
    for guid_key, locs in link_map.items():
        info = infos.get(guid_key)
        name = info["name"] if info else guid_key
        if name is None:
            continue
        if name_contains and name_contains.lower() not in (name or "").lower():
            continue
        out.append({"name": name, "guid": guid_key.upper(), "links": locs})
    out.sort(key=lambda x: (x["name"] or "").lower())
    return out


# ---------------------------------------------------------------------------
# SYSVOL (GPO settings on disk)
# ---------------------------------------------------------------------------

from . import sysvol as _sysvol  # noqa: E402

sysvol = _sysvol.SysvolClient()


def _domain_dns_name() -> str:
    """DC=wei,DC=local -> wei.local"""
    return ".".join(v for _, v, _ in parse_dn(cfg.base_dn))


def _ensure_sysvol() -> None:
    """Configure the SMB session lazily: logon name = sAMAccountName of the
    bind account (its CN may differ), unless AD_SYSVOL_USER overrides it."""
    if sysvol.creds:
        return
    dns = _domain_dns_name()
    username = cfg.sysvol_user
    if not username:
        entry = client.get_entry(cfg.bind_dn, ["sAMAccountName"])
        username = _get(_attrs(entry), "sAMAccountName") if entry else ""
    if not username:
        raise RuntimeError(
            f"Cannot resolve a logon name for '{cfg.bind_dn}'. "
            "Set AD_SYSVOL_USER to the account's sAMAccountName."
        )
    sysvol.configure(_sysvol.SysvolCreds(
        server=dns, username=username, password=cfg.sysvol_password,
        domain=dns, base=f"\\\\{dns}\\SYSVOL\\{dns}",
    ))


def _gpo_folder(guid: str) -> str:
    """Resolve a GPO (GUID or display name) to its SYSVOL policy folder name.
    SYSVOL folder names are the GUID in *uppercase*; LDAP cn may be mixed."""
    m = re.search(r"\{[0-9A-Fa-f-]+\}", guid or "")
    if m:
        return m.group(0).upper()
    infos = {i["name"].lower(): i for i in _gpo_info(_all_linked_guids()).values()}
    info = infos.get((guid or "").lower())
    if not info:
        matches = [n for n, i in infos.items() if guid and guid.lower() in n]
        if len(matches) == 1:
            info = infos[matches[0]]
        else:
            raise ValueError(
                f"GPO '{guid}' not found. Pass the GUID, or give list_gpos a "
                f"more specific name ({len(matches)} substring matches)."
            )
    return info["guid"].upper()


def _summarize_pol(entries: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    """Group Registry.pol entries into friendly categories."""
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        cat = next((c for prefix, c in _sysvol.POLICY_CATEGORIES
                    if e["key"].upper().startswith(prefix.upper())), "Other")
        by_cat.setdefault(cat, []).append(e)
    summary = {}
    for cat, items in by_cat.items():
        summary[cat] = [
            {"key": i["key"], "value_name": i["value_name"],
             "value": i["value"],
             "value_type": {1: "SZ", 2: "EXPAND_SZ", 3: "BINARY", 4: "DWORD",
                            5: "WORD", 7: "MULTI_SZ", 11: "QWORD"}.get(
                                i.get("value_type"), i.get("value_type")),
             "delete": i["value"] is None}
            for i in items[:limit]
        ]
    return summary


@mcp.tool()
@_wrap
def get_gpo_settings(name_or_guid: str, side: str = "machine",
                     limit: int = 60) -> dict[str, Any]:
    """Read what a GPO actually *does* from SYSVOL (\\\\domain\\SYSVOL).

    side: 'machine' (computer config), 'user' (user config), or 'both'.
    Returns security-template rights/options from GptTmpl.inf and a
    categorized summary of Registry.pol settings, plus file inventory and
    the SYSVOL-vs-AD version check. Settings are capped by `limit` per
    category. Requires SMB read access to SYSVOL (default for domain accounts).
    """
    _ensure_sysvol()
    guid = _gpo_folder(name_or_guid)
    folder = f"Policies\\{guid}"
    if not sysvol.is_dir(folder):
        return {"error": f"GPO folder {guid} not found in SYSVOL "
                         "(deleted GPO, or it lives in another domain)."}

    gpt_ini: dict[str, Any] = {}
    try:
        gpt_ini = _sysvol.parse_gpt_ini(sysvol.read_text(folder, "GPT.INI"))
    except Exception:
        pass

    sides = {"machine": ["Machine"], "user": ["User"],
             "both": ["Machine", "User"]}[side.lower()]
    result: dict[str, Any] = {
        "guid": guid,
        "side": side.lower(),
        "sysvol_version": gpt_ini.get("version_major"),
        "categories": {},
        "files": [],
    }
    # cross-check SYSVOL version against the AD copy
    info = _gpo_info([guid]).get(guid.lower())
    if info:
        result["name"] = info["name"]
        result["ad_version_sysvol"] = info.get("version_sysvol")
        result["ad_version_editor"] = info.get("version_ad")
        if gpt_ini and info.get("version_sysvol") is not None:
            result["in_sync"] = gpt_ini.get("version_major") == info["version_sysvol"]

    for hive in sides:
        # security template (user rights + security options)
        inf_path = (f"{hive}\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf")
        try:
            sec = _sysvol.parse_security_ini(sysvol.read_text(folder, inf_path))
            rights = sec.get(_sysvol.RIGHTS_SECTION, {})
            options = sec.get(_sysvol.SECURITY_OPTIONS_SECTION, {})
            if rights:
                result["categories"][f"{hive}: user rights"] = [
                    {"user_right": k, "accounts": v} for k, v in list(rights.items())[:limit]
                ]
            if options:
                result["categories"][f"{hive}: security options"] = [
                    {"option": k, "value": v} for k, v in list(options.items())[:limit]
                ]
        except Exception:
            pass  # no security template on this side

        # Registry.pol policy settings
        try:
            pol = _sysvol.parse_pol(sysvol.read_bytes(folder, f"{hive}\\Registry.pol"))
            result["pol_entry_count"] = result.get("pol_entry_count", 0) + len(pol)
            for cat, items in _summarize_pol(pol, limit).items():
                result["categories"][f"{hive}: {cat}"] = items
        except FileNotFoundError:
            pass  # no Registry.pol on this side
        except Exception as exc:  # a malformed .pol is worth surfacing, not hiding
            result["categories"][f"{hive}: Registry.pol error"] = [
                {"error": str(exc)}
            ]

        # preferences: Files, Groups, Services, DriveMaps...
        pref_dir = f"{hive}\\Preferences"
        try:
            for sub in sysvol.listdir(folder, pref_dir):
                name = sub.strip("\\").split("\\")[-1]
                try:
                    class_xmls = [f.strip("\\").split("\\")[-1]
                                  for f in sysvol.listdir(folder, pref_dir, sub)]
                except Exception:
                    class_xmls = []
                result["files"].append(f"{hive}/Preferences/{name}: {', '.join(class_xmls)}")
        except Exception:
            pass

    # scripts folder (logon/logoff/startup/shutdown)
    scripts = f"{sides[0]}\\Scripts"
    try:
        result["files"] += [f.strip("\\").split("\\")[-1] for f in sysvol.listdir(folder, scripts)]
    except Exception:
        pass

    if not result["categories"]:
        result["note"] = ("No machine/user policy content parsed on this side "
                          "(GPO may use only preferences, software installation, "
                          "or drive/print mappings — see 'files').")
    return result


@mcp.tool()
@_wrap
def resolve_sids(sids: list[str]) -> list[dict[str, Any]] | dict[str, Any]:
    """Resolve security identifiers (S-1-5-...) to account names. Use this to
    decode the SIDs you see in GPO user rights / security filtering."""
    out = []
    names = _resolve_sids(sids if isinstance(sids, list) else [sids])
    for sid in sids if isinstance(sids, list) else [sids]:
        entry = {"sid": sid, "name": names.get(sid)}
        if sid not in names:
            # add a hint for well-known RIDs in the local domain
            rid = int(sid.rsplit("-", 1)[1]) if sid.count("-") >= 4 else None
            well = {500: "Administrator (built-in)", 501: "Guest (built-in)",
                    512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests",
                    515: "Domain Computers", 516: "Domain Controllers",
                    517: "Cert Publishers", 518: "Schema Admins", 519: "Enterprise Admins",
                    520: "Group Policy Creator Owners", 521: "Read-only Domain Controllers",
                    526: "Domain Denied Password", 553: "RAS and IAS Servers",
                    571: "RODC Password Replication Denied"}
            entry["hint"] = well.get(rid, "unknown (deleted object, foreign domain, or hidden)")
        out.append(entry)
    return out


@mcp.tool()
@_wrap
def get_user_gpos(identity: str, include_inherited: bool = True,
                  escalate: bool = False) -> dict[str, Any]:
    """List the Group Policy Objects that apply to a *user account*, in
    precedence order (same LDAP view as get_computer_gpos, but the user side).

    Note: user settings only apply where the GPO's user config is linked and
    not blocked; loopback-processed computer GPOs are not evaluated here
    (the gPCMachineExtensionNames of linked GPOs are reported so you can spot
    loopback candidates on the computer's OU). escalate=true re-reads the GPO
    definitions through the privileged account (AD_PRIV_DN)."""
    walk = _read_gpo_links(identity, USER_BASE_FILTER, include_inherited, escalate)
    if "error" in walk:
        return walk
    user_dn = walk["entry"]["dn"]
    chain, links, infos = walk["chain"], walk["links"], walk["infos"]

    out = []
    for l in links:
        info = infos.get(l["guid"].lower())
        if info is None:
            out.append({"guid": l["guid"], "linked_at": l["linked_at"],
                        "status": "missing (no GPO object at expected DN)",
                        "enforced": l["enforced"]})
            continue
        if info.get("acl_hidden"):
            out.append({"guid": l["guid"], "linked_at": l["linked_at"],
                        "status": "hidden (attributes ACL-hidden from this account)",
                        "enforced": l["enforced"]})
            continue
        # user config presence is a hint only; the GPO must also have user
        # settings enabled (extension data) for the user half to apply
        out.append({
            "name": info["name"],
            "guid": info["guid"],
            "has_user_config": info["user_config"],
            "has_machine_config": info["computer_config"],
            "linked_at": l["linked_at"],
            "enforced": l["enforced"],
            "no_override": l["enforced"] or l["container_no_override"],
            "wmi_filter": info["wmi_filter"] or None,
            "description": info.get("description"),
        })
    result = {
        "user": user_dn,
        "container_chain": chain,
        "gpo_count": len(out),
        "gpos": out,
        "notes": [
            "has_user_config=true GPOs are the ones with user settings enabled.",
            "Loopback processing on the user's computer OU can apply computer-linked GPOs to users; inspect those OUs' machine GPOs (look for the 'User Group Policy loopback processing mode' setting in get_gpo_settings).",
        ],
    }
    if walk["escalated"]:
        result["escalated"] = True
        result["escalated_as"] = walk["escalator"]
    return result


@mcp.tool()
@_wrap
def test_privileged() -> dict[str, Any]:
    """Check the optional privileged escalation account (AD_PRIV_DN): whether
    it is configured, what its effective rights are, and what it can see that
    the service account cannot. Tools never escalate implicitly; pass
    escalate=true on a specific call."""
    from . import seal as _seal

    if not cfg.priv_dn:
        return {
            "configured": False,
            "how_to_enable": (
                "1) ad-mcp-seal genkeys <pub.pem> <priv.pem> — move the PRIVATE pem "
                "off this host. 2) ad-mcp-seal seal --pubkey pub.pem --user <sAM> "
                "--dn <DN> — paste the printed blob into AD_PRIV_SEAL. "
                "3) Set AD_PRIV_DN=<same DN> and AD_SEAL_KEY_FILE=<priv.pem>. "
                "Alternative secrets backends work too: AD_PRIV_SEAL supports "
                "{file:/path}, {env:VAR}, {plain:...}."
            ),
        }
    # resolve + bind now, report effective rights, then drop immediately
    creds = client._resolve_priv_creds()
    dn, password = creds
    entry = client.get_entry(dn, ["sAMAccountName", "userAccountControl",
                                  "member", "description"]) if _is_dn(dn) else None
    ea = _attrs(entry) if entry else {}
    sam = _get(ea, "sAMAccountName") or dn
    groups = [str(_cn_of(m)) for m in (ea.get("member") or [])][:0]  # direct groups of priv acct
    direct_member_of = []
    if _is_dn(dn):
        for e in client.search(cfg.base_dn,
                               f"(&(objectClass=group)(member={_sanitize(dn)}))",
                               ["cn"], size_limit=cfg.max_results):
            direct_member_of.append(_get(_attrs(e), "cn"))

    secret_kind = "sealed" if _seal.looks_sealed(_resolve_secret(cfg.priv_seal)) else "plaintext/env"
    key_loc = cfg.seal_key_file or cfg.seal_key_dir or _seal.default_key_location()
    keys_loaded = len(_seal.load_private_keys(key_loc)) if secret_kind == "sealed" else None
    result = {
        "configured": True,
        "dn": dn,
        "logon_name": sam,
        "secret_storage": secret_kind,
        "seal_private_keys_loaded": keys_loaded,
        "seal_key_location": key_loc if secret_kind == "sealed" else None,
        "direct_member_of": direct_member_of,
    }
    # what does escalation actually reveal? diff hidden GPO visibility
    try:
        guids = _all_linked_guids()
        base = _gpo_info(guids)
        hidden = [g for g, i in base.items() if i.get("acl_hidden")]
        with client.priv_connection() as pconn:
            priv_infos = _gpo_info(guids, conn=pconn)
        revealed = [priv_infos[h]["name"] if h in priv_infos and not priv_infos[h].get("acl_hidden")
                    else h for h in hidden]
        result["hidden_gpos_for_service_account"] = len(hidden)
        result["revealed_by_escalation"] = [r for r in revealed if not r.startswith("{")]
        result["still_hidden"] = [r for r in revealed if r.startswith("{")]
    except PermissionError as e:
        result["escalation_bind"] = f"FAILED: {e}"
    return result


@mcp.tool()
@_wrap
def test_sysvol() -> dict[str, Any]:
    """Check SMB/SYSVOL connectivity for reading GPO settings (the service
    account's logon name is resolved from AD automatically)."""
    if not cfg.sysvol_enabled:
        return {"sysvol": "disabled (AD_SYSVOL=false)"}
    _ensure_sysvol()
    return sysvol.test()


def _sid_to_bytes(sid: str) -> bytes:
    """Convert 'S-1-5-21-...' to the binary form AD stores in objectSID."""
    parts = [int(p) for p in sid.split("-")[1:]]  # [rev-drop, auth, subauth..., rid]
    if parts[0] != 1 or len(parts) < 3:
        raise ValueError(f"not a SID: {sid}")
    auth_count = len(parts) - 3
    out = bytes([1, auth_count]) + b"\x00\x00\x00\x00\x00\x05"
    out += parts[2].to_bytes(6, "big")  # 48-bit big-endian authority
    for sub in parts[3:]:
        out += struct.pack("<I", sub)
    return out


def _resolve_sids(sids: list[str]) -> dict[str, str]:
    """Map security identifiers to names via objectSID lookups."""
    uniq = list(dict.fromkeys(s for s in sids if s.startswith("S-1-")))[:60]
    if not uniq:
        return {}
    out: dict[str, str] = {}
    # built-ins
    builtin = {
        "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE", "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
        "S-1-5-18": "NT AUTHORITY\\SYSTEM", "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
        "S-1-5-32-544": "BUILTIN\\Administrators", "S-1-5-32-545": "BUILTIN\\Users",
        "S-1-5-32-568": "BUILTIN\\IIS_IUSRS", "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
        "S-1-5-32-559": "BUILTIN\\Cert Publishers",
    }
    rest = []
    for s in uniq:
        if s in builtin:
            out[s] = builtin[s]
        else:
            rest.append(s)
    for sid in list(rest):
        # foreign/security-disabled SIDs won't match; try binary objectSID
        try:
            binary = _sid_to_bytes(sid)
        except ValueError:
            rest.remove(sid)
            continue
        flt = f"(objectSID={escape_filter_chars(binary)})"
        hits = client.search(cfg.base_dn, flt, ["cn", "sAMAccountName", "objectClass"],
                             size_limit=1)
        if hits:
            a = _attrs(hits[0])
            out[sid] = str(_get(a, "sAMAccountName") or _get(a, "cn"))
            rest.remove(sid)
    return out


@mcp.tool()
@_wrap
def get_gpo_security(name_or_guid: str, limit: int = 100) -> dict[str, Any]:
    """Decode the security template (GptTmpl.inf) of a GPO with SIDs resolved
    to account names: user rights grants/denials and security options.

    This is the fastest way to see what a hardening GPO actually does, e.g.
    which groups are denied interactive/RDP/service logon. Rights entries
    include both the raw SIDs and the resolved names."""
    _ensure_sysvol()
    guid = _gpo_folder(name_or_guid)
    folder = f"Policies\\{guid}"
    info = _gpo_info([guid]).get(guid.lower())
    try:
        text = sysvol.read_text(folder, "Machine", "Microsoft", "Windows NT",
                                "SecEdit", "GptTmpl.inf")
    except Exception:
        # user-side templates are rare but exist
        try:
            text = sysvol.read_text(folder, "User", "Microsoft", "Windows NT",
                                    "SecEdit", "GptTmpl.inf")
        except Exception:
            return {"error": f"No security template (GptTmpl.inf) in GPO "
                             f"{info['name'] if info else guid} — it may configure "
                             "only registry policies or preferences. Use "
                             "get_gpo_settings instead."}

    sec = _sysvol.parse_security_ini(text)
    rights = sec.get(_sysvol.RIGHTS_SECTION, {})
    options = sec.get(_sysvol.SECURITY_OPTIONS_SECTION, {})
    all_sids = [s.strip().lstrip("*") for v in rights.values() for s in v.split(",")]
    names = _resolve_sids(all_sids)

    rights_out = []
    for right, raw in list(rights.items())[:limit]:
        accounts = []
        for token in raw.split(","):
            sid = token.strip().lstrip("*")
            accounts.append({"sid": sid, "name": names.get(sid, "?unknown")})
        rights_out.append({"user_right": right,
                           "mode": "deny" if right.startswith("SeDeny") else "grant",
                           "accounts": accounts})
    return {
        "gpo": info["name"] if info else guid,
        "guid": guid,
        "user_rights": rights_out,
        "security_options": [{"option": k, "value": v}
                             for k, v in list(options.items())[:limit]],
        "unresolved_sids": sorted({s for s in all_sids if s not in names}),
    }


@mcp.tool()
@_wrap
def get_inactive_users(days: int = 90, limit: int | None = None) -> list[dict[str, Any]] | dict[str, Any]:
    """Enabled user accounts with no logon in `days` days (lastLogonTimestamp;
    'never' means it was never set)."""
    if days < 1:
        raise ValueError("days must be >= 1")
    cutoff = _filetime_days_ago(days)
    flt = (
        "(&(objectClass=user)(objectCategory=person)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        f"(|(lastLogonTimestamp=0)(lastLogonTimestamp<={cutoff})))"
    )
    out = []
    for e in client.search(cfg.base_dn, flt, DEFAULT_USER_ATTRS, size_limit=limit):
        s = _user_summary(e)
        a = _attrs(e)
        s["last_logon"] = _ad_timestamp(_get(a, "lastLogonTimestamp")) or "never"
        s["created"] = _get(a, "whenCreated")
        out.append(s)
    return out


@mcp.tool()
@_wrap
def get_privileged_groups(limit: int | None = None) -> list[dict[str, Any]] | dict[str, Any]:
    """List well-known privileged/admin groups (Domain Admins etc.) with
    member counts. Writes to these groups are always refused."""
    conds = "".join(f"(cn={_sanitize(g)})" for g in sorted(cfg.protected_groups))
    flt = f"(&(objectClass=group)(|{conds}))"
    attrs = ["cn", "sAMAccountName", "description", "groupType", "member"]
    return [_group_summary(e) for e in client.search(cfg.base_dn, flt, attrs, size_limit=limit)]


@mcp.tool()
@_wrap
def raw_ldap_search(
    search_filter: str,
    search_base: str | None = None,
    attributes: list[str] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Run a raw LDAP search constrained to the configured base DN. Use only
    when the specific tools cannot answer the question."""
    base = _validate_dn((search_base or cfg.base_dn).strip(), cfg.base_dn, cfg)
    for bad in ("\x00", "\r", "\n"):
        if bad in search_filter:
            raise ValueError("Invalid characters in search filter")
    attrs = attributes or ["cn", "sAMAccountName", "objectClass"]
    return [_attrs(e) | {"dn": e["dn"]} for e in client.search(base, search_filter, attrs, size_limit=limit)]


# ---------------------------------------------------------------------------
# Guarded write operations (registered only when AD_ALLOW_WRITES=true)
# ---------------------------------------------------------------------------


def _assert_writable_group(group_entry: dict[str, Any]) -> None:
    name = _cn_of(group_entry["dn"]).lower()
    if name in {g.lower() for g in cfg.protected_groups}:
        raise PermissionError(
            f"'{_cn_of(group_entry['dn'])}' is a protected privileged group; refusing to modify"
        )
    _validate_dn(group_entry["dn"], cfg.base_dn, cfg, for_write=True)


if cfg.allow_writes:

    @mcp.tool()
    @_wrap
    def add_group_member(group: str, member: str) -> str | dict[str, Any]:
        """Add a user or group to a security group. Refuses protected privileged
        groups and any DN outside the configured base / AD_WRITE_OUS whitelist."""
        g = _resolve_entry(client, cfg, group, GROUP_BASE_FILTER, ["cn"])
        _assert_writable_group(g)
        m = _resolve_user(client, cfg, member)
        _validate_dn(m["dn"], cfg.base_dn, cfg, for_write=True)
        client.modify_members(g["dn"], add=[m["dn"]])
        return f"Added {m['dn']} to {g['dn']}"

    @mcp.tool()
    @_wrap
    def remove_group_member(group: str, member: str) -> str | dict[str, Any]:
        """Remove a user or group from a security group. Same guards as
        add_group_member."""
        g = _resolve_entry(client, cfg, group, GROUP_BASE_FILTER, ["cn"])
        _assert_writable_group(g)
        m = _resolve_user(client, cfg, member)
        client.modify_members(g["dn"], delete=[m["dn"]])
        return f"Removed {m['dn']} from {g['dn']}"


def main() -> None:
    try:
        mcp.run(transport="stdio")
    finally:
        client.close()


if __name__ == "__main__":
    main()
