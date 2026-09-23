# Active Directory MCP server

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets an
AI assistant query your Active Directory — users, groups, computers, OUs — and
(optionally) make guarded group-membership changes. Talks to **real AD LDAP**
(Windows AD or Samba AD DC): `objectCategory=person` filters,
`LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.803`) matching rules,
`sAMAccountName`/`userPrincipalName`/`dNSHostName` resolution, AD large-member
auto-ranging, and FILETIME timestamps.

## Tools

Read-only (always available):

| Tool | Description |
| --- | --- |
| `test_connection` | LDAP connectivity + base entry check |
| `search_users` | Substring search (name/sam/mail/UPN), filters: department, title, enabled |
| `get_user` | Full profile: decoded UAC flags, groups, last logon, pwd-last-set, GUID |
| `get_user_groups` | Group memberships; `recursive=true` expands nested groups |
| `is_user_in_group` | Membership check incl. nesting; returns **every path**, e.g. `["jdoe", "Helpdesk", "Tier2", "Domain Admins"]` |
| `list_groups` | All groups with member counts; name/security filters |
| `get_group` | Group details + direct members |
| `get_group_members` | Members; `recursive=true` expands nested groups (`via` shows the path) |
| `search_computers` | Substring search; filters: OS, enabled |
| `get_computer` | Full details by name / `NAME$` / FQDN / DN |
| `list_ous` | OUs with depth under the base DN |
| `get_inactive_users` | Enabled accounts idle for N days (lastLogonTimestamp) |
| `get_privileged_groups` | Well-known admin groups (Domain Admins etc.) with member counts |
| `raw_ldap_search` | Escape hatch — raw filter, hard-constrained to the base DN |

Writes (only registered when `AD_ALLOW_WRITES=true`):

| Tool | Description |
| --- | --- |
| `add_group_member` | Add user/group to a security group |
| `remove_group_member` | Remove member from a security group |

## Safety model

- **Read-only by default.** The read connection uses ldap3 `read_only=True`, so
  no code path can write unless you explicitly set `AD_ALLOW_WRITES=true`.
- **Privileged groups are untouchable.** `add/remove_group_member` always
  refuses Domain Admins, Enterprise Admins, and ~14 other well-known groups.
- **Base-DN confinement.** Every search base and write target must be inside
  `AD_BASE_DN`; malformed/escaping DNs are rejected.
- **Optional OU whitelist** (`AD_WRITE_OUS`) restricts write targets further.
- **Result caps and paging** (`AD_MAX_RESULTS`, `AD_PAGE_SIZE`) so an agent
  cannot dump the whole directory in one call.
- Filter-injection safe: all user-supplied terms go through
  `escape_filter_chars`.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Configuration (environment variables)

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `AD_HOSTS` | yes | — | DC hostname(s)/IP(s), comma-separated |
| `AD_BIND_DN` | yes | — | e.g. `CN=svc-mcp,OU=Service Accounts,DC=corp,DC=example,DC=com` |
| `AD_BIND_PASSWORD` | yes | — | bind password |
| `AD_BASE_DN` | yes | — | e.g. `DC=corp,DC=example,DC=com` |
| `AD_PORT` | no | `389` (`636` with SSL) | LDAP port |
| `AD_USE_SSL` | no | `false` | use LDAPS |
| `AD_ALLOW_SELF_SIGNED` | no | `true` | accept self-signed LDAPS certs |
| `AD_MAX_RESULTS` | no | `100` | hard cap per query |
| `AD_PAGE_SIZE` | no | `200` | paged-results size |
| `AD_SEARCH_TIMEOUT` | no | `30` | socket receive timeout (s) |
| `AD_ALLOW_WRITES` | no | `false` | enable `add/remove_group_member` |
| `AD_WRITE_OUS` | no | — | comma-separated OU DNs; writes restricted to these |

Any value may be a **secret reference** instead of a literal:
`{file:/path}` (supports `$VAR`/`${VAR}` expansion and `~`), `{env:VAR}`, or
`{plain:text}`. A `{file:}` whose target does not exist counts as *unset*, so
optional secrets (like `AD_PRIV_SEAL`) can point at a systemd credential that
is only mounted in some launch modes.

Instead of environment variables, put the same keys in `mcp-config.json`
(0600!) next to the server, under `mcpServers.active-directory.env`
(see `mcp-config.example.json`). Precedence: real environment → config file.
This keeps MCP-client config (which often can't pass per-call env reliably)
free of both secrets and plumbing.

The bind account needs **read** access to user/group/computer/OU objects
(Domain Users membership is enough for reads on a default AD). For writes it
needs write permission on the `member` attribute of the target groups.

## Run

```bash
AD_HOSTS=dc01.corp.example.com \
AD_BIND_DN='CN=svc-mcp,OU=Service Accounts,DC=corp,DC=example,DC=com' \
AD_BIND_PASSWORD='...' \
AD_BASE_DN='DC=corp,DC=example,DC=com' \
.venv/bin/ad-mcp          # stdio transport
```

### OpenCode with systemd credentials (the deployment on this box)

Secrets live in `~/.config/ad-mcp/` (0600) and enter the process only through
a systemd credential directory. `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "active-directory": {
      "type": "local",
      "command": [
        "systemd-run", "--user", "--quiet", "--pipe", "--collect",
        "--property", "LoadCredential=svc-admcp:/home/USER/.config/ad-mcp/svc-admcp",
        "--property", "LoadCredential=adpriv:/home/USER/.config/ad-mcp/adpriv",
        "--property", "WorkingDirectory=/path/to/services/ad",
        "/path/to/services/ad/.venv/bin/ad-mcp"
      ],
      "environment": {},
      "disabled": true
    }
  }
}
```

- `--pipe` keeps stdio working; `--collect` avoids transient-unit buildup;
  `WorkingDirectory` matters because `systemd-run` does not inherit the
  caller's cwd and the server reads `mcp-config.json` from it.
- The child env is OpenCode's `environment` block plus the systemd default —
  do **not** pass bare `--setenv` flags (an `--setenv` without `KEY=VALUE`
  makes `systemd-run` consume the next argument and the unit dies).
- `mcp-config.json` holds everything else; its `AD_BIND_PASSWORD` is
  `{file:$CREDENTIALS_DIRECTORY/svc-admcp}` and `AD_PRIV_SEAL` is
  `{file:$CREDENTIALS_DIRECTORY/adpriv}` — the server expands
  `$CREDENTIALS_DIRECTORY` itself at bind time.
- `disabled: true` means no AD connection until you run
  `opencode mcp enable active-directory` (then restart/start opencode).
- Rotation: overwrite the credential file, then
  `opencode mcp disable active-directory && opencode mcp enable active-directory`
  (unseal/resolve happens at unit start / server start).

## Example prompts

- “Is jdoe a member of Domain Admins, directly or nested?” → `is_user_in_group`
  returns the full chain.
- “Which groups does jdoe belong to, including nested ones?”
- “List all users in the IT department”
- “Show all Windows Server 2022 computers”
- “Which computer accounts haven't logged in for 90 days?”
- “Who is in Domain Admins, expanding nested groups?”

## Development

Integration tests run against a throwaway Samba AD DC container:

```bash
# throwaway container password - pick your own, it never leaves your machine
RIG_PASS='ChangeMe-123'
docker run -d --privileged --name ad-test -p 1389:389 \
  -e REALM='AD.TEST' -e DOMAIN='AD' -e ADMIN_PASS="$RIG_PASS" \
  -e DNS_FORWARDER='9.9.9.9' -e BIND_NETWORK_INTERFACES=false \
  diegogslomp/samba-ad-dc
# wait ~20s, then seed users/groups with samba-tool and run:
AD_HOSTS=127.0.0.1 AD_PORT=1389 \
AD_BIND_DN='CN=Administrator,CN=Users,DC=ad,DC=test' AD_BIND_PASSWORD="$RIG_PASS" \
AD_BASE_DN='DC=ad,DC=test' .venv/bin/python tests/test_tools.py
```

## GPO tools

- `get_computer_gpos(identity)` — GPOs applied to a computer, in precedence
  order, with the OU-chain view (own OU → domain root), link location,
  Enforced/No-Override flags, WMI filter (raw WQL, not evaluated), and
  SYSVOL/AD version sync state. `include_inherited=false` limits to links on
  the computer's own OU.
- `list_gpos(name_contains)` / `get_gpo_links(name_contains)` — domain-wide
  GPO inventory and which OUs each GPO is linked to.

All LDAP-only (no PowerShell/RPC): reads `gPLink`/`gPOptions` on containers
and the `groupPolicyContainer` objects under `CN=Policies,CN=System`. Note
that in many domains `CN=Policies` denies *list* access to non-privileged
accounts while still allowing direct object reads — these tools discover GPOs
via container link data and read definitions one by one, so they work with a
plain domain service account. GPOs whose attributes are ACL-denied per-object
are reported as `hidden: ...` instead of silently dropped. The actual settings
*inside* a GPO live in SYSVOL (`\\<domain>\SYSVOL\...\Policies\<GUID>`),
not LDAP — `get_gpo_settings(name_or_guid)` reads those over SMB (GptTmpl.inf
rights/options, Registry.pol policy entries incl. cert-store blobs, scripts,
preferences) and cross-checks the SYSVOL GPT.INI version against AD.

### Granting the service account read access (DC-side, one time)

Two PowerShell scripts in `scripts/`, both run on a Domain Controller as an
admin, both **purely additive** (they never remove or edit existing ACEs or
group members; deny ACEs are only reported):

1. `delegate-admcp-read.ps1 -Apply` — the LDAP-side grants (read the AD
   GPO container/objects so the GPO tools and escalation work).
2. `delegate-admcp-gpo-read.ps1 [-IncludeSysvol] -Apply` — grants
   `ReadProperty + ReadControl + ExtendedRight + ListChildren` on each GPO
   object to `GPO_MCP Readers` (which contains `svc_admcpprivservice`), so
   `escalate=true` reveals ACL-hidden GPOs. Re-run it after new GPOs are
   created; it skips objects that already carry the ACE. `-IncludeSysvol`
   additionally grants read on the GPO's SYSVOL `Policies\<GUID>` folder
   (off by default — SYSVOL reads for the *plain* service account already
   work through normal Authenticated Users permissions; the per-GPO grant
   only matters if you lock SYSVOL down later).

## Privileged escalation & secrets

Some environments keep the MCP service account deliberately low-privilege but
want an occasional elevated read (e.g. `escalate=true` on `list_gpos` /
`get_computer_gpos` / `get_user_gpos` to see ACL-hidden GPO names). The server
supports an **on-demand privileged bind** that exists only for the duration of
one call, with the password never stored in plaintext next to the server:

```bash
# 1) one-time keypair (run where the PRIVATE key will live; move it OFF the MCP host)
ad-mcp-seal genkeys seal_pub.pem seal_priv.pem

# 2) seal the privileged account's password (operator-side; prompts securely)
ad-mcp-seal seal --pubkey seal_pub.pem --user svc_admcp_admin \
    --dn "CN=admcp-admin,OU=...,DC=wei,DC=local" --expires-days 90
# -> prints a sealed blob (RSA-OAEP-SHA256, replayable but not decryptable
#    without the private key)

# 3) server config
AD_PRIV_DN=CN=admcp-admin,OU=...,DC=wei,DC=local
AD_PRIV_SEAL=<the sealed blob>        # or {file:/path}, {env:VAR}, {plain:...}
AD_SEAL_KEY_FILE=/secure/seal_priv.pem   # private key; only here if you want
                                         # sealed escalation on this host
```

- `test_privileged` shows whether escalation is configured, what the account
  is a member of, and exactly how many hidden GPOs the elevated bind reveals.
- Tools never escalate implicitly — pass `escalate=true` explicitly; results
  carry `escalated_as` so there is a record of who was used.
- The privileged bind is **read-only** (`read_only=True` in ldap3): a leaked
  seal can never mutate AD through this server, only read.
- Seal = RSA-OAEP(SHA-256) over the password, sealed for the server's public
  key. The private key can live anywhere (even not on this host at all — use
  `{file:}`/`{env:}` from your secret manager instead of a seal).
- **Rotation**: re-seal, replace `AD_PRIV_SEAL` in the config file — it is
  hot-reloaded on the next call. Key rotation via `kid` routing: drop the new
  keypair in and set `AD_SEAL_KEY_DIR` to a folder holding both (old seals
  still unseal with the old key until you remove it).

Secret backends that work out of the box:
- **systemd credentials (current setup)**: the OpenCode entry launches the
  server via `systemd-run --user --pipe` with
  `LoadCredential=adpriv:~/.config/ad-mcp/adpriv`, and the config uses
  `AD_PRIV_SEAL={file:$CREDENTIALS_DIRECTORY/adpriv}`. Swap the plaintext
  file for a sealed one later with `LoadCredentialEncrypted=` (system units
  only for TPM sealing — see `systemd-creds(1)`).
- **1Password**: `AD_PRIV_SEAL={env:OP_VAULT_REF}` with
  `op run -- ad-mcp` injecting it, or an op-cloned file `{file:...}`.
- **HashiCorp Vault agent / env-injection templates**: same `{file:}` pattern.
- **Sealed blob**: good when you do *not* want the plaintext password ever
  touching the MCP host (operator seals on their own workstation).

## Notes / limitations

- Pinned to the MCP Python SDK **v1** (`mcp<2`): OpenCode's MCP client
  negotiates protocol 2024-11-05, which the v2 SDK does not answer. The server
  speaks v1 FastMCP.

- `lastLogonTimestamp` is replicated only ~every 9–14 days; treat last-logon
  values as approximate (“never” means the attribute was never set).
- Primary-group membership (usually Domain Users, `primaryGroupID=513`) is not
  reflected in `memberOf`; `get_user`/`is_user_in_group` report `memberOf`
  links only.
- Writes are intentionally limited to group membership. Password resets and
  account creation are out of scope for an LLM-driven tool by design.
