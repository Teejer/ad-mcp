"""End-to-end tool tests against a live AD-protocol LDAP server.

Point AD_HOSTS/AD_BIND_DN/AD_BIND_PASSWORD/AD_BASE_DN (and optionally
AD_PORT, AD_ALLOW_WRITES) at a domain controller — e.g. the throwaway Samba AD
DC from the README — then run:

    python tests/test_tools.py

Exits non-zero on any failure.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ad_mcp.server import cfg, client, mcp  # noqa: E402

WRITE_TESTS = os.environ.get("AD_ALLOW_WRITES", "").lower() in {"1", "true", "yes"}
FAILURES: list[str] = []
PASSED = 0


def result_of(res):
    """Normalize FastMCP call_tool results (v1 tuple/list of content blocks,
    or v2 CallToolResult) into a Python value."""
    # v2: CallToolResult with is_error / structured_content
    if hasattr(res, "is_error"):
        if res.is_error:
            return {"error": res.content[0].text}
        sc = res.structured_content
        if isinstance(sc, dict) and set(sc.keys()) == {"result"}:
            return sc["result"]
        return sc if sc is not None else json.loads(res.content[0].text)
    # v1: (content, structured) tuple or plain list of content blocks
    if isinstance(res, tuple):
        if len(res) == 2 and isinstance(res[1], dict):
            content, structured = res
        else:
            content, structured = (res[0] if res else []), None
    else:
        content, structured = res, None
    if structured and isinstance(structured, dict):
        return structured.get("result", structured)
    first = content[0] if isinstance(content, list) and content else content
    text = getattr(first, "text", str(first))
    try:
        return json.loads(text)
    except Exception:
        return text


async def call(name: str, **kw):
    return result_of(await mcp.call_tool(name, kw))


def ok(label: str, cond, sample=None):
    global PASSED
    if cond:
        PASSED += 1
        print(f"PASS {label}")
    else:
        FAILURES.append(label)
        print(f"FAIL {label}  -> {str(sample)[:300]}")


async def main():
    user = os.environ.get("TEST_USER", "jdoe")
    other = os.environ.get("TEST_OTHER", "mmust")
    nested_group = os.environ.get("TEST_NESTED_GROUP", "Domain Admins")
    direct_group = os.environ.get("TEST_DIRECT_GROUP", "IT Staff")
    computer = os.environ.get("TEST_COMPUTER", "WS01")
    domain = os.environ.get("TEST_DOMAIN", "ad.test")

    r = await call("test_connection")
    ok("test_connection", isinstance(r, dict) and r.get("connected"), r)

    r = await call("search_users", query=user)
    ok("search_users finds test user", isinstance(r, list) and any(u["sam_account_name"] == user for u in r), r)

    r = await call("search_users", enabled=False)
    ok("search_users enabled filter returns list", isinstance(r, list), r)

    r = await call("search_users", query="zz-no-such-user-zz")
    ok("search_users empty result", r == [], r)

    r = await call("get_user", identity=user)
    ok("get_user by sam", isinstance(r, dict) and r.get("sam_account_name") == user and r.get("guid"), r)
    ok("get_user decodes UAC", isinstance(r, dict) and isinstance(r.get("account", {}).get("enabled"), bool), r)

    r = await call("get_user", identity=f"{user}@{domain}")
    ok("get_user by UPN", isinstance(r, dict) and r.get("sam_account_name") == user, r)

    r = await call("get_user", identity="totally-unknown-user")
    ok("get_user unknown -> error", isinstance(r, dict) and "error" in r, r)

    r = await call("get_user_groups", identity=user, recursive=False)
    ok("get_user_groups direct contains direct group", isinstance(r, list) and direct_group in [g["name"] for g in r], r)

    r = await call("get_user_groups", identity=user, recursive=True)
    names = {g["name"] for g in r} if isinstance(r, list) else set()
    ok("get_user_groups recursive reaches nested group", direct_group in names and nested_group in names, names)

    r = await call("is_user_in_group", identity=user, group=nested_group, explain=True)
    ok(
        "is_user_in_group nested + path",
        isinstance(r, dict)
        and r.get("is_member")
        and not r.get("direct")
        and r.get("membership_paths")
        and r["membership_paths"][0][0] == user
        and r["membership_paths"][0][-1] == nested_group,
        r,
    )

    r = await call("is_user_in_group", identity=user, group=direct_group)
    ok("is_user_in_group direct", isinstance(r, dict) and r.get("is_member") and r.get("direct"), r)

    r = await call("is_user_in_group", identity=other, group=nested_group)
    ok("is_user_in_group negative", isinstance(r, dict) and not r.get("is_member"), r)

    r = await call("list_groups", name_contains="zz-no-such")
    ok("list_groups filter empty", r == [], r)

    r = await call("list_groups", security_only=True)
    ok("list_groups security filter", isinstance(r, list) and all(g["type"]["security"] for g in r), r)

    r = await call("get_group", identity=direct_group)
    ok("get_group", isinstance(r, dict) and r.get("member_count", 0) >= 1, r)

    r = await call("get_group_members", identity=nested_group, recursive=True)
    sam = {x.get("sam_account_name") for x in r} if isinstance(r, list) else set()
    ok("get_group_members recursive", user in sam, sam)

    r = await call("search_computers")
    ok("search_computers list", isinstance(r, list), r)

    r = await call("get_computer", identity=computer)
    ok("get_computer by name", isinstance(r, dict) and r.get("dn", "").upper().startswith(f"CN={computer.upper()}"), r)

    r = await call("get_computer", identity=f"{computer}$")
    ok("get_computer by NAME$", isinstance(r, dict) and "dn" in r, r)

    r = await call("list_ous")
    ok("list_ous", isinstance(r, list), r)

    r = await call("get_inactive_users", days=90)
    ok("get_inactive_users", isinstance(r, list), r)

    r = await call("get_privileged_groups")
    ok("get_privileged_groups includes Domain Admins", isinstance(r, list) and any(g["cn"] == "Domain Admins" for g in r), r)

    r = await call("raw_ldap_search", search_filter=f"(sAMAccountName={user})")
    ok("raw_ldap_search", isinstance(r, list) and len(r) == 1, r)

    r = await call("raw_ldap_search", search_filter="(cn=x)", search_base="DC=evil,DC=com")
    ok("raw_ldap_search base escape blocked", isinstance(r, dict) and "error" in r, r)

    r = await call("raw_ldap_search", search_filter="(cn=*)", search_base="CN=x,DC=evil,DC=com")
    ok("raw_ldap_search DN escape blocked", isinstance(r, dict) and "error" in r, r)

    if WRITE_TESTS:
        add = await call("add_group_member", group=direct_group, member=other)
        ok("add_group_member", isinstance(add, str) and "Added" in add, add)
        chk = await call("is_user_in_group", identity=other, group=direct_group)
        ok("write verified (added)", chk.get("is_member"), chk)
        rm = await call("remove_group_member", group=direct_group, member=other)
        ok("remove_group_member", isinstance(rm, str) and "Removed" in rm, rm)
        chk = await call("is_user_in_group", identity=other, group=direct_group)
        ok("write verified (removed)", not chk.get("is_member"), chk)
        bad = await call("add_group_member", group="Domain Admins", member=other)
        ok("privileged group write refused", isinstance(bad, dict) and "refusing" in bad.get("error", ""), bad)
        bad = await call("add_group_member", group=direct_group, member="no-such-user")
        ok("unknown member rejected", isinstance(bad, dict) and "error" in bad, bad)

    print(f"\n{PASSED} passed, {len(FAILURES)} failed")
    if FAILURES:
        print("failed:", ", ".join(FAILURES))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
