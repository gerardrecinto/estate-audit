"""Account hygiene from an LDIF dump (ldapsearch -LLL output) of posixAccount and posixGroup entries."""
from __future__ import annotations

import base64
from collections import defaultdict
from datetime import date

from .checks import Finding

NOLOGIN = ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false")


def parse_ldif(text: str) -> list[dict[str, list[str]]]:
    """Entries as {attr: [values]}. Handles folded lines, base64 (::) values and comments."""
    lines: list[str] = []
    for raw in text.splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    entries, cur = [], None
    for line in lines:
        if line.startswith("#"):
            continue
        if not line.strip():
            if cur:
                entries.append(cur)
            cur = None
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        if val.startswith(":"):
            val = base64.b64decode(val[1:].strip()).decode("utf-8", "replace")
        else:
            val = val.strip()
        if key == "dn" and cur is None:
            cur = {}
        if cur is not None:
            cur.setdefault(key, []).append(val)
    if cur:
        entries.append(cur)
    return [e for e in entries if "dn" in e]


def _one(e: dict, k: str) -> str:
    return e.get(k, [""])[0]


def audit(entries: list[dict], as_of: date) -> list[Finding]:
    out: list[Finding] = []
    users = [e for e in entries if "posixAccount" in e.get("objectClass", [])]
    groups = [e for e in entries if "posixGroup" in e.get("objectClass", [])]
    uids = {_one(u, "uid") for u in users}
    gids = {_one(g, "gidNumber") for g in groups}

    by_uid, by_num = defaultdict(list), defaultdict(list)
    for u in users:
        by_uid[_one(u, "uid")].append(u)
        by_num[_one(u, "uidNumber")].append(_one(u, "uid"))
    for uid, us in by_uid.items():
        if len(us) > 1:
            out.append(Finding("critical", "ldap", "duplicate-uid", f"{uid} appears {len(us)} times"))
    for num, names in by_num.items():
        if len(set(names)) > 1:
            out.append(Finding("critical", "ldap", "duplicate-uidnumber", f"uidNumber {num} shared by {', '.join(sorted(set(names)))}"))

    epoch = date(1970, 1, 1)
    for u in users:
        uid = _one(u, "uid")
        for attr in ("homeDirectory", "loginShell", "gidNumber"):
            if not _one(u, attr):
                out.append(Finding("warn", "ldap", "missing-attribute", f"{uid} has no {attr}"))
        if _one(u, "gidNumber") and _one(u, "gidNumber") not in gids:
            out.append(Finding("warn", "ldap", "orphan-gid", f"{uid} primary gid {_one(u, 'gidNumber')} has no group"))
        exp = _one(u, "shadowExpire")
        if exp.lstrip("-").isdigit() and int(exp) >= 0:
            if (epoch.toordinal() + int(exp)) < as_of.toordinal() and _one(u, "loginShell") not in NOLOGIN:
                out.append(Finding("warn", "ldap", "expired-with-shell", f"{uid} expired but still has {_one(u, 'loginShell') or 'a shell'}"))

    for g in groups:
        for m in g.get("memberUid", []):
            if m not in uids:
                out.append(Finding("warn", "ldap", "stale-member", f"group {_one(g, 'cn')} lists {m}, who has no account"))
    return sorted(out, key=lambda f: (f.severity != "critical", f.check, f.message))
