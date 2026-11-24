from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from . import changelog, checks, facts_linux, inventory, ldapaudit, report


def _check(a) -> int:
    as_of, servers = inventory.load(a.inventory)
    findings = checks.run_all(servers, as_of)
    if a.ldif:
        with open(a.ldif, encoding="utf-8") as f:
            findings += ldapaudit.audit(ldapaudit.parse_ldif(f.read()), as_of)
    if a.html:
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(report.html_report(servers, findings, as_of))
    if a.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        sys.stdout.write(report.text(findings, len(servers)))
    return 1 if any(f.severity == "critical" for f in findings) else 0


def _ldap(a) -> int:
    with open(a.ldif, encoding="utf-8") as f:
        findings = ldapaudit.audit(ldapaudit.parse_ldif(f.read()), date.fromisoformat(a.as_of) if a.as_of else date.today())
    sys.stdout.write(report.text(findings, 0).replace("0 servers checked: ", "ldap: "))
    return 1 if any(f.severity == "critical" for f in findings) else 0


def _log(a) -> int:
    if a.action == "add":
        e = changelog.add(a.file, a.host, a.kind, a.summary, a.ts)
        print(f"#{e['seq']} {e['hash'][:12]}")
        return 0
    ok, msg = changelog.verify(a.file)
    print(msg)
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="estate-audit")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="patch age, certificates, volumes, optional LDAP")
    c.add_argument("inventory")
    c.add_argument("--ldif")
    c.add_argument("--html")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=_check)

    l = sub.add_parser("ldap", help="account hygiene from an LDIF dump")
    l.add_argument("ldif")
    l.add_argument("--as-of")
    l.set_defaults(fn=_ldap)

    g = sub.add_parser("log", help="tamper-evident maintenance log")
    g.add_argument("action", choices=["add", "verify"])
    g.add_argument("file")
    g.add_argument("--host")
    g.add_argument("--kind")
    g.add_argument("--summary")
    g.add_argument("--ts")
    g.set_defaults(fn=_log)

    f = sub.add_parser("facts-linux", help="print facts for this Linux host as inventory JSON")
    f.set_defaults(fn=lambda a: print(json.dumps(facts_linux.collect(), indent=2)) or 0)

    a = p.parse_args(argv)
    if a.cmd == "log" and a.action == "add" and not (a.host and a.kind and a.summary):
        p.error("log add needs --host, --kind and --summary")
    try:
        return a.fn(a)
    except (inventory.InventoryError, OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
