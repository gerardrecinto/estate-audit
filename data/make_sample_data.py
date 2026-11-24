"""Write data/sample_inventory.json deterministically. Synthetic: no real host, person or customer."""
import json
from datetime import date, timedelta

AS_OF = date(2026, 11, 24)


def hist(start_used, per_day, days=60, step=5):
    out = []
    for i in range(0, days + 1, step):
        d = AS_OF - timedelta(days=days - i)
        out.append({"date": d.isoformat(), "used_gb": round(start_used + per_day * i, 1)})
    return out


def srv(name, os_, role, patched_days_ago, certs=(), volumes=()):
    return {
        "name": name, "os": os_, "role": role,
        "last_patched": (AS_OF - timedelta(days=patched_days_ago)).isoformat(),
        "certs": [{"subject": s, "not_after": (AS_OF + timedelta(days=d)).isoformat()} for s, d in certs],
        "volumes": list(volumes),
    }


def vol(name, kind, size, start, per_day):
    return {"name": name, "kind": kind, "size_gb": size, "history": hist(start, per_day)}


servers = [
    srv("lin-ldap-01", "linux", "directory", 12, [("ldap.corp.example", 210)], [vol("/var/lib/ldap", "local", 100, 20, 0.02)]),
    srv("lin-ldap-02", "linux", "directory", 12, [("ldap.corp.example", 210)], [vol("/var/lib/ldap", "local", 100, 20, 0.02)]),
    srv("lin-web-01", "linux", "apache", 9, [("www.corp.example", 25)], [vol("/var/www", "local", 200, 80, 0.4)]),
    srv("lin-web-02", "linux", "apache", 71, [("www.corp.example", 25)], [vol("/var/www", "local", 200, 82, 0.4)]),
    srv("lin-mail-01", "linux", "mail-relay", 18, [("smtp.corp.example", 5)], [vol("/var/spool", "local", 100, 10, 0.05)]),
    srv("lin-nas-01", "linux", "file-server", 22, [], [
        vol("/export/labs", "nas", 20000, 14000, 55),
        vol("/export/home", "nas", 8000, 3000, 6),
    ]),
    srv("lin-hpc-01", "linux", "compute", 35, [], [vol("/scratch", "san", 50000, 30000, 120)]),
    srv("win-ad-01", "windows", "domain-controller", 14, [("dc01.corp.example", 300)], [vol("C:", "local", 200, 90, 0.2)]),
    srv("win-ad-02", "windows", "domain-controller", 14, [("dc02.corp.example", 300)], [vol("C:", "local", 200, 88, 0.2)]),
    srv("win-sql-01", "windows", "sql-server", 40, [], [
        vol("D:", "san", 4000, 2500, 12),
        vol("L:", "san", 500, 300, 0.5),
    ]),
    srv("win-iis-01", "windows", "iis", 8, [("apps.corp.example", 45)], [vol("C:", "local", 250, 120, 0.3)]),
    srv("win-file-01", "windows", "file-server", 16, [], [vol("E:", "nas", 10000, 9000, 14)]),
]

with open("data/sample_inventory.json", "w") as f:
    json.dump({"as_of": AS_OF.isoformat(), "servers": servers}, f, indent=1)
    f.write("\n")
