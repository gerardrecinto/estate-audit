"""Facts for the Linux host this runs on, in the inventory format. Standard library only."""
from __future__ import annotations

import glob
import os
import shutil
import socket
import subprocess
from datetime import date, datetime, timezone

SKIP_FS = {"tmpfs", "devtmpfs", "overlay", "squashfs", "proc", "sysfs", "efivarfs"}


def _os_name() -> str:
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "linux"


def _last_patched() -> str | None:
    """Newest mtime among package manager logs. A proxy, not a ledger: say so in reports."""
    newest = 0.0
    for pat in ("/var/log/dpkg.log*", "/var/log/apt/history.log*", "/var/log/dnf.log*", "/var/log/yum.log*"):
        for p in glob.glob(pat):
            try:
                newest = max(newest, os.path.getmtime(p))
            except OSError:
                pass
    if not newest:
        return None
    return datetime.fromtimestamp(newest, timezone.utc).date().isoformat()


def _mounts() -> list[tuple[str, str]]:
    out = []
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            for line in f:
                dev, mnt, fs = line.split()[:3]
                if fs in SKIP_FS or (not dev.startswith("/") and not fs.startswith("nfs")):
                    continue
                out.append((mnt, fs))
    except OSError:
        pass
    return out


def collect() -> dict:
    vols, seen = [], set()
    for mnt, fs in _mounts():
        if mnt in seen:
            continue
        seen.add(mnt)
        try:
            u = shutil.disk_usage(mnt)
        except OSError:
            continue
        gb = 1024 ** 3
        vols.append({
            "name": mnt,
            "kind": "nas" if fs.startswith("nfs") else "local",
            "size_gb": round(u.total / gb, 2),
            "history": [{"date": date.today().isoformat(), "used_gb": round(u.used / gb, 2)}],
        })
    return {
        "name": socket.gethostname(),
        "os": "linux",
        "os_name": _os_name(),
        "role": "unspecified",
        "last_patched": _last_patched(),
        "certs": [],
        "volumes": vols,
    }
