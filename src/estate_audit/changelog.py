"""Maintenance log: one JSON object per line, each linked to the one before by SHA-256.

Editing or deleting an earlier line breaks every hash after it, and verify says where.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

ZERO = "0" * 64


def _digest(prev: str, entry: dict) -> str:
    body = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + body).encode()).hexdigest()


def read(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def add(path: str, host: str, kind: str, summary: str, ts: str | None = None) -> dict:
    rows = read(path)
    prev = rows[-1]["hash"] if rows else ZERO
    entry = {
        "seq": len(rows) + 1,
        "ts": ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host,
        "kind": kind,
        "summary": summary,
        "prev": prev,
    }
    entry["hash"] = _digest(prev, {k: v for k, v in entry.items() if k != "hash"})
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def verify(path: str) -> tuple[bool, str]:
    prev = ZERO
    rows = read(path)
    for i, row in enumerate(rows, 1):
        body = {k: v for k, v in row.items() if k != "hash"}
        if row.get("seq") != i or row.get("prev") != prev or row.get("hash") != _digest(prev, body):
            return False, f"entry {i} does not match the chain"
        prev = row["hash"]
    return True, f"{len(rows)} entries, chain intact"
