"""Load an inventory: {"as_of": "YYYY-MM-DD", "servers": [...]} or one server object.

A server has name, os (linux|windows), role, last_patched (date), certs
[{subject, not_after}], volumes [{name, kind, size_gb, history: [{date, used_gb}]}].
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date

OSES = ("linux", "windows")
KINDS = ("local", "san", "nas")


class InventoryError(ValueError):
    pass


@dataclass
class Volume:
    name: str
    kind: str
    size_gb: float
    history: list[tuple[date, float]]


@dataclass
class Cert:
    subject: str
    not_after: date


@dataclass
class Server:
    name: str
    os: str
    role: str
    last_patched: date | None
    certs: list[Cert] = field(default_factory=list)
    volumes: list[Volume] = field(default_factory=list)


def _date(value, where: str) -> date:
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError as e:
        raise InventoryError(f"{where}: bad date {value!r}") from e


def _server(raw: dict) -> Server:
    name = raw.get("name")
    if not name:
        raise InventoryError("server without a name")
    if raw.get("os") not in OSES:
        raise InventoryError(f"{name}: os must be one of {OSES}")
    vols = []
    for v in raw.get("volumes", []):
        kind = v.get("kind", "local")
        if kind not in KINDS:
            raise InventoryError(f"{name}/{v.get('name')}: kind must be one of {KINDS}")
        hist = sorted((_date(h["date"], f"{name}/{v['name']}"), float(h["used_gb"])) for h in v.get("history", []))
        vols.append(Volume(v["name"], kind, float(v["size_gb"]), hist))
    certs = [Cert(c["subject"], _date(c["not_after"], f"{name} cert {c['subject']}")) for c in raw.get("certs", [])]
    lp = raw.get("last_patched")
    return Server(name, raw["os"], raw.get("role", "unspecified"), _date(lp, name) if lp else None, certs, vols)


def parse(doc: dict) -> tuple[date, list[Server]]:
    if "servers" not in doc:
        doc = {"as_of": doc.get("as_of"), "servers": [doc]}
    as_of = _date(doc["as_of"], "as_of") if doc.get("as_of") else date.today()
    return as_of, [_server(s) for s in doc["servers"]]


def load(path: str) -> tuple[date, list[Server]]:
    with open(path, encoding="utf-8") as f:
        return parse(json.load(f))
