"""Estate checks. Each returns a list of Finding. Severity: critical, warn."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .inventory import Server, Volume

PATCH_WARN_DAYS = 30
PATCH_CRIT_DAYS = 60
CERT_WARN_DAYS = 30
VOLUME_FULL_PCT = 90.0
FORECAST_WARN_DAYS = 90
FORECAST_CRIT_DAYS = 30
MIN_HISTORY = 5


@dataclass(frozen=True)
class Finding:
    severity: str
    host: str
    check: str
    message: str


def patch_age(s: Server, as_of: date) -> list[Finding]:
    if s.last_patched is None:
        return [Finding("warn", s.name, "patch", "no patch date recorded")]
    age = (as_of - s.last_patched).days
    if age > PATCH_CRIT_DAYS:
        return [Finding("critical", s.name, "patch", f"last patched {age} days ago")]
    if age > PATCH_WARN_DAYS:
        return [Finding("warn", s.name, "patch", f"last patched {age} days ago")]
    return []


def cert_expiry(s: Server, as_of: date) -> list[Finding]:
    out = []
    for c in s.certs:
        left = (c.not_after - as_of).days
        if left < 0:
            out.append(Finding("critical", s.name, "cert", f"{c.subject} expired {-left} days ago"))
        elif left <= CERT_WARN_DAYS:
            sev = "critical" if left <= 7 else "warn"
            out.append(Finding(sev, s.name, "cert", f"{c.subject} expires in {left} days"))
    return out


def fit(points: list[tuple[float, float]]) -> tuple[float, float]:
    """Least squares y = a + b*x. Returns (a, b)."""
    n = len(points)
    sx = sum(x for x, _ in points)
    sy = sum(y for _, y in points)
    sxx = sum(x * x for x, _ in points)
    sxy = sum(x * y for x, y in points)
    den = n * sxx - sx * sx
    if den == 0:
        return (sy / n, 0.0)
    b = (n * sxy - sx * sy) / den
    return ((sy - b * sx) / n, b)


def days_to_full(v: Volume) -> float | None:
    """Days until used space reaches VOLUME_FULL_PCT, by a straight line through the history.

    None when there are fewer than MIN_HISTORY points or usage is flat or falling.
    """
    if len(v.history) < MIN_HISTORY:
        return None
    d0 = v.history[0][0]
    _, slope = fit([((d - d0).days, used) for d, used in v.history])
    if slope <= 0:
        return None
    limit = v.size_gb * VOLUME_FULL_PCT / 100
    remaining = limit - v.history[-1][1]
    return max(remaining, 0.0) / slope


def volume_checks(s: Server) -> list[Finding]:
    out = []
    for v in s.volumes:
        label = f"{v.name} ({v.kind})"
        if v.history:
            pct = v.history[-1][1] / v.size_gb * 100
            if pct >= VOLUME_FULL_PCT:
                out.append(Finding("critical", s.name, "volume", f"{label} is {pct:.0f}% full"))
                continue
        days = days_to_full(v)
        if days is None:
            continue
        if days < FORECAST_CRIT_DAYS:
            out.append(Finding("critical", s.name, "volume", f"{label} reaches {VOLUME_FULL_PCT:.0f}% in {days:.0f} days"))
        elif days < FORECAST_WARN_DAYS:
            out.append(Finding("warn", s.name, "volume", f"{label} reaches {VOLUME_FULL_PCT:.0f}% in {days:.0f} days"))
    return out


def run_all(servers: list[Server], as_of: date) -> list[Finding]:
    out: list[Finding] = []
    for s in servers:
        out += patch_age(s, as_of) + cert_expiry(s, as_of) + volume_checks(s)
    return sorted(out, key=lambda f: (f.severity != "critical", f.host, f.check))
