"""Text and HTML reports. The HTML is one self-contained file: no scripts, no network."""
from __future__ import annotations

import html
from datetime import date

from .checks import VOLUME_FULL_PCT, Finding, days_to_full, fit
from .inventory import Server, Volume


def text(findings: list[Finding], n_servers: int) -> str:
    if not findings:
        return f"{n_servers} servers checked, no findings.\n"
    crit = sum(f.severity == "critical" for f in findings)
    lines = [f"{n_servers} servers checked: {crit} critical, {len(findings) - crit} warn"]
    for f in findings:
        lines.append(f"  {f.severity.upper():8} {f.host:18} {f.check:20} {f.message}")
    return "\n".join(lines) + "\n"


def _spark(v: Volume) -> str:
    """Inline SVG: used GB over time, the 90% line, and the fitted trend."""
    if len(v.history) < 2:
        return ""
    w, h = 220, 44
    d0 = v.history[0][0]
    xs = [(d - d0).days for d, _ in v.history]
    ys = [u for _, u in v.history]
    xmax = max(xs) or 1
    ymax = max(v.size_gb, max(ys))
    px = lambda x: 4 + (w - 8) * x / xmax
    py = lambda y: h - 4 - (h - 8) * y / ymax
    pts = " ".join(f"{px(x):.1f},{py(y):.1f}" for x, y in zip(xs, ys))
    a, b = fit(list(zip(xs, ys)))
    trend = f'<line x1="{px(0):.1f}" y1="{py(a):.1f}" x2="{px(xmax):.1f}" y2="{py(a + b * xmax):.1f}" stroke="#94a3b8" stroke-dasharray="3 3"/>'
    lim = py(v.size_gb * VOLUME_FULL_PCT / 100)
    return (f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="used space over time">'
            f'<line x1="4" x2="{w - 4}" y1="{lim:.1f}" y2="{lim:.1f}" stroke="#dc2626" stroke-width="1"/>{trend}'
            f'<polyline points="{pts}" fill="none" stroke="#0f172a" stroke-width="1.6"/></svg>')


def html_report(servers: list[Server], findings: list[Finding], as_of: date) -> str:
    e = html.escape
    crit = sum(f.severity == "critical" for f in findings)
    rows = "".join(
        f'<tr class="{f.severity}"><td>{e(f.severity)}</td><td>{e(f.host)}</td><td>{e(f.check)}</td><td>{e(f.message)}</td></tr>'
        for f in findings) or '<tr><td colspan="4">No findings.</td></tr>'
    vol_rows = ""
    for s in servers:
        for v in s.volumes:
            d = days_to_full(v)
            used = f"{v.history[-1][1]:.0f} / {v.size_gb:.0f} GB" if v.history else f"{v.size_gb:.0f} GB"
            eta = f"{d:.0f} days" if d is not None else "no trend"
            vol_rows += f"<tr><td>{e(s.name)}</td><td>{e(v.name)}</td><td>{e(v.kind)}</td><td>{used}</td><td>{eta}</td><td>{_spark(v)}</td></tr>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>estate-audit report</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;margin:0;color:#0f172a;background:#f8fafc}}
main{{max-width:980px;margin:0 auto;padding:24px 16px}}
h1{{font-size:1.5rem;margin:0 0 4px}} h2{{font-size:1.05rem;margin:28px 0 8px}}
p.sub{{color:#475569;margin:0 0 16px}}
table{{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e2e8f0}}
th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid #e2e8f0;vertical-align:middle}}
th{{background:#f1f5f9;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}}
tr.critical td:first-child{{color:#b91c1c;font-weight:600}} tr.warn td:first-child{{color:#b45309;font-weight:600}}
.wrap{{overflow-x:auto}}
</style></head><body><main>
<h1>estate-audit report</h1>
<p class="sub">As of {as_of.isoformat()}. {len(servers)} servers, {crit} critical, {len(findings) - crit} warn. Synthetic sample data.</p>
<h2>Findings</h2><div class="wrap"><table><tr><th>Severity</th><th>Host</th><th>Check</th><th>Detail</th></tr>{rows}</table></div>
<h2>Volumes (solid: used, dashed: trend, red: {VOLUME_FULL_PCT:.0f}% line)</h2>
<div class="wrap"><table><tr><th>Host</th><th>Volume</th><th>Kind</th><th>Used</th><th>To {VOLUME_FULL_PCT:.0f}%</th><th>History</th></tr>{vol_rows}</table></div>
</main></body></html>
"""
