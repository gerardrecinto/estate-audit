from datetime import date, timedelta

from estate_audit import checks
from estate_audit.inventory import Cert, InventoryError, Server, Volume, parse

import pytest

TODAY = date(2026, 11, 24)


def server(**kw):
    base = dict(name="h", os="linux", role="r", last_patched=TODAY, certs=[], volumes=[])
    base.update(kw)
    return Server(**base)


def vol(size, start, per_day, n=10, kind="nas"):
    hist = [(TODAY - timedelta(days=n - 1 - i), start + per_day * i) for i in range(n)]
    return Volume("v", kind, size, hist)


def test_patch_thresholds():
    assert checks.patch_age(server(last_patched=TODAY - timedelta(days=30)), TODAY) == []
    assert checks.patch_age(server(last_patched=TODAY - timedelta(days=31)), TODAY)[0].severity == "warn"
    assert checks.patch_age(server(last_patched=TODAY - timedelta(days=61)), TODAY)[0].severity == "critical"


def test_unknown_patch_date_is_a_finding_not_a_pass():
    assert checks.patch_age(server(last_patched=None), TODAY)[0].message == "no patch date recorded"


def test_cert_expiry_bands():
    c = lambda d: server(certs=[Cert("x", TODAY + timedelta(days=d))])
    assert checks.cert_expiry(c(31), TODAY) == []
    assert checks.cert_expiry(c(30), TODAY)[0].severity == "warn"
    assert checks.cert_expiry(c(7), TODAY)[0].severity == "critical"
    assert "expired 2 days ago" in checks.cert_expiry(c(-2), TODAY)[0].message


def test_days_to_full_is_exact_on_a_straight_line():
    v = vol(size=1000, start=100, per_day=10)  # last used 190, limit 900, slope 10
    assert checks.days_to_full(v) == pytest.approx(71.0)


def test_flat_or_falling_usage_has_no_forecast():
    assert checks.days_to_full(vol(1000, 500, 0)) is None
    assert checks.days_to_full(vol(1000, 500, -1)) is None


def test_too_little_history_has_no_forecast():
    assert checks.days_to_full(vol(1000, 100, 10, n=4)) is None


def test_volume_bands():
    assert checks.volume_checks(server(volumes=[vol(1000, 100, 10)]))[0].severity == "warn"      # 71 days
    assert checks.volume_checks(server(volumes=[vol(1000, 500, 30)]))[0].severity == "critical"  # ~6 days
    assert checks.volume_checks(server(volumes=[vol(10000, 100, 1)])) == []


def test_already_full_is_critical_even_without_trend():
    v = Volume("C:", "local", 100, [(TODAY, 95.0)])
    f = checks.volume_checks(server(volumes=[v]))
    assert f[0].severity == "critical" and "95% full" in f[0].message


def test_findings_sorted_critical_first():
    s = [server(name="b", last_patched=TODAY - timedelta(days=40)), server(name="a", last_patched=TODAY - timedelta(days=90))]
    out = checks.run_all(s, TODAY)
    assert [f.severity for f in out] == ["critical", "warn"]


def test_single_server_object_is_accepted():
    as_of, servers = parse({"name": "w", "os": "windows", "last_patched": "2026-11-01", "volumes": []})
    assert servers[0].name == "w" and as_of == date.today()


@pytest.mark.parametrize("doc,msg", [
    ({"servers": [{"os": "linux"}]}, "without a name"),
    ({"servers": [{"name": "x", "os": "plan9"}]}, "os must be"),
    ({"servers": [{"name": "x", "os": "linux", "last_patched": "soon"}]}, "bad date"),
    ({"servers": [{"name": "x", "os": "linux", "volumes": [{"name": "v", "kind": "tape", "size_gb": 1}]}]}, "kind must be"),
])
def test_bad_inventory_is_rejected_with_a_reason(doc, msg):
    with pytest.raises(InventoryError, match=msg):
        parse(doc)
