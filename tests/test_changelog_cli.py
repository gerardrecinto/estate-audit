import json
import subprocess
import sys
from pathlib import Path

from estate_audit import changelog, cli

ROOT = Path(__file__).parent.parent


def test_chain_verifies_then_detects_an_edit(tmp_path):
    p = str(tmp_path / "log.jsonl")
    for i in range(3):
        changelog.add(p, "h1", "patch", f"step {i}", ts=f"2026-11-0{i + 1}T00:00:00Z")
    assert changelog.verify(p) == (True, "3 entries, chain intact")
    rows = [json.loads(l) for l in open(p)]
    rows[1]["summary"] = "nothing happened"
    open(p, "w").write("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n")
    ok, msg = changelog.verify(p)
    assert not ok and "entry 2" in msg


def test_deleting_an_entry_is_detected(tmp_path):
    p = str(tmp_path / "log.jsonl")
    for i in range(3):
        changelog.add(p, "h", "k", str(i), ts="2026-11-01T00:00:00Z")
    lines = open(p).read().splitlines()
    open(p, "w").write("\n".join([lines[0], lines[2]]) + "\n")
    assert changelog.verify(p)[0] is False


def test_empty_log_is_valid(tmp_path):
    assert changelog.verify(str(tmp_path / "none.jsonl"))[0] is True


def test_cli_exit_codes(tmp_path, capsys):
    inv = ROOT / "data" / "sample_inventory.json"
    assert cli.main(["check", str(inv)]) == 1  # sample has critical findings
    clean = tmp_path / "ok.json"
    clean.write_text(json.dumps({"as_of": "2026-11-24", "servers": [{"name": "a", "os": "linux", "last_patched": "2026-11-20"}]}))
    assert cli.main(["check", str(clean)]) == 0
    assert cli.main(["check", str(tmp_path / "missing.json")]) == 2
    out = capsys.readouterr()
    assert "no findings" in out.out and "error:" in out.err


def test_cli_html_report_is_self_contained(tmp_path):
    out = tmp_path / "r.html"
    cli.main(["check", str(ROOT / "data" / "sample_inventory.json"), "--ldif", str(ROOT / "data" / "sample.ldif"), "--html", str(out)])
    page = out.read_text()
    assert "<script" not in page and "http" not in page.replace("http-equiv", "")
    assert "lin-nas-01" in page and "duplicate-uidnumber" in page


def test_facts_linux_matches_inventory_format():
    from estate_audit import facts_linux, inventory
    facts = facts_linux.collect()
    as_of, servers = inventory.parse(facts)
    assert servers[0].os == "linux"


def test_module_entrypoint():
    r = subprocess.run([sys.executable, "-m", "estate_audit", "log", "verify", "/nonexistent"], capture_output=True, text=True, cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")})
    assert r.returncode == 0 and "0 entries" in r.stdout


def test_sample_inventory_is_what_the_generator_writes(tmp_path):
    import shutil
    (tmp_path / "data").mkdir()
    shutil.copy(ROOT / "data" / "make_sample_data.py", tmp_path / "data")
    subprocess.run([sys.executable, "data/make_sample_data.py"], cwd=tmp_path, check=True)
    assert (tmp_path / "data" / "sample_inventory.json").read_text() == (ROOT / "data" / "sample_inventory.json").read_text()
