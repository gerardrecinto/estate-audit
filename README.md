# estate-audit

[![CI](https://github.com/gerardrecinto/estate-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/gerardrecinto/estate-audit/actions/workflows/ci.yml)

Audit a mixed Linux and Windows server estate: patch age, certificate expiry, SAN and NAS volume forecasts, LDAP account hygiene, and a tamper-evident maintenance log. Python standard library only, plus a PowerShell collector for Windows.

**Sample report: https://gerardrecinto.github.io/estate-audit/report.html**

It runs on synthetic data and on the CI runners (see "What is verified").

## Run it

```bash
git clone https://github.com/gerardrecinto/estate-audit && cd estate-audit
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" && pytest -q
estate-audit check data/sample_inventory.json --ldif data/sample.ldif --html report.html
```

Python 3.11 or newer. The check exits 1 on the sample data on purpose: it has five critical findings. Exit codes: 0 clean, 1 critical findings, 2 bad input.

## What it checks

| Command | Check | Rule |
|---|---|---|
| `check` | Patch age | warn over 30 days, critical over 60, a missing date is a finding |
| `check` | Certificates | warn at 30 days, critical at 7 or expired |
| `check` | Volumes (local, SAN, NAS) | critical at 90% full, or when a straight line through the history reaches 90% in under 30 days; warn under 90 days; no forecast under 5 samples |
| `check --ldif` / `ldap` | Accounts from an LDIF dump | duplicate uid or uidNumber, missing home or shell or gid, primary gid with no group, expired account that still has a login shell, group member with no account |
| `log add` / `log verify` | Maintenance log | each line carries the SHA-256 of the one before; editing or deleting a line is reported by entry number |
| `facts-linux` | This Linux host as inventory JSON | os-release, mounts (NFS as `nas`), patch date |
| `windows/Get-ServerFacts.ps1` | This Windows host as inventory JSON | OS, newest hotfix, fixed volumes, machine certificates |

## What is verified in CI

- 27 Python tests on 3.11, 3.12 and 3.13, plus a clean install and first run from this README.
- **OpenLDAP:** the sample entries are loaded into a real `osixia/openldap` server, dumped with `ldapsearch`, and the audit must report exactly the five seeded problems.
- **Windows:** `Get-ServerFacts.ps1` runs on a `windows-latest` runner under Pester, and its JSON is read by the Python tool.
- **Linux:** `facts-linux` runs on an `ubuntu-latest` runner and feeds `check`.

## Design choices

- **A straight line for capacity.** It can be checked by hand and explained in one sentence. It misses seasonality and launches, so treat it as an early warning. I would add weekly seasonality after a year of samples.
- **Missing data is a finding.** A host with no patch date is reported, not passed.
- **The log is a hash chain, not a database.** It needs no server and a reviewer can verify it with one command. It detects edits; it does not stop someone from rewriting the whole file, so copy the last hash somewhere else (a ticket works).
- **Collectors are read-only** and print JSON. Nothing is installed on the host.
- **Linux patch date is a proxy.** It is the newest package-manager log time, not a patch ledger. A real estate should read it from the patching tool.

## What is verified

Tested: every check, the LDIF parser (folded lines, base64, `ldapsearch` noise), the log chain, and the CLI exit codes. Run for real in CI: OpenLDAP, a Windows runner and a Linux runner.


## License
MIT
