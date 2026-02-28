# ca9

**Static & dynamic reachability analysis to cut CVE noise.**

<p align="center">
  <img src="assets/ca9.png" alt="ca9 logo" width="400">
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://mozilla.org/MPL/2.0/"><img src="https://img.shields.io/badge/license-MPL--2.0-blue.svg" alt="License: MPL-2.0"></a>
  <img src="https://img.shields.io/badge/Skylos-A%2B%20%2899%29-brightgreen" alt="Skylos A+ (99)">
</p>

---

SCA tools like Snyk and Dependabot flag every known CVE in your dependency tree — but most are in code your application never calls. **ca9** determines whether vulnerable dependency code is actually *reachable*, reducing false-positive alerts so you can focus on what matters.

## How it works

ca9 combines three techniques to produce a verdict for each CVE:

1. **Static analysis (AST)** — traces `import` statements to check if vulnerable packages are used
2. **Transitive dependency resolution** — uses `importlib.metadata` to map indirect dependencies back to root packages
3. **Dynamic analysis (coverage.py)** — checks whether vulnerable code was actually *executed* during tests

Each vulnerability receives one of four verdicts:

| Verdict | Meaning |
|---|---|
| `REACHABLE` | Package is imported and code was executed in tests |
| `UNREACHABLE (static)` | Package is never imported and is not a transitive dependency |
| `UNREACHABLE (dynamic)` | Package is imported but no code was executed in tests |
| `INCONCLUSIVE` | Cannot determine without coverage data |

## Key features

- **Zero runtime dependencies** — stdlib-only core; only `click` needed for the CLI
- **Multiple SCA formats** — Snyk JSON and Dependabot alerts supported out of the box
- **Submodule-level precision** — identifies the specific vulnerable submodule, not just the package
- **4-strategy affected component extraction** — commit analysis, curated mappings, regex extraction, and class name resolution
- **JSON and table output** — machine-readable or human-friendly reports
- **Python 3.10+** — tested on 3.10, 3.11, 3.12, and 3.13

## Quick example

```bash
# Analyze a Snyk report
ca9 check snyk-report.json --repo . --coverage coverage.json

# Scan installed packages directly (no SCA report needed)
ca9 scan --coverage coverage.json
```

```
┌──────────────────┬─────────┬─────────────────────────────────┬──────────────────────┐
│ CVE              │ Package │ Verdict                         │ Severity             │
├──────────────────┼─────────┼─────────────────────────────────┼──────────────────────┤
│ GHSA-abcd-1234   │ jinja2  │ UNREACHABLE (static)            │ high                 │
│ CVE-2024-5678    │ django  │ REACHABLE                       │ critical             │
│ GHSA-efgh-9012   │ urllib3 │ UNREACHABLE (dynamic)           │ medium               │
└──────────────────┴─────────┴─────────────────────────────────┴──────────────────────┘

Summary: 3 CVEs analyzed — 1 reachable, 2 unreachable (67% noise reduction)
```
