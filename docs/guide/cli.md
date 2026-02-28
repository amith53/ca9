# CLI Reference

ca9 provides two main commands: `check` and `scan`.

## `ca9 check`

Analyze an existing SCA report for reachability.

```
Usage: ca9 check [OPTIONS] SCA_REPORT

  Analyse an SCA report for reachability.

Arguments:
  SCA_REPORT  Path to an SCA JSON report (Snyk or Dependabot).

Options:
  -r, --repo PATH              Project repository path [default: .]
  -c, --coverage PATH          Path to coverage.json for dynamic analysis
  -f, --format [table|json]    Output format [default: table]
  -o, --output PATH            Write output to file instead of stdout
  -v, --verbose                Show reasoning trace for each verdict
  --help                       Show this message and exit.
```

### Examples

```bash
# Basic analysis
ca9 check snyk-report.json

# With coverage data and verbose output
ca9 check snyk-report.json --repo ./myproject --coverage coverage.json --verbose

# JSON output to file
ca9 check snyk-report.json --format json --output results.json
```

!!! tip "Shorthand syntax"
    You can omit the `check` command — `ca9 report.json` is equivalent to `ca9 check report.json`.

---

## `ca9 scan`

Scan installed packages directly via [OSV.dev](https://osv.dev). No SCA report needed.

```
Usage: ca9 scan [OPTIONS]

  Scan installed packages via OSV.dev (zero setup).

Options:
  -r, --repo PATH              Project repository path [default: .]
  -c, --coverage PATH          Path to coverage.json for dynamic analysis
  -f, --format [table|json]    Output format [default: table]
  -o, --output PATH            Write output to file instead of stdout
  -v, --verbose                Show reasoning trace for each verdict
  --help                       Show this message and exit.
```

### Examples

```bash
# Scan current environment
ca9 scan

# Scan with coverage data
ca9 scan --coverage coverage.json --format json
```

!!! note
    `scan` queries the OSV.dev API, so it requires an internet connection. It discovers packages from `importlib.metadata`, meaning they must be installed in the current Python environment.

---

## Global options

```bash
ca9 --version   # Show version
ca9 --help      # Show help
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Error (invalid input, missing files, API failure) |
