# Dynamic Analysis with Coverage

Dynamic analysis uses [coverage.py](https://coverage.readthedocs.io/) data to determine whether vulnerable code was actually *executed* during your test suite. This is ca9's most powerful technique — it can prove that imported code was never reached at runtime.

## Why it matters

Static analysis tells you *if* a package is imported. Dynamic analysis tells you *if that code actually ran*. This distinction matters:

- A package might be imported but only used in a code path your tests don't exercise
- A vulnerable submodule might exist in an imported package but never be called
- Transitive dependencies might be installed but never loaded at runtime

## Generating coverage data

### Step 1: Run tests with coverage

```bash
pip install coverage
coverage run -m pytest
```

### Step 2: Export as JSON

```bash
coverage json
```

This creates `coverage.json` in the current directory.

!!! important
    ca9 reads the **JSON** format from coverage.py, not the XML or HTML formats. Make sure to use `coverage json`.

### Step 3: Pass to ca9

```bash
ca9 check snyk-report.json --coverage coverage.json
# or
ca9 scan --coverage coverage.json
```

## How ca9 uses coverage data

The coverage JSON contains a mapping of filenames to executed line numbers. ca9 uses this to:

1. **Package-level check** — Did *any* file from the package execute?
    - Matches paths like `site-packages/package_name/` or `/package_name/`
2. **Submodule-level check** — Did the *specific vulnerable submodule* execute?
    - Maps dotted paths to filesystem patterns (e.g., `jinja2.sandbox` → `site-packages/jinja2/sandbox/`)
    - Also checks `file_hints` extracted from CVE metadata

## Verdicts with and without coverage

| Scenario | Without coverage | With coverage |
|---|---|---|
| Package not imported | `UNREACHABLE (static)` | `UNREACHABLE (static)` |
| Package imported, code not executed | `INCONCLUSIVE` | `UNREACHABLE (dynamic)` |
| Package imported, code executed | `INCONCLUSIVE` | `REACHABLE` |

Without coverage, ca9 can only distinguish between "imported" and "not imported." With coverage, it can further distinguish between "imported but never executed" and "imported and executed."

## Tips for better results

- **Maximize test coverage** — the more code your tests exercise, the more precise ca9's dynamic analysis becomes
- **Include integration tests** — unit tests with heavy mocking may not trigger real dependency code
- **Run coverage in your CI pipeline** — generate `coverage.json` as a build artifact and feed it to ca9
