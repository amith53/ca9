# Supported SCA Formats

ca9 auto-detects the SCA report format. You don't need to specify which tool generated it.

## Snyk

### Generating a report

```bash
snyk test --json > snyk-report.json
```

### Supported layouts

ca9 handles both single-project and multi-project Snyk outputs:

- **Single project** — the JSON root contains a `vulnerabilities` array
- **Multi-project** — the JSON root is an array of project objects, each with its own `vulnerabilities` array

### Fields extracted

| Field | Source |
|---|---|
| ID | `vulnerability.id` |
| Package name | `vulnerability.packageName` |
| Version | `vulnerability.version` |
| Severity | `vulnerability.severity` |
| Title | `vulnerability.title` |
| Description | `vulnerability.description` |

---

## Dependabot (GitHub)

### Generating a report

Export alerts via the GitHub CLI:

```bash
gh api repos/{owner}/{repo}/dependabot/alerts > dependabot.json
```

Or use the GitHub REST API directly:

```bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/{owner}/{repo}/dependabot/alerts \
  > dependabot.json
```

### Fields extracted

| Field | Source |
|---|---|
| ID | `alert.security_advisory.ghsa_id` or `cve_id` or alert number |
| Package name | `alert.dependency.package.name` |
| Version | `alert.security_vulnerability.vulnerable_version_range` |
| Severity | `alert.security_advisory.severity` |
| Title | `alert.security_advisory.summary` |
| Description | `alert.security_advisory.description` |

---

## Adding a new parser

ca9 uses a protocol-based parser architecture. To add support for a new SCA tool:

1. Create a new file in `src/ca9/parsers/`
2. Implement the `SCAParser` protocol:

```python
from ca9.parsers.base import SCAParser
from ca9.models import Vulnerability

class MyToolParser:
    def can_parse(self, data: Any) -> bool:
        """Return True if this parser can handle the given data."""
        ...

    def parse(self, data: Any) -> list[Vulnerability]:
        """Parse the data into a list of Vulnerability objects."""
        ...
```

3. Register it in `src/ca9/parsers/__init__.py`

The `detect_parser` function tries each registered parser in order and returns the first one where `can_parse()` returns `True`.
