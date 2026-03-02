from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import click
except ImportError:
    print("ca9 CLI requires 'click'. Install with: pip install ca9[cli]", file=sys.stderr)
    sys.exit(1)

from ca9.config import find_config, load_config
from ca9.engine import analyze
from ca9.parsers import detect_parser
from ca9.report import write_json, write_sarif, write_table


def _output_report(
    report,
    output_format: str,
    output_path: Path | None,
    verbose: bool = False,
) -> None:
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        text = write_json(report)
        if output_path:
            output_path.write_text(text)
        else:
            click.echo(text)
    elif output_format == "sarif":
        text = write_sarif(report)
        if output_path:
            output_path.write_text(text)
        else:
            click.echo(text)
    else:
        if output_path:
            with open(output_path, "w") as f:
                write_table(report, f, verbose=verbose)
        else:
            write_table(report, sys.stdout, verbose=verbose)


class DefaultGroup(click.Group):
    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["check"] + args
        return super().parse_args(ctx, args)


def _load_cli_config() -> dict:
    """Load .ca9.toml config, mapping keys to CLI parameter names."""
    config_path = find_config()
    if not config_path:
        return {}
    raw = load_config(config_path)
    mapping = {
        "repo": "repo_path",
        "coverage": "coverage_path",
        "format": "output_format",
        "output": "output_path",
        "verbose": "verbose",
    }
    result = {}
    for toml_key, param_name in mapping.items():
        if toml_key in raw:
            val = raw[toml_key]
            if toml_key in ("repo", "coverage", "output"):
                val = Path(val)
            result[param_name] = val
    return result


@click.group(cls=DefaultGroup)
@click.pass_context
def main(ctx):
    ctx.ensure_object(dict)
    ctx.obj["config"] = _load_cli_config()


def _get_config_default(ctx: click.Context, param_name: str, fallback):
    """Return config file value if the CLI option was not explicitly set."""
    config = ctx.obj.get("config", {}) if ctx.obj else {}
    return config.get(param_name, fallback)


@main.command()
@click.argument("sca_report", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-r",
    "--repo",
    "repo_path",
    type=click.Path(exists=True, path_type=Path),
    default=".",
    help="Path to the project repository.",
)
@click.option(
    "-c",
    "--coverage",
    "coverage_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to coverage.json for dynamic analysis.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    help="Output format.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "-v", "--verbose", is_flag=True, default=False, help="Show reasoning trace for each verdict."
)
@click.pass_context
def check(
    ctx: click.Context,
    sca_report: Path,
    repo_path: Path,
    coverage_path: Path | None,
    output_format: str,
    output_path: Path | None,
    verbose: bool,
) -> None:
    coverage_path = coverage_path or _get_config_default(ctx, "coverage_path", None)
    output_format = (
        output_format
        if output_format != "table"
        else _get_config_default(ctx, "output_format", output_format)
    )
    verbose = verbose or _get_config_default(ctx, "verbose", False)
    try:
        data = json.loads(sca_report.read_text())
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in {sca_report}: {e}") from None
    except OSError as e:
        raise click.ClickException(f"Cannot read {sca_report}: {e}") from None

    try:
        parser = detect_parser(sca_report)
    except ValueError as e:
        raise click.ClickException(str(e)) from None

    vulnerabilities = parser.parse(data)

    if not vulnerabilities:
        click.echo("No vulnerabilities found in the report.")
        return

    report = analyze(vulnerabilities, repo_path, coverage_path)
    _output_report(report, output_format, output_path, verbose=verbose)
    sys.exit(report.exit_code)


@main.command()
@click.option(
    "-r",
    "--repo",
    "repo_path",
    type=click.Path(exists=True, path_type=Path),
    default=".",
    help="Path to the project repository.",
)
@click.option(
    "-c",
    "--coverage",
    "coverage_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to coverage.json for dynamic analysis.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    help="Output format.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "-v", "--verbose", is_flag=True, default=False, help="Show reasoning trace for each verdict."
)
@click.pass_context
def scan(
    ctx: click.Context,
    repo_path: Path,
    coverage_path: Path | None,
    output_format: str,
    output_path: Path | None,
    verbose: bool,
) -> None:
    from ca9.scanner import get_installed_packages, query_osv_batch

    coverage_path = coverage_path or _get_config_default(ctx, "coverage_path", None)
    output_format = (
        output_format
        if output_format != "table"
        else _get_config_default(ctx, "output_format", output_format)
    )
    verbose = verbose or _get_config_default(ctx, "verbose", False)

    click.echo("Scanning installed packages...", err=True)
    packages = get_installed_packages()
    click.echo(f"Found {len(packages)} installed packages. Querying OSV.dev...", err=True)

    try:
        vulnerabilities = query_osv_batch(packages)
    except (ConnectionError, ValueError) as e:
        raise click.ClickException(str(e)) from None

    if not vulnerabilities:
        click.echo("No known vulnerabilities found in installed packages.")
        return

    click.echo(
        f"Found {len(vulnerabilities)} known vulnerabilities. Analyzing reachability...", err=True
    )
    report = analyze(vulnerabilities, repo_path, coverage_path)
    _output_report(report, output_format, output_path, verbose=verbose)
    sys.exit(report.exit_code)


if __name__ == "__main__":
    main()
