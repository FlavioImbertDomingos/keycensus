"""Command line: scan | serve | rules | collectors | validate."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from . import __version__
from .analysis.controls import CONTROLS
from .analysis.policy import Policy, rule_catalogue
from .collectors import DESCRIPTIONS, REGISTRY
from .config import ConfigError, load
from .exporters import FORMATS
from .model import SEVERITIES

SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def _setup_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


@click.group()
@click.version_option(__version__, prog_name="keycensus")
def main():
    """keycensus — a census of every cryptographic key, certificate and protocol you own."""


@main.command()
@click.option(
    "-c",
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True),
    help="Sources YAML.",
)
@click.option("-o", "--output-dir", default="./out", show_default=True, help="Where to write the reports.")
@click.option("-f", "--format", "formats", multiple=True, default=("json", "cbom", "csv", "html"),
              type=click.Choice(sorted(FORMATS)), show_default=True, help="Repeatable.")  # fmt: skip
@click.option("-p", "--policy", "policy_path", default=None, help="Policy YAML (default: built-in).")
@click.option("--fail-on", default=None, type=click.Choice(SEVERITIES),
              help="Exit 1 if any finding is at least this severe (for CI).")  # fmt: skip
@click.option("-v", "--verbose", is_flag=True)
def scan(config_path, output_dir, formats, policy_path, fail_on, verbose):
    """Collect from every source, apply the policy, write reports."""
    _setup_logging(verbose)
    from .scanner import scan as run_scan

    try:
        config = load(config_path)
        policy = Policy.load(policy_path or config.policy)
    except (ConfigError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc)) from exc

    inv = run_scan(config, policy)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    for fmt in formats:
        render, filename = FORMATS[fmt]
        (out / filename).write_text(render(inv))
        click.echo(f"wrote {out / filename}", err=True)

    s = inv.summary()
    click.echo("")
    click.echo(f"assets:   {s['assets']}  ({', '.join(f'{k}={v}' for k, v in s['assets_by_kind'].items())})")
    click.echo(f"sources:  {s['sources'] - s['sources_failed']}/{s['sources']} ok")
    for src in inv.sources:
        status = f"ERROR {src.error}" if src.error else f"{len(src.assets)} assets"
        click.echo(f"  - {src.name} ({src.type}): {status}")
    click.echo("findings: " + ", ".join(f"{k}={v}" for k, v in s["findings_by_severity"].items()))
    if inv.findings:
        click.echo("")
        for f in inv.findings[:15]:
            click.echo(f"  [{f.severity:8}] {f.asset_name} — {f.title}")
        if len(inv.findings) > 15:
            click.echo(f"  … {len(inv.findings) - 15} more in the report")

    if fail_on:
        worst = min((SEV_RANK[f.severity] for f in inv.findings), default=99)
        if worst <= SEV_RANK[fail_on]:
            click.echo(f"\nfailing: findings at or above '{fail_on}' present", err=True)
            sys.exit(1)
    if s["sources_failed"]:
        sys.exit(2)


@main.command()
@click.option("-c", "--config", "config_path", required=True, type=click.Path(exists=True))
@click.option("-p", "--policy", "policy_path", default=None)
@click.option("--port", default=9742, show_default=True)
@click.option("--listen", default="0.0.0.0", show_default=True)
@click.option("--interval", default="15m", show_default=True, help="Rescan interval, e.g. 30s, 15m, 6h.")
@click.option("--no-per-asset-metrics", is_flag=True, help="Only aggregate metrics (huge fleets).")
@click.option("-v", "--verbose", is_flag=True)
def serve(config_path, policy_path, port, listen, interval, no_per_asset_metrics, verbose):
    """Rescan periodically; serve /metrics, /report.html, /cbom.json, /inventory.json."""
    _setup_logging(verbose)
    from .serve import serve as run_serve

    try:
        config = load(config_path)
        policy = Policy.load(policy_path or config.policy)
    except (ConfigError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc)) from exc
    run_serve(config, policy, port, _seconds(interval), listen, not no_per_asset_metrics)


@main.command()
def rules():
    """List policy rules with their default severity."""
    click.echo(f"{'rule':32} {'severity':9} enabled")
    for r in rule_catalogue():
        click.echo(f"{r['rule']:32} {r['severity']:9} {r['enabled']}")


@main.command()
def collectors():
    """List available source types."""
    for name in sorted(REGISTRY):
        click.echo(f"{name:10} {DESCRIPTIONS.get(name, '')}")


@main.command()
def controls():
    """List the compliance controls findings map to."""
    for cid, c in CONTROLS.items():
        click.echo(f"{cid:24} {c['framework']:28} {c['title']}")


@main.command()
@click.option("-c", "--config", "config_path", required=True, type=click.Path(exists=True))
def validate(config_path):
    """Check a config file parses and every source type is known."""
    try:
        config = load(config_path)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    bad = [s for s in config.sources if s.type not in REGISTRY]
    for s in config.sources:
        mark = "?" if s.type not in REGISTRY else "ok"
        click.echo(f"{mark:3} {s.name} ({s.type})")
    if bad:
        raise click.ClickException(f"unknown source types: {', '.join(s.type for s in bad)}")
    click.echo(f"policy: {config.policy}")


def _seconds(text: str) -> float:
    text = str(text).strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text[-1] in mult:
        return float(text[:-1]) * mult[text[-1]]
    return float(text)


if __name__ == "__main__":
    main()
