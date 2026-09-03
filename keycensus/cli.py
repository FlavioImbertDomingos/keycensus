"""Command line: scan | link | diff | changes | notify | upload | serve | rules | collectors | controls | validate."""

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
@click.option("--baseline", "baseline_path", default=None, type=click.Path(exists=True),
              help="Previous inventory.json: also write diff.json + diff.md and print what changed.")  # fmt: skip
@click.option("--fail-on-new", default=None, type=click.Choice(SEVERITIES),
              help="With --baseline: exit 3 if a NEW finding is at least this severe.")  # fmt: skip
@click.option("--fail-on-page", is_flag=True,
              help="With --baseline: exit 5 on any page-worthy change (see `keycensus changes --kinds`).")  # fmt: skip
@click.option("--notify/--no-notify", default=None,
              help="With --baseline: POST the classified changes to the configured webhook. "
                   "Defaults to on when the config has a notifications block.")  # fmt: skip
@click.option("--notify-dry-run", is_flag=True, help="Print the webhook payload instead of sending it.")
@click.option("-v", "--verbose", is_flag=True)
def scan(
    config_path,
    output_dir,
    formats,
    policy_path,
    fail_on,
    baseline_path,
    fail_on_new,
    fail_on_page,
    notify,
    notify_dry_run,
    verbose,
):
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
    if inv.applications:
        click.echo(
            f"apps:     {s['applications']} linked to {s['assets_linked']} assets, {s['assets_unlinked']} unlinked"
        )
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

    rc = 0
    if baseline_path:
        import json as _json

        from .changes import PAGE, classify, summarize
        from .changes import render_text as render_changes
        from .diff import diff_inventories, load_inventory_dict, render_json, render_markdown, render_text

        d = diff_inventories(load_inventory_dict(baseline_path), inv)
        classified = classify(d, config.change_urgency)
        (out / "diff.json").write_text(render_json(d))
        (out / "diff.md").write_text(render_markdown(d))
        (out / "changes.json").write_text(
            _json.dumps({"summary": summarize(classified), "changes": [c.to_dict() for c in classified]},
                        indent=2, default=str) + "\n"
        )  # fmt: skip
        click.echo(f"wrote {out / 'diff.json'}, diff.md and changes.json", err=True)
        click.echo("")
        click.echo(render_text(d).rstrip())
        if classified:
            click.echo("")
            click.echo("by urgency (what would page vs what waits for the weekly digest):")
            click.echo(render_changes(classified).rstrip())

        if notify_dry_run or (notify if notify is not None else config.notifications is not None):
            _notify(config, classified, dry_run=notify_dry_run, context={"source": "scan"})

        worst_new = d.worst_new_severity()
        if fail_on_new and worst_new and SEV_RANK[worst_new] <= SEV_RANK[fail_on_new]:
            click.echo(f"\nfailing: NEW findings at or above '{fail_on_new}' since the baseline", err=True)
            rc = 3
        if fail_on_page and any(c.urgency == PAGE for c in classified):
            n = sum(1 for c in classified if c.urgency == PAGE)
            click.echo(f"\nfailing: {n} page-worthy change(s) since the baseline", err=True)
            rc = rc or 5

    if fail_on:
        worst = min((SEV_RANK[f.severity] for f in inv.findings), default=99)
        if worst <= SEV_RANK[fail_on]:
            click.echo(f"\nfailing: findings at or above '{fail_on}' present", err=True)
            rc = rc or 1
    if s["sources_failed"]:
        rc = rc or 2
    if rc:
        sys.exit(rc)


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
        click.echo(f"{name:15} {DESCRIPTIONS.get(name, '')}")


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


def _notify(cfg, classified, dry_run: bool, context: dict | None = None):
    """Send classified changes to the webhook. Shared by `scan` and `diff`."""
    from .notify import NotifyConfig, NotifyError, render_preview, send

    try:
        ncfg = NotifyConfig.from_dict(cfg.notifications if cfg else None)
    except NotifyError as exc:
        raise click.ClickException(str(exc)) from exc
    if ncfg is None:
        raise click.ClickException(
            "--notify needs a `notifications:` block in the config (and -c pointing at it). See docs/ALERTING.md."
        )
    result = send(classified, ncfg, context=context or {}, dry_run=dry_run)
    if dry_run:
        click.echo("")
        click.echo(f"webhook payload ({ncfg.format}, would POST to ${ncfg.url_env}):", err=True)
        click.echo(render_preview(result["payload"]) if result["payload"] else "(nothing to send)")
    elif result["sent"]:
        click.echo(f"notified: {ncfg.format} webhook accepted the change set", err=True)
    else:
        click.echo(f"not notified: {result['reason']}", err=True)


@main.command()
@click.option("--kinds", is_flag=True, help="Print every change kind this build can emit and its default urgency.")
@click.argument("before", type=click.Path(exists=True), required=False)
@click.argument("after", type=click.Path(exists=True), required=False)
@click.option("-c", "--config", "config_path", default=None, type=click.Path(exists=True))
@click.option("-f", "--format", "fmt", default="text", type=click.Choice(["text", "json"]), show_default=True)
@click.option("--include-ignored", is_flag=True, help="Also show changes classified as noise or good news.")
def changes(kinds, before, after, config_path, fmt, include_ignored):
    """Classify a diff into what should page and what can wait.

    \b
      keycensus changes --kinds                       the alerting vocabulary
      keycensus changes old/inventory.json new/inventory.json
    """
    import json as _json

    from .changes import classify, kinds_table, summarize
    from .changes import render_text as render_changes

    if kinds:
        click.echo(kinds_table().rstrip())
        return
    if not (before and after):
        raise click.ClickException("give two inventory.json files, or --kinds")

    from .diff import diff_files

    cfg = None
    if config_path:
        try:
            cfg = load(config_path)
        except ConfigError as exc:
            raise click.ClickException(str(exc)) from exc
    try:
        classified = classify(diff_files(before, after), cfg.change_urgency if cfg else None)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    if fmt == "json":
        click.echo(
            _json.dumps(
                {"summary": summarize(classified), "changes": [c.to_dict() for c in classified]}, indent=2, default=str
            )
        )
    else:
        click.echo(render_changes(classified, include_ignored=include_ignored).rstrip())


@main.command()
@click.argument("before", type=click.Path(exists=True))
@click.argument("after", type=click.Path(exists=True))
@click.option(
    "-f", "--format", "fmt", default="text", type=click.Choice(["text", "markdown", "json"]), show_default=True
)
@click.option("-o", "--output", default=None, type=click.Path(), help="Write here instead of stdout.")
@click.option("--fail-on-new", default=None, type=click.Choice(SEVERITIES),
              help="Exit 3 if a finding that was not in BEFORE is at least this severe.")  # fmt: skip
@click.option("--fail-on-change", is_flag=True, help="Exit 4 if anything at all changed (drift gate).")
@click.option("--fail-on-page", is_flag=True,
              help="Exit 5 if any change classified page-worthy appears (a key vanished, weakened, "
                   "became exportable ...). See `keycensus changes --kinds`.")  # fmt: skip
@click.option("-c", "--config", "config_path", default=None, type=click.Path(exists=True),
              help="Config file, for changes.urgency overrides and the notifications block.")  # fmt: skip
@click.option("--notify/--no-notify", default=False, help="POST the classified changes to the configured webhook.")
@click.option("--notify-dry-run", is_flag=True, help="Print the webhook payload instead of sending it.")
def diff(before, after, fmt, output, fail_on_new, fail_on_change, fail_on_page, config_path, notify, notify_dry_run):
    """What changed between two scans (two inventory.json files)."""
    from .changes import PAGE, classify
    from .changes import render_text as render_changes
    from .diff import RENDERERS, diff_files

    try:
        d = diff_files(before, after)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    cfg = None
    if config_path:
        try:
            cfg = load(config_path)
        except ConfigError as exc:
            raise click.ClickException(str(exc)) from exc
    classified = classify(d, cfg.change_urgency if cfg else None)

    text = RENDERERS[fmt](d)
    if output:
        Path(output).write_text(text)
        click.echo(f"wrote {output}", err=True)
    else:
        click.echo(text.rstrip())

    if fmt == "text" and classified:
        click.echo("")
        click.echo("by urgency (what would page vs what waits for the weekly digest):")
        click.echo(render_changes(classified).rstrip())

    if notify or notify_dry_run:
        _notify(cfg, classified, dry_run=notify_dry_run, context={"source": "diff"})

    if fail_on_page and any(c.urgency == PAGE for c in classified):
        n = sum(1 for c in classified if c.urgency == PAGE)
        click.echo(f"\nfailing: {n} page-worthy change(s) since BEFORE", err=True)
        sys.exit(5)

    worst = d.worst_new_severity()
    if fail_on_new and worst and SEV_RANK[worst] <= SEV_RANK[fail_on_new]:
        click.echo(f"\nfailing: new findings at or above '{fail_on_new}'", err=True)
        sys.exit(3)
    if fail_on_change and not d.empty:
        click.echo("\nfailing: inventory changed", err=True)
        sys.exit(4)


@main.command()
@click.option("-c", "--config", "config_path", required=True, type=click.Path(exists=True),
              help="Config with the applications: list (sources are not scanned).")  # fmt: skip
@click.option("-i", "--inventory", "inventory_path", default="out/inventory.json", show_default=True,
              type=click.Path(exists=True), help="A previous scan to link.")  # fmt: skip
@click.option("-o", "--output-dir", default="./out", show_default=True)
@click.option("-f", "--format", "formats", multiple=True, default=("json", "cbom", "csv", "html"),
              type=click.Choice(sorted(FORMATS)), show_default=True)  # fmt: skip
@click.option("-p", "--policy", "policy_path", default=None)
@click.option("--sbom", "sboms", multiple=True, type=click.Path(exists=True),
              help="Extra SBOMs to link as applications (metadata.component; auto-match only).")  # fmt: skip
def link(config_path, inventory_path, output_dir, formats, policy_path, sboms):
    """Link applications (SBOMs) to the assets of an existing scan, and rewrite the reports."""
    from .diff import load_inventory_dict
    from .linking import LinkingError, apply, impact
    from .model import Inventory

    try:
        config = load(config_path)
        policy = Policy.load(policy_path or config.policy)
        inv = Inventory.from_dict(load_inventory_dict(inventory_path))
        entries = list(config.applications) + [{"sbom": p} for p in sboms]
        if not entries:
            raise click.ClickException("nothing to link: add applications: to the config or pass --sbom")
        apply(inv, entries, policy, base_dir=config.base_dir, auto_match=config.auto_match)
    except (ConfigError, LinkingError, ValueError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc)) from exc
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    for fmt in formats:
        render, filename = FORMATS[fmt]
        (out / filename).write_text(render(inv))
        click.echo(f"wrote {out / filename}", err=True)
    click.echo("")
    for row in impact(inv):
        worst = row["worst_severity"] or "-"
        click.echo(f"  {row['name']:32} {row['assets']:4} assets  {row['findings']:4} findings  worst {worst}")
    s = inv.summary()
    if s.get("assets_unlinked"):
        click.echo(f"\n{s['assets_unlinked']} asset(s) not linked to any application")


@main.group()
def upload():
    """Push scan results somewhere else."""


@upload.command("dtrack")
@click.option("--url", required=True, help="Dependency-Track API base URL, e.g. https://dtrack.example.com")
@click.option("--api-key-env", default="DTRACK_API_KEY", show_default=True, help="Env var holding the API key.")
@click.option("--api-key-file", default=None, type=click.Path(exists=True), help="Or a file holding the API key.")
@click.option("--cbom", "cbom_path", default="out/cbom.json", show_default=True, type=click.Path(exists=True))
@click.option("--project", default=None, help="Project name (created with --auto-create).")
@click.option("--version", "project_version", default=None, help="Project version, e.g. a date or git sha.")
@click.option("--project-uuid", default=None, help="Upload to an existing project by UUID instead of name.")
@click.option("--parent", default=None, help="Parent project name (portfolio grouping).")
@click.option("--parent-version", default=None)
@click.option("--auto-create/--no-auto-create", default=True, show_default=True)
@click.option("--latest/--no-latest", "is_latest", default=None, help="Mark this version as the project's latest.")
@click.option(
    "--wait/--no-wait", default=True, show_default=True, help="Wait until Dependency-Track processed the BOM."
)
@click.option("--timeout", default=120, show_default=True, help="Seconds to wait for processing.")
@click.option("--insecure", is_flag=True, help="Skip TLS verification (lab only).")
def upload_dtrack(url, api_key_env, api_key_file, cbom_path, project, project_version, project_uuid, parent,
                  parent_version, auto_create, is_latest, wait, timeout, insecure):  # fmt: skip
    """Upload the CBOM to OWASP Dependency-Track."""
    import os

    from .dtrack import DependencyTrack, DependencyTrackError

    api_key = Path(api_key_file).read_text().strip() if api_key_file else os.environ.get(api_key_env)
    if not api_key:
        raise click.ClickException(f"no API key: set {api_key_env} or pass --api-key-file")
    dt = DependencyTrack(url, api_key, verify_tls=not insecure)
    try:
        token = dt.upload(cbom_path, project=project, version=project_version, project_uuid=project_uuid,
                          auto_create=auto_create, parent_name=parent, parent_version=parent_version,
                          is_latest=is_latest)  # fmt: skip
        click.echo(f"uploaded {cbom_path} (token {token})", err=True)
        if wait:
            if not dt.wait(token, timeout=timeout):
                raise click.ClickException(f"Dependency-Track did not finish processing within {timeout}s")
            click.echo("processed", err=True)
            if project:
                proj = dt.project(project, project_version)
                if proj:
                    click.echo(dt.project_url(proj))
    except DependencyTrackError as exc:
        raise click.ClickException(str(exc)) from exc


def _seconds(text: str) -> float:
    text = str(text).strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text[-1] in mult:
        return float(text[:-1]) * mult[text[-1]]
    return float(text)


if __name__ == "__main__":
    main()
