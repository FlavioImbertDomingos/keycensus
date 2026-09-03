"""Webhook notifications: alerting for people who do not run Prometheus.

Prometheus is the right home for this when you already have it -- the exporter
publishes `keycensus_change_total{kind,urgency}` and the shipped rules turn it
into a page. Plenty of teams scanning a key estate do not have Prometheus, and
telling them to install one before they can be told a key vanished is a bad
answer.

So: one HTTP POST, no dependencies beyond `requests`, three payload shapes.

    notifications:
      webhook_url_env: KEYCENSUS_WEBHOOK_URL   # never the URL itself -- it is a credential
      format: slack                            # generic | slack | teams
      on: page                                 # page (default) | any | never
      include_digest: true                     # list digest changes in the body of a page

The URL is read from the environment, not from the config file, because a Slack
webhook URL *is* the credential -- anyone holding it can post as your app.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from .changes import DIGEST, IGNORE, PAGE, Change, summarize

log = logging.getLogger(__name__)

FORMATS = ("generic", "slack", "teams")
TRIGGERS = ("page", "any", "never")


class NotifyError(Exception):
    pass


@dataclass
class NotifyConfig:
    url_env: str = "KEYCENSUS_WEBHOOK_URL"
    format: str = "generic"
    on: str = "page"
    include_digest: bool = True
    timeout: float = 10.0
    max_items: int = 20

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> NotifyConfig | None:
        # None means "no notifications block at all"; an empty block means
        # "notifications, with the defaults" -- the distinction matters because
        # `notifications: {}` is a deliberate opt-in.
        if raw is None:
            return None
        cfg = cls(
            url_env=str(raw.get("webhook_url_env", "KEYCENSUS_WEBHOOK_URL")),
            format=str(raw.get("format", "generic")).lower(),
            on=str(raw.get("on", "page")).lower(),
            include_digest=bool(raw.get("include_digest", True)),
            timeout=float(raw.get("timeout", 10.0)),
            max_items=int(raw.get("max_items", 20)),
        )
        if cfg.format not in FORMATS:
            raise NotifyError(f"notifications.format must be one of {', '.join(FORMATS)}, got {cfg.format!r}")
        if cfg.on not in TRIGGERS:
            raise NotifyError(f"notifications.on must be one of {', '.join(TRIGGERS)}, got {cfg.on!r}")
        if "webhook_url" in raw:
            raise NotifyError(
                "notifications.webhook_url is not accepted: a webhook URL is a credential and belongs in the "
                "environment. Use webhook_url_env: KEYCENSUS_WEBHOOK_URL."
            )
        return cfg

    def url(self) -> str:
        url = os.environ.get(self.url_env, "").strip()
        if not url:
            raise NotifyError(
                f"${self.url_env} is empty. keycensus reads the webhook URL from the environment because the URL "
                "itself is a credential -- export it, or drop the notifications block."
            )
        return url


# ---------------------------------------------------------------------------
#  Payload shaping
# ---------------------------------------------------------------------------
_EMOJI = {PAGE: ":rotating_light:", DIGEST: ":memo:", IGNORE: ":white_check_mark:"}


def should_send(changes: list[Change], cfg: NotifyConfig) -> bool:
    if cfg.on == "never":
        return False
    if cfg.on == "any":
        return any(c.urgency != IGNORE for c in changes)
    return any(c.urgency == PAGE for c in changes)


def _selected(changes: list[Change], cfg: NotifyConfig) -> list[Change]:
    pages = [c for c in changes if c.urgency == PAGE]
    if cfg.include_digest or cfg.on == "any":
        pages += [c for c in changes if c.urgency == DIGEST]
    return pages[: cfg.max_items]


def _headline(changes: list[Change], context: dict[str, Any]) -> str:
    s = summarize(changes)
    n_page = s["by_urgency"].get(PAGE, 0)
    n_digest = s["by_urgency"].get(DIGEST, 0)
    where = context.get("environment") or context.get("hostname") or ""
    lead = f"{n_page} change(s) worth paging for" if n_page else f"{n_digest} change(s) since the last scan"
    return f"keycensus: {lead}{f' — {where}' if where else ''}"


def build_payload(changes: list[Change], cfg: NotifyConfig, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or {}
    headline = _headline(changes, context)
    picked = _selected(changes, cfg)
    s = summarize(changes)

    if cfg.format == "slack":
        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text", "text": headline[:150]}},
        ]
        for c in picked:
            text = f"{_EMOJI.get(c.urgency, '')} *{c.kind}* — {c.summary}"
            if c.urgency == PAGE and c.why:
                text += f"\n_{c.why}_"
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}})
        if len(changes) > len(picked):
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"…and {len(changes) - len(picked)} more; see the report."}
                    ],
                }
            )
        if context.get("report_url"):
            blocks.append(
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"<{context['report_url']}|Open the report>"}],
                }
            )
        return {"text": headline, "blocks": blocks}

    if cfg.format == "teams":
        facts = [{"name": c.kind, "value": c.summary} for c in picked]
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": headline,
            "themeColor": "D93F0B" if s["by_urgency"].get(PAGE) else "0B6BCB",
            "title": headline,
            "sections": [{"facts": facts, "markdown": False}],
        }

    # generic: the whole thing as JSON, for a receiver that will do its own shaping
    return {
        "tool": "keycensus",
        "headline": headline,
        "summary": s,
        "changes": [c.to_dict() for c in picked],
        "truncated": max(0, len(changes) - len(picked)),
        "context": context,
    }


# ---------------------------------------------------------------------------
#  Sending
# ---------------------------------------------------------------------------
def send(
    changes: list[Change],
    cfg: NotifyConfig,
    context: dict[str, Any] | None = None,
    session: Any = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """POST the payload. Returns {sent, reason, status, payload}. Never raises on a
    delivery failure -- a scan that found a problem should still exit with the code
    that says so, even when the notification could not be delivered."""
    if not should_send(changes, cfg):
        return {"sent": False, "reason": f"no changes matching notifications.on={cfg.on}", "payload": None}

    payload = build_payload(changes, cfg, context)
    if dry_run:
        return {"sent": False, "reason": "dry run", "payload": payload}

    import requests  # noqa: PLC0415 - keeps `keycensus diff` importable without requests

    http = session or requests
    url = cfg.url()
    try:
        r = http.post(url, json=payload, timeout=cfg.timeout, headers={"Content-Type": "application/json"})
    except Exception as exc:  # network, DNS, TLS -- all the same to the caller
        log.warning("[notify] webhook POST failed: %s", exc)
        return {"sent": False, "reason": f"POST failed: {exc}", "payload": payload}
    if r.status_code >= 400:
        # Never log the URL: it is the credential.
        log.warning("[notify] webhook returned %s: %s", r.status_code, r.text[:200])
        return {"sent": False, "reason": f"HTTP {r.status_code}", "status": r.status_code, "payload": payload}
    log.info("[notify] sent %d change(s) to the %s webhook", len(payload.get("changes", []) or [1]), cfg.format)
    return {"sent": True, "reason": "ok", "status": r.status_code, "payload": payload}


def render_preview(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, default=str) + "\n"
