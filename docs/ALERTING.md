# Alerting on change

An inventory tells you what is bad **right now**. That is a report, and a report is something a person has to remember to open. Alerting needs the other question — *what got worse since the last scan* — and until 0.4.0 keycensus could not answer it: the diff existed as a CLI command and an exit code, and exported no metrics at all, so "this key became exportable an hour ago" could not fire anything.

This page is that gap, closed.

> The prompt for this was a comment from [Jitendra Bhargude](https://www.linkedin.com/in/jitendrabhargude/) on LinkedIn: *"Great feature with diff mode. Alerts for significant changes could be valuable too."* He was right, and specifically right.

## Two families of alert

| | Fires on | Example | Driven by |
|---|---|---|---|
| **State** | how the estate is now | "there is a critical finding", "this certificate expires in 9 days" | `keycensus_findings_by_severity`, `keycensus_certificate_expiry_timestamp_seconds`, … |
| **Change** | how the estate moved | "a key that was active is gone", "a key became exportable" | `keycensus_change_total{kind,urgency}` |

Both ship in `prometheus/alerts/keycensus.rules.yml`. You want both: state alerts catch what you inherited, change alerts catch what someone did this afternoon.

## Urgency: page, digest, ignore

Every change is classified into a **kind**, and every kind has an **urgency**. Urgency is not severity — it answers "should this interrupt someone", which is a different question from "how bad is this".

```
page      something got weaker, disappeared, or became reachable in a way it was
          not before. Look now.
digest    real, worth reviewing, not worth interrupting anyone. Weekly.
ignore    noise, or good news — a key was rotated, a finding was resolved.
```

The classification is deliberately stingy with `page`. An alert that fires on routine change teaches people to close the page without reading it, and then the one that mattered gets closed too.

```bash
keycensus changes --kinds        # the whole vocabulary and its default urgency
```

### What pages by default

| Kind | Why it is worth waking someone |
|---|---|
| `asset-removed` | A key that was **active** in the last scan is gone. Either it was deleted or the source stopped reporting it — both matter in minutes. (A key that was already `destroyed` disappearing is `asset-retired`, a digest.) |
| `key-became-exportable` | Private material that could not leave the module now can. This is the attribute an attacker flips before exfiltrating a key, and it is rarely changed on purpose. |
| `hardware-backing-lost` | A key that lived in an HSM is now software-held. Your compliance scope changed with it. |
| `fips-validation-lost` | No longer in a FIPS-validated module — an audit finding as well as a security one. |
| `algorithm-weakened` | Effective strength went down: a shorter key, or a re-key to a weaker algorithm. Judged with the same strength model the findings use, so RSA-3072 → RSA-2048 counts and RSA-2048 → RSA-4096 does not. |
| `rotation-disabled` | Nothing breaks today. The cryptoperiod quietly becomes unbounded. |
| `protocol-weakened` | An endpoint started accepting a TLS version it previously refused. |
| `state-compromised` | A key was marked compromised. Everything it protects is suspect. |
| `source-broken` | A source that worked now errors, so the inventory is incomplete — and every other alert on it is unreliable until it is fixed. |
| `source-removed` | A source left the config; its assets are no longer watched by anything. |
| `finding-new-critical`, `finding-new-high` | A new serious finding since the last scan. |

Everything else is `digest` (new keys, consumer changes, certificate replacement, expiry moving in, application links) or `ignore` (rotation, strengthening, resolved findings, metadata).

### Re-mapping it for your estate

The shipped table is an opinion, not a law. A new principal on a payment key might genuinely be a page where you work; a certificate you rotate hourly is noise:

```yaml
changes:
  urgency:
    consumer-added: page
    certificate-replaced: ignore
```

An unknown kind is a config error rather than a silent no-op, so a typo cannot quietly disable an alert.

## The metrics

`keycensus serve` diffs every rescan against the previous one and exports:

```
keycensus_change_total{kind,urgency,source}       counter, monotonic — the one alerts query
keycensus_changes_last_scan{kind,urgency}         gauge, the most recent diff only
keycensus_last_change_timestamp_seconds           gauge
keycensus_diffs_total                             counter — how many scans were compared at all
```

`increase(keycensus_change_total{urgency="page"}[15m]) > 0` is the whole alert. `keycensus_diffs_total` matters more than it looks: if it stops advancing, change alerting is blind, and `KeycensusNoChangeDetectionRunning` says so.

`serve` also publishes `/diff.json` and `/changes.json` alongside the report, so a responder can see the classified list without re-running anything.

## Webhooks, for teams without Prometheus

Prometheus is the right home for this when you have it. Telling a team that does not have one to install it before they can be told a key vanished is a bad answer, so there is a webhook:

```yaml
notifications:
  webhook_url_env: KEYCENSUS_WEBHOOK_URL   # the URL is a credential -- never inline it
  format: slack                            # generic | slack | teams
  on: page                                 # page (default) | any | never
  include_digest: true                     # list digest changes in the body of a page
  max_items: 20
```

```bash
export KEYCENSUS_WEBHOOK_URL='https://hooks.slack.com/services/…'
keycensus scan -c keycensus.yml -o out --baseline out/inventory.json          # notifies automatically
keycensus diff old.json new.json -c keycensus.yml --notify-dry-run            # see the payload first
```

The URL lives in the environment because a Slack webhook URL **is** the credential — anyone holding it can post as your app. `notifications.webhook_url` is rejected outright rather than accepted with a warning, and a failed HTTP status is logged without the URL in it.

A delivery failure never changes the exit code. A scan that found a problem must still exit with the code that says so, even when nobody could be told.

The Slack payload carries the `why` for every page-worthy change, so the first question a responder has is answered in the message rather than in a wiki:

> 🚨 **key-became-exportable** — luna/payments-kek can now be exported
> *Private material that could not leave the module now can. This is the attribute an attacker changes before exfiltrating a key, and it is rarely changed on purpose.*

## In CI

```bash
keycensus scan -c keycensus.yml -o out --baseline baseline/inventory.json --fail-on-page
```

| Exit | Meaning |
|---|---|
| 0 | nothing to say |
| 1 | `--fail-on` severity present (state) |
| 3 | `--fail-on-new` severity appeared since the baseline |
| 4 | `--fail-on-change`: anything at all changed (drift gate) |
| 5 | `--fail-on-page`: a page-worthy change appeared |

`--fail-on-page` is the useful one for a pipeline that runs against production: it ignores the churn of new keys and rotations and fails only when the estate got worse.

## Choosing what pages: a short opinion

Start with the defaults and change one thing at a time, in this order:

1. **Route `digest` to a channel, never to a pager.** `KeycensusChangeDigest` exists to be read on a Monday.
2. **Promote before you demote.** If a kind should page for you, promote it. Demoting a shipped page because it fired once usually means the underlying change was real and unexplained — which is the alert working.
3. **Watch `source-broken` first.** A broken source silently drains every other alert of meaning, and it is the most common real page in practice.
4. **`asset-removed` will fire on your own cleanups.** That is correct. If it fires often enough to annoy you, the deletions should be going through a change process anyway.
