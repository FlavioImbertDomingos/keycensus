"""Change classification and webhook notification.

The interesting assertions are the ones about *urgency*: an alert that pages on
routine change is worse than no alert, so every kind that reaches `page` is
pinned by a test, and the ones that must not page are pinned too.
"""

from __future__ import annotations

import json

import pytest

from keycensus.changes import (
    DEFAULT_URGENCY,
    DIGEST,
    IGNORE,
    PAGE,
    classify,
    kinds_table,
    render_text,
    summarize,
)
from keycensus.diff import diff_dicts
from keycensus.notify import NotifyConfig, NotifyError, build_payload, send, should_send


# --------------------------------------------------------------------------- fixtures
def asset(**kw):
    base = {
        "id": "luna/key/payments-kek",
        "name": "payments-kek",
        "source": "luna",
        "source_type": "pkcs11",
        "kind": "key",
        "algorithm": "RSA",
        "display_algorithm": "RSA-3072",
        "key_size": 3072,
        "state": "active",
        "exportable": False,
        "hardware_backed": True,
        "fips_validated": True,
        "rotation_enabled": True,
        "applications": ["payments-api"],
        "used_by": [],
    }
    base.update(kw)
    return base


def inventory(assets, findings=(), sources=(("luna", None),)):
    return {
        "tool": "keycensus",
        "generated_at": "2026-09-03T00:00:00+00:00",
        "assets": list(assets),
        "findings": list(findings),
        "sources": [{"name": n, "type": "pkcs11", "error": e} for n, e in sources],
    }


def kinds(changes):
    return {c.kind for c in changes}


def one(changes, kind):
    matches = [c for c in changes if c.kind == kind]
    assert matches, f"expected a {kind} change, got {sorted(kinds(changes))}"
    return matches[0]


# --------------------------------------------------------------------------- pages
def test_active_key_disappearing_pages():
    before = inventory([asset()])
    after = inventory([])
    changes = classify(diff_dicts(before, after))
    c = one(changes, "asset-removed")
    assert c.urgency == PAGE
    assert "payments-api" in c.applications  # who breaks is in the payload
    assert c.why


def test_retired_key_disappearing_does_not_page():
    """Housekeeping is not an incident: a key that was already destroyed and is
    now gone should not wake anyone."""
    before = inventory([asset(state="destroyed")])
    after = inventory([])
    changes = classify(diff_dicts(before, after))
    assert "asset-removed" not in kinds(changes)
    assert one(changes, "asset-retired").urgency == DIGEST


def test_key_becoming_exportable_pages():
    changes = classify(diff_dicts(inventory([asset()]), inventory([asset(exportable=True)])))
    c = one(changes, "key-became-exportable")
    assert c.urgency == PAGE
    assert c.before is False and c.after is True


def test_key_becoming_non_exportable_does_not_page():
    changes = classify(diff_dicts(inventory([asset(exportable=True)]), inventory([asset(exportable=False)])))
    assert "key-became-exportable" not in kinds(changes)
    assert all(c.urgency != PAGE for c in changes)


def test_shorter_key_is_a_weakening():
    before = inventory([asset(key_size=3072, display_algorithm="RSA-3072")])
    after = inventory([asset(key_size=2048, display_algorithm="RSA-2048")])
    changes = classify(diff_dicts(before, after))
    assert one(changes, "algorithm-weakened").urgency == PAGE


def test_longer_key_is_not_a_weakening():
    before = inventory([asset(key_size=2048, display_algorithm="RSA-2048")])
    after = inventory([asset(key_size=4096, display_algorithm="RSA-4096")])
    changes = classify(diff_dicts(before, after))
    assert one(changes, "algorithm-strengthened").urgency == IGNORE


def test_leaving_hardware_pages_and_entering_it_does_not():
    out = classify(diff_dicts(inventory([asset()]), inventory([asset(hardware_backed=False)])))
    assert one(out, "hardware-backing-lost").urgency == PAGE
    back = classify(diff_dicts(inventory([asset(hardware_backed=False)]), inventory([asset()])))
    assert one(back, "hardware-backing-gained").urgency == IGNORE


def test_rotation_disabled_pages():
    changes = classify(diff_dicts(inventory([asset()]), inventory([asset(rotation_enabled=False)])))
    assert one(changes, "rotation-disabled").urgency == PAGE


def test_compromised_state_pages():
    changes = classify(diff_dicts(inventory([asset()]), inventory([asset(state="compromised")])))
    assert one(changes, "state-compromised").urgency == PAGE


def test_broken_source_pages_because_the_inventory_is_now_incomplete():
    before = inventory([asset()])
    after = inventory([asset()], sources=(("luna", "connection refused"),))
    changes = classify(diff_dicts(before, after))
    c = one(changes, "source-broken")
    assert c.urgency == PAGE
    assert "connection refused" in c.summary


def test_new_critical_finding_pages_and_a_low_one_does_not():
    def finding(sev):
        return {"rule_id": "weak-key", "asset_id": asset()["id"], "asset_name": "payments-kek",
                "severity": sev, "title": "weak", "source": "luna"}  # fmt: skip

    crit = classify(diff_dicts(inventory([asset()]), inventory([asset()], findings=[finding("critical")])))
    assert one(crit, "finding-new-critical").urgency == PAGE
    low = classify(diff_dicts(inventory([asset()]), inventory([asset()], findings=[finding("low")])))
    assert one(low, "finding-new").urgency == DIGEST


def test_protocol_accepting_a_version_it_used_to_refuse_pages():
    tls = asset(id="edge/protocol/api", kind="protocol", weak_versions_accepted=[])
    after = asset(id="edge/protocol/api", kind="protocol", weak_versions_accepted=["TLSv1.0"])
    changes = classify(diff_dicts(inventory([tls]), inventory([after])))
    assert one(changes, "protocol-weakened").urgency == PAGE


# --------------------------------------------------------------------------- digest / ignore
def test_a_new_key_is_a_digest_not_a_page():
    changes = classify(diff_dicts(inventory([]), inventory([asset()])))
    assert one(changes, "asset-added").urgency == DIGEST


def test_consumers_are_digest_by_default_but_can_be_promoted():
    before = inventory([asset(used_by=[{"id": "role/payments-api", "type": "role"}])])
    after = inventory([asset(used_by=[{"id": "role/payments-api", "type": "role"},
                                      {"id": "role/analytics", "type": "role"}])])  # fmt: skip
    changes = classify(diff_dicts(before, after))
    c = one(changes, "consumer-added")
    assert c.urgency == DIGEST
    assert "role/analytics" in c.summary

    promoted = classify(diff_dicts(before, after), {"consumer-added": PAGE})
    assert one(promoted, "consumer-added").urgency == PAGE


def test_rotation_is_good_news():
    before = inventory([asset(last_rotated="2026-01-01T00:00:00+00:00")])
    after = inventory([asset(last_rotated="2026-09-01T00:00:00+00:00")])
    changes = classify(diff_dicts(before, after))
    assert one(changes, "key-rotated").urgency == DIGEST
    assert all(c.urgency != PAGE for c in changes)


def test_resolved_findings_are_ignored():
    f = {"rule_id": "weak-key", "asset_id": asset()["id"], "asset_name": "payments-kek",
         "severity": "high", "title": "weak", "source": "luna"}  # fmt: skip
    changes = classify(diff_dicts(inventory([asset()], findings=[f]), inventory([asset()])))
    assert one(changes, "finding-resolved").urgency == IGNORE


def test_an_unchanged_estate_produces_nothing():
    same = inventory([asset()])
    assert classify(diff_dicts(same, same)) == []


def test_unknown_urgency_is_rejected():
    with pytest.raises(ValueError, match="page"):
        classify(diff_dicts(inventory([]), inventory([asset()])), {"asset-added": "loud"})


# --------------------------------------------------------------------------- views
def test_summary_counts_by_urgency_and_kind():
    before = inventory([asset(), asset(id="luna/key/old", name="old")])
    after = inventory([asset(exportable=True)])
    s = summarize(classify(diff_dicts(before, after)))
    assert s["by_urgency"][PAGE] == 2  # removed + became exportable
    assert s["by_kind"]["key-became-exportable"] == 1
    assert all("why" in c for c in s["page_worthy"])


def test_text_view_hides_noise_unless_asked():
    before = inventory([asset(location="slot 0")])
    after = inventory([asset(location="slot 1")])
    changes = classify(diff_dicts(before, after))
    assert "no changes worth reporting" in render_text(changes)
    assert "metadata-changed" in render_text(changes, include_ignored=True)


def test_every_kind_the_classifier_emits_is_in_the_urgency_table():
    """A kind with no entry silently defaults to digest, which is how an alert
    goes missing. Keep the table exhaustive."""
    before = inventory(
        [asset(), asset(id="luna/key/gone", name="gone"), asset(id="luna/key/flip", name="flip", exportable=True)],
        sources=(("luna", None), ("vault", None)),
    )
    after = inventory(
        [
            asset(
                key_size=2048,
                exportable=True,
                hardware_backed=False,
                rotation_enabled=False,
                state="compromised",
                used_by=[{"id": "role/new"}],
                applications=[],
                fingerprint_sha256="ab",
                location="slot 9",
            ),
            asset(id="luna/key/new", name="new"),
        ],  # fmt: skip
        sources=(("luna", "boom"),),
    )
    emitted = kinds(classify(diff_dicts(before, after)))
    missing = emitted - set(DEFAULT_URGENCY)
    assert not missing, f"kinds with no urgency mapping: {sorted(missing)}"


def test_kinds_table_lists_everything_and_explains_the_pages():
    table = kinds_table()
    for kind, urgency in DEFAULT_URGENCY.items():
        assert kind in table
        if urgency == PAGE:
            assert kind in table


# --------------------------------------------------------------------------- notifications
def sample_changes():
    return classify(diff_dicts(inventory([asset()]), inventory([asset(exportable=True)])))


def test_notify_config_refuses_an_inline_webhook_url():
    with pytest.raises(NotifyError, match="credential"):
        NotifyConfig.from_dict({"webhook_url": "https://hooks.example/T000"})


def test_notify_config_validates_format_and_trigger():
    with pytest.raises(NotifyError, match="format"):
        NotifyConfig.from_dict({"format": "carrier-pigeon"})
    with pytest.raises(NotifyError, match="on"):
        NotifyConfig.from_dict({"on": "sometimes"})
    assert NotifyConfig.from_dict(None) is None


def test_missing_url_env_says_why_it_is_not_in_the_config(monkeypatch):
    monkeypatch.delenv("KEYCENSUS_WEBHOOK_URL", raising=False)
    cfg = NotifyConfig.from_dict({})
    with pytest.raises(NotifyError, match="credential"):
        cfg.url()


def test_default_trigger_sends_only_on_page():
    cfg = NotifyConfig.from_dict({})
    assert should_send(sample_changes(), cfg)
    digest_only = classify(diff_dicts(inventory([]), inventory([asset()])))
    assert not should_send(digest_only, cfg)
    assert should_send(digest_only, NotifyConfig.from_dict({"on": "any"}))
    assert not should_send(sample_changes(), NotifyConfig.from_dict({"on": "never"}))


def test_slack_payload_carries_the_reason_someone_is_awake():
    payload = build_payload(sample_changes(), NotifyConfig.from_dict({"format": "slack"}), {"environment": "prod"})
    text = json.dumps(payload)
    assert "key-became-exportable" in text
    assert "prod" in payload["text"]
    assert payload["blocks"][0]["type"] == "header"
    assert "attacker" in text  # the `why`, so the responder knows why it matters


def test_generic_payload_is_the_whole_classified_set():
    payload = build_payload(sample_changes(), NotifyConfig.from_dict({}))
    assert payload["tool"] == "keycensus"
    assert payload["summary"]["by_urgency"][PAGE] == 1
    assert payload["changes"][0]["kind"] == "key-became-exportable"


def test_teams_payload_is_a_message_card():
    payload = build_payload(sample_changes(), NotifyConfig.from_dict({"format": "teams"}))
    assert payload["@type"] == "MessageCard"
    assert payload["sections"][0]["facts"]


def test_max_items_truncates_and_says_so():
    many = inventory([asset(id=f"luna/key/k{i}", name=f"k{i}") for i in range(30)])
    changes = classify(diff_dicts(inventory([]), many))
    payload = build_payload(changes, NotifyConfig.from_dict({"on": "any", "max_items": 5}))
    assert len(payload["changes"]) == 5
    assert payload["truncated"] == 25


class _FakeSession:
    def __init__(self, status=200, boom=None):
        self.status, self.boom, self.calls = status, boom, []

    def post(self, url, json=None, timeout=None, headers=None):
        self.calls.append({"url": url, "json": json})
        if self.boom:
            raise self.boom

        class R:
            status_code = self.status
            text = "ok"

        return R()


def test_send_posts_the_payload(monkeypatch):
    monkeypatch.setenv("KEYCENSUS_WEBHOOK_URL", "https://hooks.example/T000/B111")
    session = _FakeSession()
    result = send(sample_changes(), NotifyConfig.from_dict({"format": "slack"}), session=session)
    assert result["sent"] is True
    assert session.calls[0]["url"] == "https://hooks.example/T000/B111"
    assert "blocks" in session.calls[0]["json"]


def test_a_dead_webhook_does_not_break_the_scan(monkeypatch):
    monkeypatch.setenv("KEYCENSUS_WEBHOOK_URL", "https://hooks.example/T000/B111")
    result = send(sample_changes(), NotifyConfig.from_dict({}), session=_FakeSession(boom=OSError("no route")))
    assert result["sent"] is False
    assert "no route" in result["reason"]


def test_http_error_is_reported_without_leaking_the_url(monkeypatch, caplog):
    monkeypatch.setenv("KEYCENSUS_WEBHOOK_URL", "https://hooks.example/SECRET")
    result = send(sample_changes(), NotifyConfig.from_dict({}), session=_FakeSession(status=403))
    assert result["sent"] is False and result["status"] == 403
    assert "SECRET" not in caplog.text


def test_dry_run_builds_the_payload_without_sending(monkeypatch):
    monkeypatch.delenv("KEYCENSUS_WEBHOOK_URL", raising=False)
    result = send(sample_changes(), NotifyConfig.from_dict({}), dry_run=True)
    assert result["sent"] is False
    assert result["payload"]["changes"][0]["kind"] == "key-became-exportable"
