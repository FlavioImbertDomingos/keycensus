"""Every collector is a class with one job: `collect()` returns CryptoAssets.

To add a source system, subclass `Collector`, set `type_name`, implement
`collect()`, and register it in `collectors/__init__.py`. That's the whole
plug-in contract.

A collector that walks several scopes (accounts, regions, subscriptions, namespaces) should say how far
it got, so a partial scan is never mistaken for a complete one:

    self.coverage.expect("regions", len(regions))      # None when the total cannot be discovered
    self.coverage.ok("regions")                         # one scanned
    self.coverage.gap("regions", "111/eu-west-3", exc, GAP_DENIED)
    asset.extra["coverage_scope"] = ["region:111/eu-west-3"]   # which scopes each asset lives in

Assets missing from a scope that was not scanned are carried forward as "not observed", and their
findings stay open, instead of looking resolved.
"""

from __future__ import annotations

import logging
import re
import time
from abc import ABC, abstractmethod

from ..config import SourceConfig
from ..model import (
    GAP_DENIED,
    GAP_ERROR,
    GAP_UNAVAILABLE,
    Coverage,
    CryptoAsset,
    SourceResult,
    normalise_fips_evidence,
)

__all__ = ["GAP_DENIED", "GAP_ERROR", "GAP_UNAVAILABLE", "Collector", "CollectorError", "gap_kind"]


_DENIED_WORDS = ("accessdenied", "access denied", "forbidden", "unauthorized", "authorizationfailed", "permission",
                 "not authorized")  # fmt: skip
_UNAVAILABLE_WORDS = ("not enabled", "optinrequired", "unavailable", "timed out", "timeout", "could not connect",
                      "unrecognizedclient")  # fmt: skip


def gap_kind(exc: BaseException) -> str:
    """denied / unavailable / error, from an exception's text or HTTP status."""
    text = f"{type(exc).__name__} {exc}".lower()
    status = getattr(getattr(exc, "response", None), "status_code", None) or getattr(exc, "status", None)
    if status is None:  # our own RuntimeErrors read "GET <url> -> 403: ..." or "HTTP 403"
        m = re.search(r"(?:-> |HTTP )(\d{3})\b", str(exc))
        status = int(m.group(1)) if m else None
    if status in (401, 403) or any(w in text for w in _DENIED_WORDS):
        return GAP_DENIED
    if status in (404, 503) or any(w in text for w in _UNAVAILABLE_WORDS):
        return GAP_UNAVAILABLE
    return GAP_ERROR


log = logging.getLogger(__name__)


class CollectorError(Exception):
    pass


class Collector(ABC):
    type_name = "abstract"
    #: pip extra needed for this collector, for a friendly error message
    requires_extra: str | None = None

    def __init__(self, cfg: SourceConfig):
        self.cfg = cfg
        self.name = cfg.name
        self.opt = cfg.options
        self.coverage = Coverage()

    @abstractmethod
    def collect(self) -> list[CryptoAsset]: ...

    def run(self) -> SourceResult:
        """collect() with timing and error capture -- one bad source never kills the scan."""
        started = time.perf_counter()
        result = SourceResult(name=self.name, type=self.type_name, coverage=self.coverage)
        try:
            result.assets = self.collect()
            log.info("[%s] %s: %d assets", self.name, self.type_name, len(result.assets))
        except ImportError as exc:
            hint = f" (pip install 'keycensus[{self.requires_extra}]')" if self.requires_extra else ""
            result.error = f"missing dependency: {exc}{hint}"
            log.error("[%s] %s", self.name, result.error)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the scan
            result.error = f"{type(exc).__name__}: {exc}"
            log.error("[%s] %s", self.name, result.error)
        result.duration_seconds = time.perf_counter() - started
        return result

    # ------------------------------------------------------------ helpers
    VENDOR_FIPS_NOTE = (
        "The vendor documents this key store as running on FIPS-validated modules. The API does not "
        "say which standard, level or certificate; add fips_evidence to the source to record them."
    )

    def _fips_evidence(self) -> dict | None:
        if not hasattr(self, "_fips_ev"):
            raw = self.opt.get("fips_evidence")
            self._fips_ev = normalise_fips_evidence(raw, f"{self.name}.fips_evidence") if raw else None
        return self._fips_ev

    def asset(self, **kwargs) -> CryptoAsset:
        kwargs.setdefault("source", self.name)
        kwargs.setdefault("source_type", self.type_name)
        if kwargs.get("fips_validated") and not kwargs.get("fips_evidence"):
            ev = self._fips_evidence()
            kwargs["fips_evidence"] = dict(ev) if ev else {"basis": "vendor-documentation",
                                                           "note": self.VENDOR_FIPS_NOTE}  # fmt: skip
        tags = dict(self.opt.get("tags") or {})
        tags.update(kwargs.pop("tags", {}) or {})
        return CryptoAsset(tags=tags, **kwargs)
