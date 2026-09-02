"""Every collector is a class with one job: `collect()` returns CryptoAssets.

To add a source system, subclass `Collector`, set `type_name`, implement
`collect()`, and register it in `collectors/__init__.py`. That's the whole
plug-in contract.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from ..config import SourceConfig
from ..model import CryptoAsset, SourceResult

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

    @abstractmethod
    def collect(self) -> list[CryptoAsset]: ...

    def run(self) -> SourceResult:
        """collect() with timing and error capture -- one bad source never kills the scan."""
        started = time.perf_counter()
        result = SourceResult(name=self.name, type=self.type_name)
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
    def asset(self, **kwargs) -> CryptoAsset:
        kwargs.setdefault("source", self.name)
        kwargs.setdefault("source_type", self.type_name)
        tags = dict(self.opt.get("tags") or {})
        tags.update(kwargs.pop("tags", {}) or {})
        return CryptoAsset(tags=tags, **kwargs)
