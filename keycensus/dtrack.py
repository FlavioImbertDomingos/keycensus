"""Upload a CBOM to OWASP Dependency-Track.

Dependency-Track (>= 4.11) ingests CycloneDX 1.6 BOMs including cryptographic assets, so the
CBOM keycensus writes can live next to your software BOMs: one project per HSM estate /
environment, a new version per scan, policies and notifications on top.

    keycensus upload dtrack --url https://dtrack.example.com --api-key-env DTRACK_API_KEY \
        --project "hsm-estate" --version "2026-09-02" --cbom out/cbom.json --wait

Uses `PUT /api/v1/bom` with the JSON body form (`projectName`, `projectVersion`, `autoCreate`,
base64 `bom`), then polls `GET /api/v1/bom/token/{token}` until Dependency-Track has processed
it (`--wait`). The API key needs `BOM_UPLOAD` (+ `PROJECT_CREATION_UPLOAD` for `--auto-create`,
+ `VIEW_PORTFOLIO` for the readback).
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import requests


class DependencyTrackError(Exception):
    pass


class DependencyTrack:
    def __init__(self, url: str, api_key: str, verify_tls: bool | str = True, timeout: float = 30):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"X-Api-Key": api_key, "Accept": "application/json"})
        self.session.verify = verify_tls
        self.timeout = timeout

    def upload(
        self,
        bom_path: str | Path,
        project: str | None = None,
        version: str | None = None,
        project_uuid: str | None = None,
        auto_create: bool = True,
        parent_name: str | None = None,
        parent_version: str | None = None,
        is_latest: bool | None = None,
    ) -> str:
        """Upload a CycloneDX BOM; return the processing token."""
        raw = Path(bom_path).read_bytes()
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise DependencyTrackError(f"{bom_path} is not JSON: {exc}") from exc
        if doc.get("bomFormat") != "CycloneDX":
            raise DependencyTrackError(f"{bom_path} is not a CycloneDX BOM (bomFormat={doc.get('bomFormat')!r})")
        if not project_uuid and not project:
            raise DependencyTrackError("project name or project uuid is required")
        body: dict = {"bom": base64.b64encode(raw).decode()}
        if project_uuid:
            body["project"] = project_uuid
        else:
            body.update({"projectName": project, "projectVersion": version or "", "autoCreate": bool(auto_create)})
        if parent_name:
            body["parentName"] = parent_name
            if parent_version:
                body["parentVersion"] = parent_version
        if is_latest is not None:
            body["isLatest"] = bool(is_latest)
        r = self.session.put(f"{self.url}/api/v1/bom", json=body, timeout=self.timeout)
        if r.status_code == 401 or r.status_code == 403:
            raise DependencyTrackError(f"upload rejected ({r.status_code}): check the API key permissions "
                                       "(BOM_UPLOAD, PROJECT_CREATION_UPLOAD for auto-create)")  # fmt: skip
        if r.status_code == 404:
            raise DependencyTrackError("project not found (404): pass --auto-create or create it first")
        if r.status_code >= 400:
            raise DependencyTrackError(f"upload failed: {r.status_code} {r.text[:300]}")
        token = (r.json() or {}).get("token")
        if not token:
            raise DependencyTrackError(f"no processing token in response: {r.text[:200]}")
        return token

    def wait(self, token: str, timeout: float = 120, interval: float = 2.0) -> bool:
        """Poll until the BOM is processed. Returns True when done, False on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = self.session.get(f"{self.url}/api/v1/bom/token/{token}", timeout=self.timeout)
            if r.status_code >= 400:
                raise DependencyTrackError(f"token lookup failed: {r.status_code} {r.text[:200]}")
            if not (r.json() or {}).get("processing", False):
                return True
            time.sleep(interval)
        return False

    def project(self, name: str, version: str | None = None) -> dict | None:
        params = {"name": name}
        if version:
            params["version"] = version
        r = self.session.get(f"{self.url}/api/v1/project/lookup", params=params, timeout=self.timeout)
        if r.status_code == 404:
            return None
        if r.status_code >= 400:
            raise DependencyTrackError(f"project lookup failed: {r.status_code} {r.text[:200]}")
        return r.json()

    def project_url(self, project: dict) -> str:
        return f"{self.url}/projects/{project.get('uuid')}"
