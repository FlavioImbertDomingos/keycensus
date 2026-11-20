"""Release packaging: the Homebrew formula generator, the release workflow and the package data."""

from __future__ import annotations

import re
import runpy
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
formula_mod = runpy.run_path(str(ROOT / "packaging" / "homebrew" / "make_formula.py"))


def test_formula_names_both_binaries_with_their_checksums(tmp_path):
    sums = tmp_path / "SHA256SUMS"
    sums.write_text("a" * 64 + "  keycensus-1.2.3-macos-arm64\n" + "b" * 64 + "  keycensus-1.2.3-linux-x86_64\n"
                    + "c" * 64 + "  keycensus-1.2.3-py3-none-any.whl\n")  # fmt: skip
    rb = formula_mod["formula"]("1.2.3", formula_mod["read_sums"](str(sums)))
    assert 'version "1.2.3"' in rb and f'sha256 "{"a" * 64}"' in rb and f'sha256 "{"b" * 64}"' in rb
    assert "/releases/download/v1.2.3/keycensus-1.2.3-macos-arm64" in rb
    assert re.search(r'desc "[^"]{1,80}"', rb)  # brew audit: 80 characters at most


def test_formula_refuses_a_missing_binary():
    with pytest.raises(SystemExit, match="linux-x86_64"):
        formula_mod["formula"]("1.2.3", {"keycensus-1.2.3-macos-arm64": "a" * 64})


def test_every_action_in_the_release_workflow_is_pinned_to_a_commit():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses
    wf = yaml.safe_load(text)
    assert wf["permissions"] == {"contents": "read"}
    assert wf["jobs"]["pypi"]["permissions"] == {"id-token": "write"}


def test_package_data_covers_every_data_file():
    patterns = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["setuptools"]["package-data"]["keycensus"]
    pkg = ROOT / "keycensus"
    covered = {p for pat in patterns for p in pkg.glob(pat)}
    data = {p for d in ("templates", "data") for p in (pkg / d).rglob("*") if p.is_file() and "__pycache__" not in
            p.parts and p.suffix != ".py"}  # fmt: skip
    assert data <= covered, sorted(str(p.relative_to(pkg)) for p in data - covered)
