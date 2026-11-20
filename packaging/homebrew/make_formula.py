"""Write the Homebrew formula for a release from the binaries' SHA-256 sums.

    python packaging/homebrew/make_formula.py 0.21.0 SHA256SUMS > keycensus.rb

SHA256SUMS is the file the release workflow writes (`<sha256>  keycensus-<version>-<platform>`). The formula
installs the single-file binary, so Homebrew needs no Python. It goes in the tap repository
FlavioImbertDomingos/homebrew-keycensus as Formula/keycensus.rb; then

    brew install flavioimbertdomingos/keycensus/keycensus
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = "https://github.com/FlavioImbertDomingos/keycensus"
PLATFORMS = {"macos-arm64": ("on_macos", "on_arm"), "linux-x86_64": ("on_linux", "on_intel")}


def formula(version: str, sums: dict[str, str]) -> str:
    blocks = []
    for platform, (os_block, cpu_block) in PLATFORMS.items():
        asset = f"keycensus-{version}-{platform}"
        if asset not in sums:
            raise SystemExit(f"no SHA-256 for {asset}")
        blocks.append(f"""  {os_block} do
    {cpu_block} do
      url "{REPO}/releases/download/v{version}/{asset}"
      sha256 "{sums[asset]}"
    end
  end""")
    body = "\n".join(blocks)
    return f'''class Keycensus < Formula
  desc "Cryptographic inventory (CBOM) and key-hygiene scanner"
  homepage "{REPO}"
  version "{version}"
  license "Apache-2.0"

{body}

  def install
    bin.install Dir["keycensus-*"].first => "keycensus"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/keycensus --version")
  end
end
'''


def read_sums(path: str) -> dict[str, str]:
    out = {}
    for line in Path(path).read_text().splitlines():
        if line.strip():
            digest, name = line.split(maxsplit=1)
            out[name.strip().lstrip("*")] = digest
    return out


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    sys.stdout.write(formula(sys.argv[1], read_sums(sys.argv[2])))
