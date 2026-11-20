#!/bin/sh
# Build a single-file keycensus binary with PyInstaller, in the current Python environment.
# Install first: pip install pyinstaller ".[all]"
# Output: dist/keycensus (dist/keycensus.exe on Windows)
set -eu
cd "$(dirname "$0")/.."
pyinstaller --noconfirm --clean --onefile --name keycensus \
  --collect-data keycensus \
  --collect-submodules keycensus \
  --collect-data botocore \
  --collect-submodules boto3 \
  --collect-submodules botocore \
  --collect-submodules azure.identity \
  --collect-submodules google.auth \
  --collect-submodules ldap3 \
  --collect-submodules kubernetes \
  --collect-submodules pkcs11 \
  --collect-data certifi \
  packaging/keycensus_entry.py
