#!/usr/bin/env bash
# Preflight checks for snowflake-rbac-auditor (no Snowflake connection).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Checking Python package"
python3 -c "import snowflake_rbac_auditor; print(f'  snowflake-rbac-auditor {snowflake_rbac_auditor.__version__}')"

echo "==> Checking env vars (informational)"
for var in SNOWFLAKE_ACCOUNT SNOWFLAKE_USER SNOWFLAKE_PRIVATE_KEY_PATH; do
  if [[ -n "${!var:-}" ]]; then
    echo "  $var is set"
  else
    echo "  $var is NOT set"
  fi
done

if [[ -n "${SNOWFLAKE_PRIVATE_KEY_PATH:-}" ]]; then
  KEY_PATH="${SNOWFLAKE_PRIVATE_KEY_PATH/#\~/$HOME}"
  if [[ -f "$KEY_PATH" ]]; then
    echo "  Private key file exists"
  else
    echo "  WARNING: Private key file not found at $KEY_PATH"
    exit 1
  fi
fi

echo "==> Preflight OK"
