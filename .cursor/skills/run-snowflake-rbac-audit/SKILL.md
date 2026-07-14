---
name: run-snowflake-rbac-audit
description: >-
  Runs snowflake-rbac-auditor audits with key-pair auth, validates Snowflake
  ACCOUNT_USAGE access, and writes timestamped JSON/Markdown reports. Use when
  running RBAC audits, setting up the auditor service account, or troubleshooting
  audit CLI failures.
---

# Run Snowflake RBAC Audit

Execute a read-only RBAC audit and produce `audit-*.json` + `report-*.md`.

## Workflow

```
Task Progress:
- [ ] Preflight (venv, package, env vars)
- [ ] Confirm auditor Snowflake privileges
- [ ] Run audit (live or --from-json for re-analysis)
- [ ] Verify outputs in reports/
- [ ] Hand off to analyze-rbac-audit skill if recommendations needed
```

## Step 1: Preflight

From repo root:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
bash scripts/preflight.sh
```

Required env vars (key-pair auth preferred):

| Variable | Required | Notes |
|----------|----------|-------|
| `SNOWFLAKE_ACCOUNT` | Yes | Account identifier |
| `SNOWFLAKE_USER` | Yes | Dedicated auditor service user |
| `SNOWFLAKE_PRIVATE_KEY_PATH` | Yes* | Path to `.p8` key |
| `SNOWFLAKE_PRIVATE_KEY_PASSPHRASE` | No | If key is encrypted |
| `SNOWFLAKE_ROLE` | No | Auditor role if not default |
| `SNOWFLAKE_WAREHOUSE` | No | Optional compute |

*Password via `SNOWFLAKE_PASSWORD` is for local testing only — warn the user.

**Never** commit keys, `.env`, or `reports/` contents.

## Step 2: Privileges

Auditor needs read access to `SNOWFLAKE.ACCOUNT_USAGE`:

- `ROLES`
- `GRANTS_TO_ROLES`
- `GRANTS_TO_USERS`

See [reference.md](reference.md) for a minimal custom auditor role template.

## Step 3: Run audit

**Live extraction** (start narrow before account-wide):

```bash
python -m snowflake_rbac_auditor.cli audit \
  --output-dir ./reports \
  --focus-privileges UPDATE,DELETE,INSERT,TRUNCATE,MODIFY \
  --flag-role-patterns "reader,viewer,analyst,bi_" \
  --flag-schema-patterns "prod_,finance_,sensitive_"
```

**Re-analyze existing JSON** (no Snowflake call — tune heuristics):

```bash
python -m snowflake_rbac_auditor.cli audit \
  --from-json ./reports/audit-2026-07-14.json \
  --output-dir ./reports \
  --flag-role-patterns "reader,viewer,analyst,bi_,reporting_" \
  --flag-schema-patterns "prod_,finance_"
```

## Step 4: Verify outputs

Confirm both files exist in `--output-dir`:

- `audit-YYYY-MM-DD.json` — full graph for LLMs/scripts
- `report-YYYY-MM-DD.md` — executive summary + flagged issues table

Run `python scripts/summarize_audit.py reports/audit-*.json` for a quick issue count.

## Troubleshooting

| Error | Likely cause | Fix |
|-------|--------------|-----|
| Configuration error | Missing env vars | Set account, user, key path |
| Private key not found | Wrong path | Check `SNOWFLAKE_PRIVATE_KEY_PATH` |
| Insufficient privileges | Role lacks ACCOUNT_USAGE | Grant auditor role per reference.md |
| Empty grants | Latency on ACCOUNT_USAGE | Wait 45+ min after grant changes; re-run |
| Connection timeout | Network/warehouse | Set `SNOWFLAKE_WAREHOUSE`, check VPN |

## Security rules

- Treat all outputs as confidential (org structure, sensitive object names).
- Use dedicated rotated keypair service account — not personal admin creds.
- Tool is read-only; never execute DDL on the user's behalf from this skill.

## Additional resources

- Auditor role SQL: [reference.md](reference.md)
- Least-privilege analysis: use `analyze-rbac-audit` skill on the JSON output
