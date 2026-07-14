---
name: tune-rbac-heuristics
description: >-
  Tunes snowflake-rbac-auditor flag patterns and analyzer heuristics, validates
  with unit tests, and reduces false positives. Use when adjusting
  --flag-role-patterns, --flag-schema-patterns, or extending deterministic issue
  detection.
---

# Tune RBAC Heuristics

Iterate on flag patterns without re-querying Snowflake when possible.

## Workflow

```
Task Progress:
- [ ] Identify false positive or missed issue type
- [ ] Try CLI flag changes first (--from-json)
- [ ] If insufficient, edit analyzer.py + tests
- [ ] Run pytest
- [ ] Re-analyze with --from-json and compare issue counts
```

## Step 1: Diagnose

| Symptom | Likely fix |
|---------|------------|
| ETL roles flagged on prod schemas | Narrow `--flag-role-patterns`; exclude etl/svc prefixes |
| Too many analyst false positives | Make role patterns more specific (`bi_reader` not `analyst`) |
| Missing prod tables in dev DBs | Add `--flag-schema-patterns` entries |
| New object type not flagged | Code change in `analyzer.py` |

## Step 2: CLI iteration (preferred)

Re-analyze saved JSON — no Snowflake connection:

```bash
python -m snowflake_rbac_auditor.cli audit \
  --from-json ./reports/audit-2026-07-14.json \
  --output-dir ./reports \
  --flag-role-patterns "reader,viewer,bi_reader,reporting_" \
  --flag-schema-patterns "prod_,finance_,sensitive_"
```

Compare flagged issue counts:

```bash
python scripts/summarize_audit.py reports/audit-2026-07-14.json
```

## Step 3: Code changes (when flags aren't enough)

Files to edit:

| File | Purpose |
|------|---------|
| `snowflake_rbac_auditor/analyzer.py` | Flagging logic |
| `tests/test_analyzer.py` | Unit tests for heuristics |
| `readme.md` | Document new defaults if changed |

After edits:

```bash
pytest tests/ -q
```

## Step 4: Scope guard

Do **not** add without explicit user request:

- Full effective-privilege recursion
- ACCESS_HISTORY integration
- Auto-remediation
- Web UI or dashboards

## Test patterns

Add tests in `tests/test_analyzer.py` for:

- Role pattern match → flag
- Schema pattern match → flag
- ETL on dev schema → no flag
- Reader role with SELECT only → no flag

Use `_sample_result()` helper pattern from existing tests.

## Document changes

If default CLI patterns change, update `readme.md` Quickstart examples.

If org-specific patterns are stable, suggest user add them to a private gitignored config or document in their run command — avoid hardcoding client names in OSS defaults.
