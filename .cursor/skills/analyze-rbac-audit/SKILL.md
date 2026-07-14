---
name: analyze-rbac-audit
description: >-
  Analyzes snowflake-rbac-auditor JSON output for least-privilege recommendations
  using prompts/least-privilege-advisor.md. Use when reviewing audit JSON, drafting
  REVOKE suggestions, or answering which roles/users are over-privileged.
---

# Analyze RBAC Audit

Produce conservative least-privilege recommendations from audit JSON facts.

## Workflow

```
Task Progress:
- [ ] Load audit JSON (and report MD if helpful)
- [ ] Read prompts/least-privilege-advisor.md
- [ ] Gather org context from user (or ask)
- [ ] Analyze flagged_issues first, then supporting grants
- [ ] Output structured sections per advisor prompt
- [ ] Offer review-revoke-recommendations skill before any SQL apply
```

## Step 1: Load sources

Read these files (do not skip the prompt):

1. `reports/audit-*.json` or user-provided path
2. `prompts/least-privilege-advisor.md` — follow its rules and output format

Optional: `python scripts/summarize_audit.py reports/audit-*.json` for top issues.

## Step 2: Gather org context

If the user has not provided context, ask for:

- Which roles are legitimate ETL/pipeline (should keep INSERT/UPDATE)
- Schema/database naming conventions (prod vs dev)
- Roles that must stay read-only (BI, analysts, reporting)
- Any known exceptions before recommending revokes

## Step 3: Analysis rules (mandatory)

1. **Facts from JSON only** — every grantee, object, and privilege cited must exist in the JSON.
2. **Prioritize** `flagged_issues` sorted by: severity → `affected_users_count` → object sensitivity.
3. **Be conservative** — when uncertain, recommend investigation not immediate revoke.
4. **State limitations** — v0.1 has no effective-priv recursion, ACCESS_HISTORY, future grants, tasks, dynamic tables, column-level grants.
5. **Never auto-apply** — all SQL is `DRAFT — REVIEW REQUIRED`.

## Step 4: Output format

Use the sections from `prompts/least-privilege-advisor.md`:

```
## Executive Summary
## Priority Findings
## Proposed Changes (DRAFT SQL)
## False Positive Review
## Recommended Next Steps
```

For each priority finding include:

- Confidence: `high` | `medium` | `low`
- Blast radius (users + inheritance notes from JSON)
- Test plan for lower environment

## Step 5: Cursor invocation example

When running in Cursor Composer:

```
@prompts/least-privilege-advisor.md
@reports/audit-2026-07-14.json

Analyze for least-privilege improvements.

Org context:
- ETL_LOADER and SVC_* roles may INSERT on prod schemas
- BI_* and *_ANALYST roles should be SELECT-only on prod_*
- Finance schemas require extra scrutiny
```

## Anti-patterns

- Do not invent grants, users, or roles not in the JSON
- Do not recommend revoking ETL roles without explicit org confirmation
- Do not skip the False Positive Review section
- Do not present LLM output as approved for production

## Additional resources

- Worked example: [examples.md](examples.md)
