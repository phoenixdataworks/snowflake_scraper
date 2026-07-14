---
name: review-revoke-recommendations
description: >-
  Reviews proposed Snowflake REVOKE/GRANT statements against audit JSON for blast
  radius, false positives, and missing context. Use before applying least-privilege
  SQL or approving LLM-generated permission changes.
---

# Review REVOKE Recommendations

Safety gate before any permission change reaches a Snowflake environment.

## Workflow

```
Task Progress:
- [ ] Load source audit JSON used for recommendations
- [ ] Parse each proposed REVOKE/GRANT statement
- [ ] Verify against JSON facts
- [ ] Assess blast radius and unknowns
- [ ] Issue verdict: APPROVED FOR LOWER ENV TEST | PASS WITH CAVEATS | BLOCK
```

## Review checklist

For **each** proposed SQL statement, verify:

- [ ] Grantee (role/user) exists in audit JSON
- [ ] Object name matches a grant in `grants_to_roles` or `grants_to_users`
- [ ] Privilege being revoked is actually granted in the JSON
- [ ] Direct user count checked via `users` + `assigned_roles`
- [ ] Parent role inheritance noted from `role_hierarchy`
- [ ] ETL/service roles not caught in collateral revokes
- [ ] SELECT or replacement grants considered if revoking DML
- [ ] Test plan exists for lower environment
- [ ] Rollback SQL documented (re-grant if needed)

## Unknowns to flag (always mention if not in JSON)

- Tasks, streams, dynamic tables depending on the privilege
- Future grants on schema/database
- Stored procedures running as owner with elevated rights
- Column-level grants
- ACCESS_HISTORY — was privilege ever used?

## Verdict format

```markdown
## Verdict: [APPROVED FOR LOWER ENV TEST | PASS WITH CAVEATS | BLOCK]

### Statements reviewed
1. `REVOKE UPDATE ON TABLE ... FROM ROLE ...` — [pass/caveat/block]

### Blockers (if any)
- ...

### Caveats (if any)
- ...

### Required before production
- [ ] Tested in dev/staging
- [ ] Workload owner sign-off
- [ ] Rollback SQL prepared
```

## Rules

- **BLOCK** if SQL references grants not in the audit JSON
- **BLOCK** if blast radius includes unreviewed service accounts
- **PASS WITH CAVEATS** if inheritance makes user impact uncertain
- **APPROVED FOR LOWER ENV TEST** only — never approve direct production apply from this skill
- Never execute SQL on the user's behalf

## Cross-reference

After review passes lower-env testing, user should update IaC (Permifrost etc.) to prevent drift — this tool finds problems, it does not enforce.
