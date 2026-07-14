# Analyze RBAC Audit — Worked Example

Using `examples/sample-audit.json` from the repo.

## Input summary

| Metric | Value |
|--------|-------|
| Roles | BI_READER, ETL_LOADER, FINANCE_ANALYST |
| Users | 3 (2 with BI_READER) |
| Flagged issues | 3 |

## Expected priority findings

1. **BI_READER + UPDATE on PROD_ANALYTICS.PUBLIC.FACT_ORDERS** — HIGH confidence revoke
   - 2 direct users; inherited by SYSADMIN
   - BI role name + prod object = clear false positive for DML

2. **BI_READER + DELETE on same table** — HIGH confidence revoke
   - Same blast radius as above

3. **FINANCE_ANALYST + INSERT on FINANCE_CORE.SENSITIVE.LEDGER_ENTRIES** — MEDIUM confidence
   - 1 user; may be legitimate for finance workflows — needs org context

## Sample DRAFT SQL (illustrative)

```sql
-- DRAFT — REVIEW REQUIRED
-- Blast radius: ANALYST_JANE, ANALYST_BOB (+ SYSADMIN inheritance)

REVOKE UPDATE ON TABLE PROD_ANALYTICS.PUBLIC.FACT_ORDERS FROM ROLE BI_READER;
REVOKE DELETE ON TABLE PROD_ANALYTICS.PUBLIC.FACT_ORDERS FROM ROLE BI_READER;

-- Confirm SELECT remains:
-- SHOW GRANTS TO ROLE BI_READER;
```

## False positive check

- **ETL_LOADER INSERT on FACT_ORDERS** — NOT flagged (role name doesn't match reader patterns). Correct behavior for pipeline role.

## Test plan

1. Confirm BI dashboards/queries work with SELECT only in staging
2. Verify no tools rely on UPDATE/DELETE via BI_READER
3. Run `SHOW GRANTS TO ROLE BI_READER` before and after in lower env
