# Snowflake Auditor Role Reference

Minimal custom role for read-only RBAC auditing. Adjust names to your org standards.

## Custom auditor role (template)

Run as `SECURITYADMIN` or equivalent:

```sql
-- Service user (key-pair auth configured separately)
CREATE USER IF NOT EXISTS snowflake_auditor
  COMMENT = 'Read-only RBAC audit service account';

CREATE ROLE IF NOT EXISTS rbac_auditor
  COMMENT = 'Read-only access to ACCOUNT_USAGE for RBAC audits';

GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE rbac_auditor;
GRANT USAGE ON SCHEMA SNOWFLAKE.ACCOUNT_USAGE TO ROLE rbac_auditor;

GRANT ROLE rbac_auditor TO USER snowflake_auditor;

ALTER USER snowflake_auditor SET DEFAULT_ROLE = rbac_auditor;
```

## Verify access

Connect as the auditor user and run:

```sql
SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES WHERE deleted IS NULL;
SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES WHERE deleted IS NULL;
SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS WHERE deleted IS NULL;
```

All three must succeed without permission errors.

## Key-pair setup (outline)

1. Generate key pair locally (`openssl genrsa` + `openssl pkcs8`).
2. Register public key on the Snowflake user: `ALTER USER snowflake_auditor SET RSA_PUBLIC_KEY='...';`
3. Set `SNOWFLAKE_PRIVATE_KEY_PATH` to the private `.p8` file.
4. Rotate keys on a schedule; never store keys in the repo.

## ACCOUNT_USAGE latency note

`ACCOUNT_USAGE` views can lag 45 minutes to several hours behind live grants. If results look stale, note the lag in the report and re-run later — do not treat ACCOUNT_USAGE as real-time.
