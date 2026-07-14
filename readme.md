# snowflake-rbac-auditor

Open-source tool for auditing Snowflake permissions, generating clean documentation, and producing AI-ready artifacts for least-privilege recommendations.

**Goal:** Help data platform teams detect excessive privileges (e.g., UPDATE/DELETE grants on tables that should be read-only) and move toward least privilege with structured facts + LLM assistance. Complements declarative tools like Permifrost rather than competing with them.

**Current status:** v0.1 MVP implemented. Ready for real-account testing and heuristic tuning.

## Quickstart (target for v0.1)

```bash
# After cloning and venv
pip install -r requirements.txt

# Recommended: key-pair auth (never password in prod)
export SNOWFLAKE_ACCOUNT=your-account
export SNOWFLAKE_USER=snowflake_auditor
export SNOWFLAKE_PRIVATE_KEY_PATH=~/.ssh/snowflake_auditor_key.p8
export SNOWFLAKE_DATABASE=optional_for_context  # or leave for account level

python -m snowflake_rbac_auditor.cli audit \
  --output-dir ./reports \
  --focus-privileges UPDATE,DELETE,INSERT,TRUNCATE,MODIFY \
  --flag-role-patterns "reader,viewer,analyst,bi_" \
  --flag-schema-patterns "prod_,finance_,sensitive_"

# Re-analyze saved JSON without querying Snowflake (tune heuristics)
python -m snowflake_rbac_auditor.cli audit \
  --from-json ./reports/audit-2026-07-14.json \
  --output-dir ./reports \
  --flag-role-patterns "reader,viewer,bi_reader"
```

Outputs:
- `reports/audit-2026-07-14.json` — structured permission graph for LLMs, diffing, or automation
- `reports/report-2026-07-14.md` — human-readable executive summary, Mermaid role hierarchy, flagged issues table, user impact counts, and basic deterministic recommendations

Feed the JSON into Claude, Cursor, or your local Hermes/Qwen model using the prompt in `prompts/least-privilege-advisor.md` for nuanced suggestions including proposed REVOKE statements (always human-reviewed).

## Cursor Agent Skills

Project skills in `.cursor/skills/` guide the agent through common workflows:

| Skill | Use when |
|-------|----------|
| `run-snowflake-rbac-audit` | Running audits, setup, troubleshooting |
| `analyze-rbac-audit` | Least-privilege recommendations from JSON |
| `review-revoke-recommendations` | Safety review before applying SQL |
| `tune-rbac-heuristics` | Adjusting flag patterns, reducing false positives |

Helper scripts: `scripts/preflight.sh`, `scripts/summarize_audit.py`.

## Required Snowflake Privileges

The auditor account needs read access to `SNOWFLAKE.ACCOUNT_USAGE` views:

- `ROLES`
- `GRANTS_TO_ROLES`
- `GRANTS_TO_USERS`

In practice this usually means a role with **ACCOUNTADMIN**, **SECURITYADMIN**, or a custom auditor role granted `IMPORTED PRIVILEGES` on the `SNOWFLAKE` database plus `USAGE` on the `ACCOUNT_USAGE` schema. Create a dedicated service user with key-pair auth and rotate keys regularly. Run from ephemeral environments when possible — audit outputs contain sensitive org structure.

## Scope — MVP First (ranked by impact/effort)

**Must have for v0.1 (addresses your core example immediately):**
- Secure extraction of current RBAC state using `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES`, `GRANTS_TO_USERS`, role lists, and targeted `SHOW GRANTS` where needed.
- Structured in-memory model (roles, users, grants, hierarchy edges).
- Clean Markdown documentation: executive summary, role hierarchy (Mermaid), grants breakdown, and a dedicated "Potential Over-Privileged Grants" section that directly surfaces roles/users with UPDATE/DELETE/etc. on tables/schemas that match read-oriented patterns or prod naming.
- JSON export with stable schema, metadata (run timestamp, account, extractor version, Snowflake edition hints), and full graph so LLMs or scripts have complete context without hallucinating the facts.
- Basic deterministic flagging + user count estimation (direct + note on inheritance).
- CLI with progress, rich tables, and config via env vars.
- `prompts/` folder with a high-quality, conservative system prompt tuned for Snowflake security analysis. Supports pasting JSON + your business context (e.g., "fact tables in prod should be append-only for ETL roles only").

**Explicitly out of MVP (prevent scope creep):**
- Auto-applying any changes or opening PRs.
- Full recursive "effective privileges for every user on every object" computation (very expensive; report direct grants + inheritance notes instead).
- Deep usage-based analysis from `ACCESS_HISTORY` (Enterprise+ only; make optional in v0.2 if demand exists — it adds powerful "unused privilege" signals but increases complexity and data sensitivity).
- Column-level grants, dynamic tables, tasks, or masking policy interactions in first pass.
- Web UI, dashboards, or Slack/Teams bots.
- Multi-account or cross-cloud aggregation.
- Full policy-as-code roundtrip (export to Permifrost YAML). Design the JSON so this is easy later.

**Later phases (only after v0.1 validated):**
- Optional ACCESS_HISTORY integration for "privileges that were never exercised in last N days".
- Better inheritance simulation for accurate user counts.
- Heuristic improvements from community examples.
- Thin optional LLM wrapper script (LiteLLM or direct Anthropic/OpenAI compatible) for fully local runs.
- GitHub Action example for scheduled audits (with proper secret handling).

## Architecture (lean, production-minded)

Single Python package. No servers, no external services required at runtime.

```
snowflake_rbac_auditor/
├── cli.py                 # argparse entrypoint
├── pipeline.py            # load/extract → analyze → write orchestration
├── connector.py           # context-managed Snowflake connection, keypair loader, safe config
├── extractor.py           # queries + in-memory hierarchy derivation
├── model.py               # dataclasses including AnalyzerConfig
├── analyzer.py            # deterministic heuristics, issue flagging, stats
├── reporter.py            # Markdown builder, Mermaid, JSON serializer
├── prompts/
│   └── least-privilege-advisor.md
├── examples/
│   └── sample-audit.json
└── pyproject.toml / requirements.txt
```

**Deps (strictly minimal for v0.1):**
- `snowflake-connector-python` (keypair + connection)
- `rich` (beautiful CLI tables and progress)
- Standard library only otherwise (json, pathlib, dataclasses, re for patterns)

No pandas, no graphviz, no heavy templating unless it proves necessary. Keep install footprint small and reviewable.

**Security & maintainability highlights:**
- Private key auth is the documented path; password support exists only for quick local testing with strong warnings.
- All outputs go to timestamped files in an output dir (never overwrite latest without flag).
- Sensitive values (user names, role names, object names) are treated as potentially confidential — `.gitignore` reports/ by default and document org-specific handling.
- The tool never executes DDL. It is read-only by design.
- Clear "Required Snowflake Privileges" section in docs (typically needs a role with ACCOUNTADMIN or equivalent for full `ACCOUNT_USAGE` access; discuss creating a dedicated low-risk auditor service account where possible).

## Core Extraction Approach (facts, not estimates)

Use these Snowflake sources (exact queries will live in `extractor.py`):

- `SNOWFLAKE.ACCOUNT_USAGE.ROLES` or `SHOW ROLES` for role inventory.
- `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES` for privilege grants to roles (filter by `granted_on` in TABLE, SCHEMA, DATABASE, VIEW, etc.).
- `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS` for direct user-to-role grants.
- Role-to-role grants appear in `GRANTS_TO_ROLES` (privilege column semantics for roles).
- For deeper object detail on specific objects: `SHOW GRANTS ON <object>` in targeted loops (rate-limit aware).
- Optional (Enterprise): `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY` for last-access patterns (join on object names/IDs to flag unused high privileges).

The analyzer applies simple, transparent rules first:
- Any grant of UPDATE/DELETE/INSERT/TRUNCATE/MODIFY on a table or schema whose name matches `--flag-schema-patterns` or whose parent database looks production.
- Roles whose name matches `--flag-role-patterns` (reader/viewer/analyst) that hold any of the above.
- Rough user impact: count of direct grantees + recursive note for inherited roles.

This directly answers "how many users have update/delete permissions on tables that they should only be able to read."

The LLM layer then receives the complete structured picture plus any additional context you supply and produces reasoned, conservative suggestions.

## Using the AI Wrapper Layer (Claude / Cursor / local models)

1. Run the audit.
2. Open `audit-*.json` (or relevant subset) in your editor.
3. In Cursor: Use composer, reference the `prompts/least-privilege-advisor.md` file, and include the JSON (or ask it to read the file). Add your business rules in the message.
4. In Claude: Paste key sections or upload the JSON to a Project/Artifact and use the same prompt.
5. On your Mac Studio with Hermes/Qwen: The JSON is compact enough for strong local models. You already have the infrastructure.

The prompt is written to be:
- Conservative ("do not recommend changes that could break existing pipelines without explicit testing notes").
- Structured output (JSON or clear sections with REVOKE SQL, confidence, blast radius, test steps).
- Context-aware (you can prepend org-specific policies).

This keeps the "smart" part where it belongs (LLM reasoning) while the tool owns accurate, complete, versionable facts.

## Tradeoffs & Decision Framework

| Option                        | Impact                          | Effort | Risks                              | Recommendation |
|-------------------------------|---------------------------------|--------|------------------------------------|----------------|
| Pure deterministic reporting only | High for visibility            | Low    | Misses nuanced business context   | Good v0.1 base |
| Add full effective-priv recursion | High accuracy                  | High   | Performance, complexity           | Post-MVP      |
| Usage-based (ACCESS_HISTORY)     | Very high for least-privilege  | Med    | Edition limit, data volume/privacy| v0.2 optional |
| Auto-remediation                 | High velocity                  | High   | Safety, trust, rollback           | Never in core |
| LLM-only analysis (no structured facts) | Low (hallucination risk)    | Low    | Wrong facts, incomplete           | Avoid         |
| Hybrid (structured + LLM prompts) | Highest practical value       | Med    | Prompt drift, human review needed | Chosen path   |

Favor the hybrid because it reuses your existing Cursor/local LLM investment, produces auditable artifacts, and keeps security decisions with humans.

## Risks & Second-Order Effects (devil's advocate)

- **Credential & privilege risk:** The auditor role needs significant visibility. Document key rotation, dedicated service accounts, and running from ephemeral environments. A compromised auditor key is dangerous.
- **LLM over-trust:** Even with excellent prompts, models can suggest unsafe revokes or miss side effects (tasks, dynamic tables, future grants, stored procs using the privilege). The prompt and README will hammer "human review + test in lower environment + impact analysis required."
- **Incomplete picture without usage data:** On Standard edition or without ACCESS_HISTORY joins, we flag on naming heuristics only. This can produce false positives (legitimate broad grants for admin/ETL roles). v0.2 can tighten this.
- **Drift vs enforcement:** This tool finds problems. It does not prevent them. Pair with Permifrost or equivalent for "permissions as code" to reduce future drift.
- **Maintenance & Snowflake evolution:** New object types, privilege names, and view changes will require updates. OSS model helps if community adopts; otherwise it becomes your ongoing cost.
- **Data sensitivity in outputs:** Role and grant data can reveal org structure or sensitive projects. Treat reports as confidential.
- **Opportunity cost:** Time invested here is time not spent on OpQuest features, client delivery, or family. Scope tightly and consider whether a simpler internal script meets 80% of needs before open-sourcing.

## Best Practices & Anti-Patterns

**Best practices:**
- Always run with the least Snowflake privileges possible for the audit.
- Version the JSON outputs alongside code or in a private audit repo.
- Start with narrow focus (one database or schema pattern) before account-wide.
- Add your org's specific naming conventions and policies to the prompt and CLI flags.
- Review LLM output in a pair with a human who understands the workloads.

**Anti-patterns to avoid:**
- Building a full RBAC simulator or re-implementing Snowflake's grant model in Python in v0.1.
- Letting the LLM be the source of truth for "what grants exist" — it must consume the tool's JSON.
- Auto-committing or auto-applying suggestions.
- Ignoring future grants and managed access schemas (document these limitations clearly).
- Over-engineering the CLI or adding web framework "just in case."

## Next Concrete Steps

1. Test against a real Snowflake account and tune `--flag-role-patterns` / `--flag-schema-patterns` for your naming conventions.
2. Anonymize a sample audit JSON for the repo if you want richer examples than `examples/sample-audit.json`.
3. Consider v0.2 additions (ACCESS_HISTORY, better inheritance counts) only after validating the core loop on production-like data.

This scoped approach delivers immediate value on your stated example while staying maintainable, secure, and aligned with reuse over reinvention.

What could invalidate this recommendation?
If your actual day-to-day pain is primarily declarative drift prevention and automated enforcement rather than periodic discovery + AI-augmented analysis, then forking or contributing to Permifrost (or adopting Titan Core) would deliver faster ROI with less custom code. If permission issues are already rare because of strong IaC practices, the marginal value of this auditor drops. If testing shows that even well-prompted local LLMs consistently produce recommendations requiring too much manual correction to be worth the context overhead, then a pure deterministic reporting tool (without the AI layer) would be the simpler, more reliable choice.