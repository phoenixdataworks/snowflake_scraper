"""Generate Markdown reports and JSON exports from audit results."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from snowflake_rbac_auditor.model import AuditResult, FlaggedIssue, RoleHierarchyEdge


def _mermaid_role_hierarchy(edges: list[RoleHierarchyEdge], max_nodes: int = 40) -> str:
    if not edges:
        return "_No role hierarchy edges found._"

    parent_to_children: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        parent_to_children[edge.parent_role].append(edge.child_role)

    lines = ["```mermaid", "flowchart TD"]
    node_ids: dict[str, str] = {}
    node_count = 0

    def node_id(name: str) -> str:
        nonlocal node_count
        if name not in node_ids:
            safe = re.sub(r"[^A-Za-z0-9_]", "_", name)
            node_ids[name] = f"R{node_count}_{safe[:20]}"
            node_count += 1
        return node_ids[name]

    rendered = 0
    for parent, children in sorted(parent_to_children.items()):
        if rendered >= max_nodes:
            lines.append('    note["... truncated for readability ..."]')
            break
        pid = node_id(parent)
        lines.append(f'    {pid}["{parent}"]')
        for child in sorted(set(children)):
            if rendered >= max_nodes:
                break
            cid = node_id(child)
            lines.append(f'    {cid}["{child}"]')
            lines.append(f"    {pid} --> {cid}")
            rendered += 1

    lines.append("```")
    return "\n".join(lines)


def _issues_table(issues: list[FlaggedIssue]) -> str:
    if not issues:
        return "_No flagged issues matched the configured heuristics._"

    rows = [
        "| Severity | Role | Privilege | Object | Users | Reason |",
        "|----------|------|-----------|--------|-------|--------|",
    ]
    for issue in issues:
        rows.append(
            "| {severity} | `{grantee}` | {privilege} | `{obj}` | {users} | {reason} |".format(
                severity=issue.severity.upper(),
                grantee=issue.grantee_name,
                privilege=issue.privilege,
                obj=issue.object_name,
                users=issue.affected_users_count,
                reason=issue.reason.replace("|", "\\|"),
            )
        )
    return "\n".join(rows)


def _recommendations_section(issues: list[FlaggedIssue], limit: int = 10) -> str:
    if not issues:
        return "_No deterministic recommendations — no issues flagged._"

    lines = []
    for issue in issues[:limit]:
        lines.append(f"- **{issue.grantee_name}** on `{issue.object_name}`: {issue.recommendation}")
    if len(issues) > limit:
        lines.append(f"\n_... and {len(issues) - limit} more issues. See JSON for full detail._")
    return "\n".join(lines)


def build_markdown_report(result: AuditResult) -> str:
    meta = result.metadata
    stats = result.stats

    high_count = sum(1 for i in result.flagged_issues if i.severity == "high")
    medium_count = sum(1 for i in result.flagged_issues if i.severity == "medium")

    sections = [
        "# Snowflake RBAC Audit Report",
        "",
        f"**Generated:** {meta.run_timestamp}  ",
        f"**Account:** `{meta.account}`  ",
        f"**Extractor version:** {meta.extractor_version}  ",
        f"**Snowflake edition:** {meta.snowflake_edition or 'unknown'}  ",
        "",
        "## Executive Summary",
        "",
        f"- **Roles:** {stats.role_count}",
        f"- **Users with role assignments:** {stats.user_count}",
        f"- **Grants to roles:** {stats.grants_to_roles_count}",
        f"- **DML grants on tables/views (monitored):** {stats.dml_grants_on_tables_count}",
        f"- **Flagged over-privileged grants:** {stats.flagged_issue_count} "
        f"({high_count} high, {medium_count} medium)",
        "",
        "> **Human review required.** This report uses naming heuristics and does not "
        "compute full effective privileges or usage patterns.",
        "",
        "## Role Hierarchy (sample)",
        "",
        _mermaid_role_hierarchy(result.role_hierarchy),
        "",
        "## Potential Over-Privileged Grants",
        "",
        _issues_table(result.flagged_issues),
        "",
        "## Deterministic Recommendations (sample)",
        "",
        _recommendations_section(result.flagged_issues),
        "",
        "## Configuration Used",
        "",
        f"- Focus privileges: `{', '.join(meta.focus_privileges)}`",
        f"- Flag role patterns: `{', '.join(meta.flag_role_patterns)}`",
        f"- Flag schema patterns: `{', '.join(meta.flag_schema_patterns)}`",
        "",
        "## Next Steps",
        "",
        "1. Review flagged grants with workload owners.",
        "2. Feed `audit-*.json` to an LLM using `prompts/least-privilege-advisor.md`.",
        "3. Test any proposed REVOKE statements in a lower environment first.",
        "",
    ]
    return "\n".join(sections)


def write_reports(result: AuditResult, output_dir: Path, *, overwrite: bool = False) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    date_suffix = result.metadata.run_timestamp[:10]
    json_path = output_dir / f"audit-{date_suffix}.json"

    if not overwrite:
        json_path = _unique_numbered_path(json_path)

    report_stem = json_path.stem.replace("audit-", "report-", 1)
    md_path = output_dir / f"{report_stem}.md"

    json_path.write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(build_markdown_report(result), encoding="utf-8")
    return json_path, md_path


def _unique_numbered_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    counter = 1
    while True:
        candidate = path.with_name(f"{stem}-{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1
