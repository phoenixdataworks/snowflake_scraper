"""Deterministic heuristics for flagging over-privileged grants."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import replace

from snowflake_rbac_auditor.model import (
    AnalyzerConfig,
    AuditResult,
    FlaggedIssue,
    Grant,
    Severity,
)


def _compile_patterns(patterns: tuple[str, ...]) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        stripped = pattern.strip()
        if not stripped:
            continue
        compiled.append(re.compile(re.escape(stripped), re.IGNORECASE))
    return compiled


def _matches_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def _object_context(grant: Grant) -> str:
    parts = [grant.table_catalog or "", grant.table_schema or "", grant.name]
    return ".".join(part for part in parts if part)


def _is_dml_grant(grant: Grant, focus_privileges: frozenset[str]) -> bool:
    privilege = grant.privilege.upper()
    if privilege == "ALL":
        return True
    return privilege in focus_privileges


def _is_target_object(grant: Grant) -> bool:
    return grant.granted_on in {"TABLE", "VIEW", "SCHEMA", "DATABASE"}


def _should_flag(role_match: bool, schema_match: bool) -> bool:
    """Flag when the role name OR object/schema matches configured patterns."""
    return role_match or schema_match


def _count_dml_grants_on_tables(
    grants: list[Grant],
    focus_privileges: frozenset[str],
) -> int:
    return sum(
        1
        for grant in grants
        if grant.granted_on in {"TABLE", "VIEW"}
        and _is_dml_grant(grant, focus_privileges)
    )


def _build_role_to_users(result: AuditResult) -> dict[str, set[str]]:
    role_users: dict[str, set[str]] = defaultdict(set)
    for user in result.users:
        for role_name in user.assigned_roles:
            role_users[role_name.upper()].add(user.name)
    return role_users


def _build_role_ancestors(result: AuditResult) -> dict[str, set[str]]:
    """Map child role -> parent roles that inherit it (one hop only in v0.1)."""
    ancestors: dict[str, set[str]] = defaultdict(set)
    for edge in result.role_hierarchy:
        ancestors[edge.child_role.upper()].add(edge.parent_role)
    return ancestors


def _count_affected_users(
    grantee_name: str,
    role_users: dict[str, set[str]],
    role_ancestors: dict[str, set[str]],
) -> tuple[int, str]:
    direct_users = role_users.get(grantee_name.upper(), set())
    parent_roles = role_ancestors.get(grantee_name.upper(), set())

    if direct_users:
        note = "Direct role assignment"
        if parent_roles:
            note += f"; also inherited by parent roles: {', '.join(sorted(parent_roles))}"
        return len(direct_users), note

    if parent_roles:
        return 0, (
            "No direct users; privilege may reach users via parent roles: "
            + ", ".join(sorted(parent_roles))
        )

    return 0, "No direct users assigned to this role"


def _deterministic_recommendation(grant: Grant, reason: str) -> str:
    obj = _object_context(grant) or grant.name
    return (
        f"Review whether {grant.grantee_name} needs {grant.privilege} on {obj}. "
        f"If read-only access is sufficient, revoke {grant.privilege} and grant SELECT only. "
        f"Flag reason: {reason}"
    )


def _severity_for(user_count: int) -> Severity:
    return "high" if user_count > 0 else "medium"


def analyze(result: AuditResult, config: AnalyzerConfig) -> AuditResult:
    focus = frozenset(privilege.strip().upper() for privilege in config.focus_privileges if privilege.strip())
    role_patterns = _compile_patterns(config.flag_role_patterns)
    schema_patterns = _compile_patterns(config.flag_schema_patterns)

    role_users = _build_role_to_users(result)
    role_ancestors = _build_role_ancestors(result)

    seen: set[tuple[str, str, str, str, str]] = set()
    issues: list[FlaggedIssue] = []

    for grant in result.grants_to_roles:
        if grant.grantee_type != "ROLE":
            continue
        if not _is_target_object(grant):
            continue
        if not _is_dml_grant(grant, focus):
            continue

        context = _object_context(grant)
        role_match = _matches_any(grant.grantee_name, role_patterns)
        schema_match = _matches_any(context, schema_patterns) or _matches_any(
            grant.name, schema_patterns
        )

        if not _should_flag(role_match, schema_match):
            continue

        dedupe_key = (
            grant.grantee_name,
            grant.privilege,
            grant.granted_on,
            grant.name,
            context,
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        reasons: list[str] = []
        if role_match:
            reasons.append(f"role name matches read-oriented pattern ({grant.grantee_name})")
        if schema_match:
            reasons.append(f"object/schema matches sensitive pattern ({context or grant.name})")

        reason = "; ".join(reasons)
        user_count, user_note = _count_affected_users(
            grant.grantee_name, role_users, role_ancestors
        )

        issues.append(
            FlaggedIssue(
                severity=_severity_for(user_count),
                reason=reason,
                grantee_name=grant.grantee_name,
                grantee_type=grant.grantee_type,
                privilege=grant.privilege,
                granted_on=grant.granted_on,
                object_name=context or grant.name,
                affected_users_count=user_count,
                affected_users_note=user_note,
                recommendation=_deterministic_recommendation(grant, reason),
            )
        )

    issues.sort(
        key=lambda issue: (
            0 if issue.severity == "high" else 1,
            -issue.affected_users_count,
            issue.grantee_name,
            issue.object_name,
        )
    )

    result.flagged_issues = issues
    result.stats = replace(
        result.stats,
        flagged_issue_count=len(issues),
        dml_grants_on_tables_count=_count_dml_grants_on_tables(result.grants_to_roles, focus),
    )
    return result
