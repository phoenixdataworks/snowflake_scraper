"""Unit tests for deterministic analyzer heuristics."""

from __future__ import annotations

from snowflake_rbac_auditor.analyzer import analyze, _should_flag
from snowflake_rbac_auditor.model import (
    AnalyzerConfig,
    AuditMetadata,
    AuditResult,
    AuditStats,
    Grant,
    RoleHierarchyEdge,
    User,
)


def _sample_config() -> AnalyzerConfig:
    return AnalyzerConfig(
        focus_privileges=("UPDATE", "DELETE"),
        flag_role_patterns=("reader", "bi_"),
        flag_schema_patterns=("prod_",),
    )


def _sample_result() -> AuditResult:
    return AuditResult(
        metadata=AuditMetadata(
            run_timestamp="2026-07-14T12:00:00+00:00",
            account="test",
            extractor_version="0.1.0",
        ),
        users=[
            User(name="user_a", assigned_roles=("BI_READER",)),
            User(name="user_b", assigned_roles=("BI_READER",)),
        ],
        grants_to_roles=[
            Grant(
                grantee_name="BI_READER",
                grantee_type="ROLE",
                privilege="UPDATE",
                granted_on="TABLE",
                name="FACT_ORDERS",
                table_catalog="PROD_ANALYTICS",
                table_schema="PUBLIC",
            ),
            Grant(
                grantee_name="ETL_LOADER",
                grantee_type="ROLE",
                privilege="INSERT",
                granted_on="TABLE",
                name="FACT_ORDERS",
                table_catalog="PROD_ANALYTICS",
                table_schema="PUBLIC",
            ),
        ],
        role_hierarchy=[
            RoleHierarchyEdge(parent_role="SYSADMIN", child_role="BI_READER"),
        ],
        stats=AuditStats(grants_to_roles_count=2),
    )


def test_should_flag_uses_role_or_schema_match() -> None:
    assert _should_flag(role_match=True, schema_match=False) is True
    assert _should_flag(role_match=False, schema_match=True) is True
    assert _should_flag(role_match=False, schema_match=False) is False


def test_flags_reader_role_with_dml_on_prod_schema() -> None:
    result = analyze(_sample_result(), _sample_config())

    assert len(result.flagged_issues) == 1
    issue = result.flagged_issues[0]
    assert issue.grantee_name == "BI_READER"
    assert issue.privilege == "UPDATE"
    assert issue.affected_users_count == 2
    assert issue.severity == "high"


def test_does_not_flag_etl_role_without_pattern_match() -> None:
    result = _sample_result()
    result.grants_to_roles = [
        Grant(
            grantee_name="ETL_LOADER",
            grantee_type="ROLE",
            privilege="INSERT",
            granted_on="TABLE",
            name="STAGING_ORDERS",
            table_catalog="DEV_ANALYTICS",
            table_schema="PUBLIC",
        )
    ]

    analyzed = analyze(result, _sample_config())

    assert len(analyzed.flagged_issues) == 0
