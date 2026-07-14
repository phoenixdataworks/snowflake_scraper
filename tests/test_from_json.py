"""Tests for JSON round-trip, pipeline, and --from-json re-analysis."""

from __future__ import annotations

import json
from pathlib import Path

from snowflake_rbac_auditor.analyzer import analyze
from snowflake_rbac_auditor.cli import main
from snowflake_rbac_auditor.extractor import _derive_role_hierarchy
from snowflake_rbac_auditor.model import AnalyzerConfig, AuditResult, Grant
from snowflake_rbac_auditor.pipeline import load_audit_json, run_audit
from snowflake_rbac_auditor.reporter import build_markdown_report


def test_audit_result_from_dict_round_trip() -> None:
    sample_path = Path("examples/sample-audit.json")
    data = json.loads(sample_path.read_text(encoding="utf-8"))
    result = AuditResult.from_dict(data)

    assert result.metadata.account == "xy12345.us-east-1"
    assert len(result.roles) == 3
    assert len(result.grants_to_roles) == 5
    assert len(result.users) == 3
    assert len(result.flagged_issues) == 3


def test_from_json_cli_reanalyze(tmp_path: Path) -> None:
    sample_path = Path("examples/sample-audit.json")
    output_dir = tmp_path / "reports"
    exit_code = main(
        [
            "audit",
            "--from-json",
            str(sample_path),
            "--output-dir",
            str(output_dir),
            "--flag-role-patterns",
            "reader,bi_",
            "--flag-schema-patterns",
            "prod_,finance_",
        ]
    )

    assert exit_code == 0
    json_files = list(output_dir.glob("audit-*.json"))
    md_files = list(output_dir.glob("report-*.md"))
    assert len(json_files) == 1
    assert len(md_files) == 1

    output = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert output["stats"]["flagged_issue_count"] >= 1


def test_from_dict_then_analyze_matches_sample_issues() -> None:
    sample_path = Path("examples/sample-audit.json")
    result = load_audit_json(sample_path)
    config = AnalyzerConfig.from_metadata(result.metadata)

    analyzed = analyze(result, config)

    assert analyzed.stats.flagged_issue_count == 3


def test_pipeline_run_from_json(tmp_path: Path) -> None:
    sample_path = Path("examples/sample-audit.json")
    output_dir = tmp_path / "reports"

    run = run_audit(
        config=AnalyzerConfig.defaults(),
        output_dir=output_dir,
        from_json=sample_path,
    )

    assert run.json_path.exists()
    assert run.markdown_path.exists()
    assert run.result.stats.flagged_issue_count >= 1


def test_derive_role_hierarchy_from_grants() -> None:
    grants = [
        Grant(
            grantee_name="SYSADMIN",
            grantee_type="ROLE",
            privilege="USAGE",
            granted_on="ROLE",
            name="BI_READER",
        ),
        Grant(
            grantee_name="BI_READER",
            grantee_type="ROLE",
            privilege="SELECT",
            granted_on="TABLE",
            name="FACT_ORDERS",
            table_catalog="PROD",
            table_schema="PUBLIC",
        ),
    ]

    hierarchy = _derive_role_hierarchy(grants)

    assert len(hierarchy) == 1
    assert hierarchy[0].parent_role == "SYSADMIN"
    assert hierarchy[0].child_role == "BI_READER"


def test_reporter_includes_flagged_section() -> None:
    sample_path = Path("examples/sample-audit.json")
    result = load_audit_json(sample_path)
    analyzed = analyze(result, AnalyzerConfig.from_metadata(result.metadata))

    markdown = build_markdown_report(analyzed)

    assert "Potential Over-Privileged Grants" in markdown
    assert "BI_READER" in markdown
