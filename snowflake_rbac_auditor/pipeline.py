"""Audit pipeline: load or extract, analyze, and write reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import snowflake.connector

from snowflake_rbac_auditor import __version__
from snowflake_rbac_auditor.analyzer import analyze
from snowflake_rbac_auditor.connector import SnowflakeConfig, connect
from snowflake_rbac_auditor.extractor import extract_rbac
from snowflake_rbac_auditor.model import AnalyzerConfig, AuditResult, utc_now_iso
from snowflake_rbac_auditor.reporter import write_reports


class AuditPipelineError(Exception):
    """Raised when audit pipeline steps fail."""


@dataclass(frozen=True)
class AuditRunResult:
    result: AuditResult
    json_path: Path
    markdown_path: Path


def load_audit_json(path: Path) -> AuditResult:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return AuditResult.from_dict(data)
    except json.JSONDecodeError as exc:
        raise AuditPipelineError(f"Invalid audit JSON: {exc}") from exc
    except (KeyError, TypeError) as exc:
        raise AuditPipelineError(f"Invalid audit JSON shape: {exc}") from exc


def extract_live(config: SnowflakeConfig) -> AuditResult:
    config.validate()
    try:
        with connect(config) as connection:
            return extract_rbac(
                connection,
                account=config.account,
                extractor_version=__version__,
            )
    except snowflake.connector.errors.Error as exc:
        raise AuditPipelineError(f"Snowflake connection or extraction failed: {exc}") from exc
    except OSError as exc:
        raise AuditPipelineError(f"Snowflake connection or extraction failed: {exc}") from exc


def run_audit(
    *,
    config: AnalyzerConfig,
    output_dir: Path,
    overwrite: bool = False,
    from_json: Path | None = None,
    snowflake_config: SnowflakeConfig | None = None,
) -> AuditRunResult:
    if from_json is not None:
        if not from_json.is_file():
            raise AuditPipelineError(f"File not found: {from_json}")
        result = load_audit_json(from_json)
        result.metadata = config.apply_to_metadata(
            result.metadata,
            run_timestamp=utc_now_iso(),
            extractor_version=__version__,
        )
    else:
        if snowflake_config is None:
            raise AuditPipelineError("Snowflake configuration is required for live audits")
        result = extract_live(snowflake_config)
        result.metadata = config.apply_to_metadata(result.metadata)

    result = analyze(result, config)
    json_path, markdown_path = write_reports(result, output_dir, overwrite=overwrite)
    return AuditRunResult(result=result, json_path=json_path, markdown_path=markdown_path)
