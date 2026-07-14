"""CLI entrypoint for snowflake-rbac-auditor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from snowflake_rbac_auditor import __version__
from snowflake_rbac_auditor.connector import SnowflakeConfig
from snowflake_rbac_auditor.model import AnalyzerConfig
from snowflake_rbac_auditor.pipeline import AuditPipelineError, run_audit

console = Console()


def _build_audit_parser(subparsers: argparse._SubParsersAction) -> None:
    defaults = AnalyzerConfig.defaults()
    audit = subparsers.add_parser(
        "audit",
        help="Extract RBAC state, analyze grants, and write Markdown + JSON reports",
    )
    audit.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Directory for timestamped report files (default: ./reports)",
    )
    audit.add_argument(
        "--focus-privileges",
        default=",".join(defaults.focus_privileges),
        help="Comma-separated DML privileges to monitor (default: UPDATE,DELETE,...)",
    )
    audit.add_argument(
        "--flag-role-patterns",
        default=",".join(defaults.flag_role_patterns),
        help="Comma-separated substrings; roles matching these are flagged if they hold DML grants",
    )
    audit.add_argument(
        "--flag-schema-patterns",
        default=",".join(defaults.flag_schema_patterns),
        help="Comma-separated substrings; objects/schemas matching these are flagged for DML grants",
    )
    audit.add_argument(
        "--from-json",
        type=Path,
        help="Re-analyze an existing audit JSON instead of querying Snowflake",
    )
    audit.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite same-day report files instead of creating suffixed copies",
    )
    audit.set_defaults(func=_run_audit)


def _run_audit(args: argparse.Namespace) -> int:
    config = AnalyzerConfig.from_csv(
        args.focus_privileges,
        args.flag_role_patterns,
        args.flag_schema_patterns,
    )

    try:
        run = run_audit(
            config=config,
            output_dir=args.output_dir,
            overwrite=args.overwrite,
            from_json=args.from_json,
            snowflake_config=None if args.from_json else SnowflakeConfig.from_env(),
        )
    except AuditPipelineError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1

    if args.from_json:
        console.print(f"[dim]Loaded audit from {args.from_json}[/dim]")

    _print_summary(run.result, run.json_path, run.markdown_path)
    return 0


def _print_summary(result, json_path: Path, md_path: Path) -> None:
    table = Table(title="Audit Complete")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    stats = result.stats
    table.add_row("Roles", str(stats.role_count))
    table.add_row("Users", str(stats.user_count))
    table.add_row("Grants to roles", str(stats.grants_to_roles_count))
    table.add_row("Flagged issues", str(stats.flagged_issue_count))
    table.add_row("JSON output", str(json_path))
    table.add_row("Markdown output", str(md_path))

    console.print(table)
    console.print(
        "\n[dim]Next: open the JSON and use prompts/least-privilege-advisor.md "
        "with Claude, Cursor, or your local model.[/dim]"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snowflake-rbac-auditor",
        description="Audit Snowflake RBAC and generate least-privilege analysis artifacts",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    _build_audit_parser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
