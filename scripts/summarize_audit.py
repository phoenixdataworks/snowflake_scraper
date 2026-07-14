#!/usr/bin/env python3
"""Print top flagged issues from an audit JSON (for context-limited models)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from snowflake_rbac_auditor.pipeline import load_audit_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize flagged issues from audit JSON")
    parser.add_argument("audit_json", type=Path, help="Path to audit-*.json")
    parser.add_argument("--limit", type=int, default=10, help="Max issues to print")
    args = parser.parse_args()

    try:
        result = load_audit_json(args.audit_json)
    except Exception as exc:
        print(f"Error loading audit JSON: {exc}", file=sys.stderr)
        return 1

    issues = result.flagged_issues
    meta = result.metadata

    print(f"Account: {meta.account}")
    print(f"Run: {meta.run_timestamp}")
    print(f"Flagged issues: {len(issues)}")
    print()

    for index, issue in enumerate(issues[: args.limit], start=1):
        print(
            f"{index}. [{issue.severity.upper()}] "
            f"{issue.grantee_name} — {issue.privilege} on "
            f"{issue.object_name} ({issue.affected_users_count} users)"
        )
        print(f"   Reason: {issue.reason}")

    if len(issues) > args.limit:
        print(f"\n... and {len(issues) - args.limit} more (see full JSON)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
