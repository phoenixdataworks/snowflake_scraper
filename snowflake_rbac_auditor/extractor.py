"""Extract RBAC state from Snowflake ACCOUNT_USAGE views."""

from __future__ import annotations

from typing import Any, Iterable

import snowflake.connector
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from snowflake_rbac_auditor.model import (
    AuditMetadata,
    AuditResult,
    AuditStats,
    Grant,
    GranteeType,
    Role,
    RoleHierarchyEdge,
    User,
    utc_now_iso,
)

console = Console()

ROLES_QUERY = """
SELECT name, owner, comment
FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
WHERE deleted IS NULL
ORDER BY name
"""

GRANTS_TO_ROLES_QUERY = """
SELECT
    grantee_name,
    granted_to,
    privilege,
    granted_on,
    name,
    table_catalog,
    table_schema,
    granted_by,
    grant_option
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE deleted IS NULL
ORDER BY grantee_name, granted_on, name
"""

GRANTS_TO_USERS_QUERY = """
SELECT
    grantee_name,
    role AS name,
    granted_by
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE deleted IS NULL
ORDER BY grantee_name, role
"""


def _fetch_all(cursor: snowflake.connector.cursor.SnowflakeCursor) -> list[dict[str, Any]]:
    columns = [col[0].lower() for col in cursor.description or []]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _bool_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return str(value).upper() in {"TRUE", "YES", "Y", "1"}


def _grantee_type(value: str | None) -> GranteeType:
    normalized = (value or "ROLE").upper()
    if normalized == "USER":
        return "USER"
    return "ROLE"


def _row_to_grant(row: dict[str, Any], grantee_type: GranteeType) -> Grant:
    return Grant(
        grantee_name=row.get("grantee_name") or "",
        grantee_type=grantee_type,
        privilege=(row.get("privilege") or "").upper(),
        granted_on=(row.get("granted_on") or "").upper(),
        name=row.get("name") or "",
        table_catalog=row.get("table_catalog"),
        table_schema=row.get("table_schema"),
        granted_by=row.get("granted_by"),
        grant_option=_bool_value(row.get("grant_option")),
    )


def _build_users(grants_to_users_rows: Iterable[dict[str, Any]]) -> list[User]:
    roles_by_user: dict[str, list[str]] = {}
    for row in grants_to_users_rows:
        user_name = row.get("grantee_name") or ""
        role_name = row.get("name") or ""
        if user_name and role_name:
            roles_by_user.setdefault(user_name, []).append(role_name)

    return [
        User(name=user_name, assigned_roles=tuple(sorted(set(roles))))
        for user_name, roles in sorted(roles_by_user.items())
    ]


def _derive_role_hierarchy(grants: list[Grant]) -> list[RoleHierarchyEdge]:
    edges = [
        RoleHierarchyEdge(parent_role=grant.grantee_name, child_role=grant.name)
        for grant in grants
        if grant.granted_on == "ROLE" and grant.privilege == "USAGE"
    ]
    return sorted(edges, key=lambda edge: (edge.parent_role, edge.child_role))


def extract_rbac(
    connection: snowflake.connector.SnowflakeConnection,
    *,
    account: str,
    extractor_version: str,
) -> AuditResult:
    metadata = AuditMetadata(
        run_timestamp=utc_now_iso(),
        account=account,
        extractor_version=extractor_version,
    )
    result = AuditResult(metadata=metadata)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Connecting to Snowflake ACCOUNT_USAGE...", total=None)

        with connection.cursor() as cursor:
            progress.update(task, description="Fetching roles...")
            role_rows = _fetch_all(cursor.execute(ROLES_QUERY))
            result.roles = [
                Role(
                    name=row["name"],
                    owner=row.get("owner"),
                    comment=row.get("comment"),
                )
                for row in role_rows
            ]

            progress.update(task, description="Fetching grants to roles...")
            grant_rows = _fetch_all(cursor.execute(GRANTS_TO_ROLES_QUERY))
            result.grants_to_roles = [
                _row_to_grant(row, _grantee_type(row.get("granted_to")))
                for row in grant_rows
            ]
            result.role_hierarchy = _derive_role_hierarchy(result.grants_to_roles)

            progress.update(task, description="Fetching grants to users...")
            user_grant_rows = _fetch_all(cursor.execute(GRANTS_TO_USERS_QUERY))
            result.users = _build_users(user_grant_rows)
            result.grants_to_users = [
                Grant(
                    grantee_name=row.get("grantee_name") or "",
                    grantee_type="USER",
                    privilege="ROLE",
                    granted_on="ROLE",
                    name=row.get("name") or "",
                    granted_by=row.get("granted_by"),
                )
                for row in user_grant_rows
            ]

            progress.update(task, description="Collecting account metadata...")
            try:
                cursor.execute("SELECT CURRENT_EDITION() AS edition")
                edition_row = cursor.fetchone()
                if edition_row:
                    result.metadata.snowflake_edition = edition_row[0]
            except snowflake.connector.errors.ProgrammingError:
                result.metadata.snowflake_edition = None

        progress.update(task, description="Extraction complete.")

    result.stats = AuditStats(
        role_count=len(result.roles),
        user_count=len(result.users),
        grants_to_roles_count=len(result.grants_to_roles),
        grants_to_users_count=len(result.grants_to_users),
        hierarchy_edge_count=len(result.role_hierarchy),
    )

    console.print(
        f"[green]Extracted[/green] {result.stats.role_count} roles, "
        f"{result.stats.user_count} users, "
        f"{result.stats.grants_to_roles_count} role grants."
    )
    return result
