"""Typed data model for Snowflake RBAC audit artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Literal

GranteeType = Literal["ROLE", "USER"]
Severity = Literal["high", "medium"]

DEFAULT_FOCUS_PRIVILEGES = ("UPDATE", "DELETE", "INSERT", "TRUNCATE", "MODIFY")
DEFAULT_FLAG_ROLE_PATTERNS = ("reader", "viewer", "analyst", "bi_")
DEFAULT_FLAG_SCHEMA_PATTERNS = ("prod_", "finance_", "sensitive_")


@dataclass(frozen=True)
class AnalyzerConfig:
    focus_privileges: tuple[str, ...]
    flag_role_patterns: tuple[str, ...]
    flag_schema_patterns: tuple[str, ...]

    @classmethod
    def defaults(cls) -> AnalyzerConfig:
        return cls(
            focus_privileges=DEFAULT_FOCUS_PRIVILEGES,
            flag_role_patterns=DEFAULT_FLAG_ROLE_PATTERNS,
            flag_schema_patterns=DEFAULT_FLAG_SCHEMA_PATTERNS,
        )

    @classmethod
    def from_csv(
        cls,
        focus_privileges: str,
        flag_role_patterns: str,
        flag_schema_patterns: str,
    ) -> AnalyzerConfig:
        return cls(
            focus_privileges=_split_csv(focus_privileges),
            flag_role_patterns=_split_csv(flag_role_patterns),
            flag_schema_patterns=_split_csv(flag_schema_patterns),
        )

    @classmethod
    def from_metadata(cls, metadata: AuditMetadata) -> AnalyzerConfig:
        return cls(
            focus_privileges=metadata.focus_privileges or DEFAULT_FOCUS_PRIVILEGES,
            flag_role_patterns=metadata.flag_role_patterns or DEFAULT_FLAG_ROLE_PATTERNS,
            flag_schema_patterns=metadata.flag_schema_patterns or DEFAULT_FLAG_SCHEMA_PATTERNS,
        )

    def apply_to_metadata(
        self,
        metadata: AuditMetadata,
        *,
        run_timestamp: str | None = None,
        extractor_version: str | None = None,
    ) -> AuditMetadata:
        return replace(
            metadata,
            run_timestamp=run_timestamp or metadata.run_timestamp,
            extractor_version=extractor_version or metadata.extractor_version,
            focus_privileges=self.focus_privileges,
            flag_role_patterns=self.flag_role_patterns,
            flag_schema_patterns=self.flag_schema_patterns,
        )


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


@dataclass(frozen=True)
class Role:
    name: str
    owner: str | None = None
    comment: str | None = None


@dataclass(frozen=True)
class User:
    name: str
    default_role: str | None = None
    assigned_roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class Grant:
    grantee_name: str
    grantee_type: GranteeType
    privilege: str
    granted_on: str
    name: str
    table_catalog: str | None = None
    table_schema: str | None = None
    granted_by: str | None = None
    grant_option: bool = False

    @property
    def qualified_name(self) -> str:
        if self.table_catalog and self.table_schema:
            return f"{self.table_catalog}.{self.table_schema}.{self.name}"
        if self.table_catalog:
            return f"{self.table_catalog}.{self.name}"
        return self.name


@dataclass(frozen=True)
class RoleHierarchyEdge:
    parent_role: str
    child_role: str


@dataclass(frozen=True)
class FlaggedIssue:
    severity: Severity
    reason: str
    grantee_name: str
    grantee_type: GranteeType
    privilege: str
    granted_on: str
    object_name: str
    affected_users_count: int
    affected_users_note: str
    recommendation: str


@dataclass
class AuditMetadata:
    run_timestamp: str
    account: str
    extractor_version: str
    snowflake_edition: str | None = None
    focus_privileges: tuple[str, ...] = ()
    flag_role_patterns: tuple[str, ...] = ()
    flag_schema_patterns: tuple[str, ...] = ()


@dataclass
class AuditStats:
    role_count: int = 0
    user_count: int = 0
    grants_to_roles_count: int = 0
    grants_to_users_count: int = 0
    hierarchy_edge_count: int = 0
    flagged_issue_count: int = 0
    dml_grants_on_tables_count: int = 0


@dataclass
class AuditResult:
    metadata: AuditMetadata
    roles: list[Role] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    grants_to_roles: list[Grant] = field(default_factory=list)
    grants_to_users: list[Grant] = field(default_factory=list)
    role_hierarchy: list[RoleHierarchyEdge] = field(default_factory=list)
    flagged_issues: list[FlaggedIssue] = field(default_factory=list)
    stats: AuditStats = field(default_factory=AuditStats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": asdict(self.metadata),
            "roles": [asdict(role) for role in self.roles],
            "users": [
                {
                    "name": user.name,
                    "default_role": user.default_role,
                    "assigned_roles": list(user.assigned_roles),
                }
                for user in self.users
            ],
            "grants_to_roles": [asdict(grant) for grant in self.grants_to_roles],
            "grants_to_users": [asdict(grant) for grant in self.grants_to_users],
            "role_hierarchy": [asdict(edge) for edge in self.role_hierarchy],
            "flagged_issues": [asdict(issue) for issue in self.flagged_issues],
            "stats": asdict(self.stats),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditResult:
        meta_raw = data["metadata"]
        metadata = AuditMetadata(
            run_timestamp=meta_raw["run_timestamp"],
            account=meta_raw["account"],
            extractor_version=meta_raw["extractor_version"],
            snowflake_edition=meta_raw.get("snowflake_edition"),
            focus_privileges=tuple(meta_raw.get("focus_privileges", ())),
            flag_role_patterns=tuple(meta_raw.get("flag_role_patterns", ())),
            flag_schema_patterns=tuple(meta_raw.get("flag_schema_patterns", ())),
        )
        return cls(
            metadata=metadata,
            roles=[Role(**row) for row in data.get("roles", [])],
            users=[
                User(
                    name=row["name"],
                    default_role=row.get("default_role"),
                    assigned_roles=tuple(row.get("assigned_roles", [])),
                )
                for row in data.get("users", [])
            ],
            grants_to_roles=[Grant(**row) for row in data.get("grants_to_roles", [])],
            grants_to_users=[Grant(**row) for row in data.get("grants_to_users", [])],
            role_hierarchy=[
                RoleHierarchyEdge(**row) for row in data.get("role_hierarchy", [])
            ],
            flagged_issues=[
                FlaggedIssue(**row) for row in data.get("flagged_issues", [])
            ],
            stats=AuditStats(**data.get("stats", {})),
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
