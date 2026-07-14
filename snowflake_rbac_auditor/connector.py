"""Snowflake connection management with key-pair authentication."""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import snowflake.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


@dataclass(frozen=True)
class SnowflakeConfig:
    account: str
    user: str
    private_key_path: str | None = None
    private_key_passphrase: str | None = None
    password: str | None = None
    token: str | None = None
    legacy_pat: str | None = None
    warehouse: str | None = None
    role: str | None = None
    database: str | None = None

    @classmethod
    def from_env(cls) -> SnowflakeConfig:
        return cls(
            account=os.environ.get("SNOWFLAKE_ACCOUNT", ""),
            user=os.environ.get("SNOWFLAKE_USER", ""),
            private_key_path=os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH"),
            private_key_passphrase=os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE"),
            password=os.environ.get("SNOWFLAKE_PASSWORD"),
            token=os.environ.get("SNOWFLAKE_PAT"),
            legacy_pat=os.environ.get("SNOWFLAKE_LEGACY_PAT"),
            warehouse=os.environ.get("SNOWFLAKE_WAREHOUSE"),
            role=os.environ.get("SNOWFLAKE_ROLE"),
            database=os.environ.get("SNOWFLAKE_DATABASE"),
        )

    def validate(self) -> None:
        if not self.account:
            raise ValueError("SNOWFLAKE_ACCOUNT is required")
        if not self.user:
            raise ValueError("SNOWFLAKE_USER is required")
        if not any(
            (self.private_key_path, self.token, self.legacy_pat, self.password)
        ):
            raise ValueError(
                "One of SNOWFLAKE_PRIVATE_KEY_PATH (recommended), SNOWFLAKE_PAT, "
                "SNOWFLAKE_LEGACY_PAT, or SNOWFLAKE_PASSWORD (local testing only) is required"
            )
        if self.password and not any((self.private_key_path, self.token, self.legacy_pat)):
            warnings.warn(
                "Password authentication is enabled. Use key-pair auth or a PAT in production.",
                stacklevel=2,
            )


def _load_private_key_bytes(path: str, passphrase: str | None) -> bytes:
    key_path = Path(path).expanduser()
    if not key_path.is_file():
        raise FileNotFoundError(f"Private key not found: {key_path}")

    passphrase_bytes = passphrase.encode() if passphrase else None
    with key_path.open("rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=passphrase_bytes,
            backend=default_backend(),
        )

    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def connect(config: SnowflakeConfig) -> snowflake.connector.SnowflakeConnection:
    config.validate()

    connect_kwargs: dict[str, Any] = {
        "account": config.account,
        "user": config.user,
    }

    if config.private_key_path:
        connect_kwargs["private_key"] = _load_private_key_bytes(
            config.private_key_path,
            config.private_key_passphrase,
        )
    elif config.token:
        connect_kwargs["authenticator"] = "PROGRAMMATIC_ACCESS_TOKEN"
        connect_kwargs["token"] = config.token
    elif config.legacy_pat:
        connect_kwargs["password"] = config.legacy_pat
    else:
        connect_kwargs["password"] = config.password

    if config.warehouse:
        connect_kwargs["warehouse"] = config.warehouse
    if config.role:
        connect_kwargs["role"] = config.role
    if config.database:
        connect_kwargs["database"] = config.database

    return snowflake.connector.connect(**connect_kwargs)
