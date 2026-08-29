"""Minimal bearer-credential authentication for the local prototype."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from typing import Mapping

from dotenv import load_dotenv
from fastapi import Header, HTTPException, status

load_dotenv()


@dataclass(frozen=True)
class Principal:
    principal_id: str
    account_id: str


def configured_principals(
    credentials: Mapping[str, str] | None = None,
) -> dict[str, Principal]:
    if credentials is None:
        raw = os.getenv("AGENTTRUST_API_TOKENS", "")
        if raw:
            try:
                credentials = json.loads(raw)
            except (TypeError, ValueError) as exc:
                raise RuntimeError("AGENTTRUST_API_TOKENS is invalid") from exc
        else:
            token = os.getenv("AGENTTRUST_API_TOKEN")
            if token:
                principal = os.getenv("AGENTTRUST_PRINCIPAL_ID", "local-user")
                credentials = {token: principal}
            else:
                credentials = {}
    return {
        token: Principal(principal_id=str(principal), account_id=str(principal))
        for token, principal in credentials.items()
        if isinstance(token, str) and isinstance(principal, str) and token and principal
    }


def authenticate(
    principals: Mapping[str, Principal],
    authorization: str | None = Header(default=None),
) -> Principal | None:
    if not principals:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "authentication_required", "message": "Bearer authentication is required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "authentication_required", "message": "Bearer authentication is required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    supplied = authorization[7:].strip()
    for token, principal in principals.items():
        if secrets.compare_digest(supplied, token):
            return principal
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "invalid_credentials", "message": "Bearer credentials are invalid"},
        headers={"WWW-Authenticate": "Bearer"},
    )
