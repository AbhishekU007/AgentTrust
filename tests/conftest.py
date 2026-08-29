"""Shared test authentication configuration; production never uses this file."""

import os

from fastapi.testclient import TestClient

os.environ.setdefault(
    "AGENTTRUST_API_TOKENS",
    '{"demo-token":"demo-user","test-token":"__legacy_test__"}',
)

import agenttrust.api as api_module


def _legacy_test_principal(principal):
    return principal is not None and principal.principal_id == "__legacy_test__"


api_module._legacy_test_principal = _legacy_test_principal

_original_init = TestClient.__init__


def _test_client_init(self, app, *args, **kwargs):
    kwargs.setdefault("headers", {"Authorization": "Bearer test-token"})
    return _original_init(self, app, *args, **kwargs)


TestClient.__init__ = _test_client_init