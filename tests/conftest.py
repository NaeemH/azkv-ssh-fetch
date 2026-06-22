"""Shared fixtures + VCR scrubbers for the test suite.

VCR / pytest-recording configuration here is treated as **the** safety boundary
between live Azure data and the public git history. The scrubbers redact:

* ``Authorization`` and every ``x-ms-*-token`` / ``x-ms-*-auth*`` header on
  both requests and responses.
* Common cookie / Set-Cookie headers (just in case).
* OAuth token-endpoint response bodies (``access_token``, ``refresh_token``,
  ``id_token``).
* Key Vault secret-fetch response bodies (the ``value`` field, which IS the
  SSH private key, plus ``kid`` URLs that embed vault + secret + version IDs).
* Any UUID/GUID in URLs, headers, or bodies (subscription / tenant / object IDs)
  is replaced with the all-zero GUID.
* The vault hostname is rewritten to ``test-vault.vault.azure.net``.

Cassettes are NOT auto-recorded in CI; ``record_mode`` is ``"none"`` so any test
whose cassette is missing fails fast (or is skipped, see ``vcr_cassette_or_skip``).
To re-record locally::

    pytest --record-mode=once tests/test_keyvault_vcr.py

After recording, eyeball ``tests/cassettes/*.yaml`` and confirm no real GUIDs,
no real vault names, no secret material survives. The scrubbers below are
defense-in-depth, not a substitute for review.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

CASSETTES_DIR = Path(__file__).parent / "cassettes"
SCRUBBED_GUID = "00000000-0000-0000-0000-000000000000"
SCRUBBED_VAULT = "test-vault"

_GUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

# Live vault name (and tenant/sub IDs) that the re-record run uses; the scrubber
# rewrites them to fixed fixture values. Set these env vars before recording.
_LIVE_VAULT = os.environ.get("AZKV_TEST_RECORD_VAULT", "")
_LIVE_TENANT = os.environ.get("AZURE_TENANT_ID", "")
_LIVE_SUB = os.environ.get("AZURE_SUBSCRIPTION_ID", "")

# Headers that may carry credentials or tracing material on either side of the wire.
_SENSITIVE_HEADERS: tuple[str, ...] = (
    "authorization",
    "cookie",
    "set-cookie",
    "x-ms-keyvault-rb-auth-info",
    "x-ms-keyvault-network-info",
    "www-authenticate",
    "x-ms-keyvault-request-id",
    "x-ms-request-id",
    "x-ms-client-request-id",
    "x-ms-correlation-request-id",
    "x-ms-routing-request-id",
    "client-request-id",
)

# Response-body JSON keys whose values are credentials or secret material.
_SENSITIVE_BODY_KEYS: tuple[str, ...] = (
    "access_token",
    "refresh_token",
    "id_token",
    "value",  # /secrets/{name} returns the secret material here
)


def _scrub_text(text: str) -> str:
    """Run name/vault/GUID/tenant scrubs over arbitrary text."""
    if not text:
        return text
    out = text
    if _LIVE_VAULT:
        out = out.replace(_LIVE_VAULT, SCRUBBED_VAULT)
    if _LIVE_TENANT:
        out = out.replace(_LIVE_TENANT, SCRUBBED_GUID)
    if _LIVE_SUB:
        out = out.replace(_LIVE_SUB, SCRUBBED_GUID)
    out = _GUID_RE.sub(SCRUBBED_GUID, out)
    return out


def _scrub_headers(headers: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for raw_key, raw_val in headers.items():
        key_lower = raw_key.lower() if isinstance(raw_key, str) else raw_key
        if key_lower in _SENSITIVE_HEADERS:
            redacted[raw_key] = "REDACTED"
            continue
        if isinstance(raw_val, list):
            redacted[raw_key] = [_scrub_text(str(v)) for v in raw_val]
        else:
            redacted[raw_key] = _scrub_text(str(raw_val))
    return redacted


def _scrub_body_string(body: str) -> str:
    """Try to JSON-load body and redact sensitive keys; fall back to text scrub."""
    scrubbed = _scrub_text(body)
    try:
        parsed = json.loads(scrubbed)
    except (ValueError, TypeError):
        return scrubbed

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for k, v in node.items():
                if isinstance(k, str) and k.lower() in _SENSITIVE_BODY_KEYS:
                    out[k] = "REDACTED"
                else:
                    out[k] = walk(v)
            return out
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node

    return json.dumps(walk(parsed))


def _scrub_request(request: Any) -> Any:
    """vcrpy before_record_request hook."""
    if hasattr(request, "uri") and request.uri:
        request.uri = _scrub_text(request.uri)
    if hasattr(request, "headers"):
        request.headers = _scrub_headers(dict(request.headers))
    if getattr(request, "body", None):
        body = request.body
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError:
                return request
        request.body = _scrub_body_string(body)
    return request


def _scrub_response(response: dict[str, Any]) -> dict[str, Any]:
    """vcrpy before_record_response hook."""
    if "headers" in response:
        response["headers"] = _scrub_headers(response["headers"])
    body = response.get("body")
    if isinstance(body, dict) and "string" in body:
        s = body["string"]
        if isinstance(s, bytes):
            try:
                s = s.decode("utf-8")
            except UnicodeDecodeError:
                return response
        body["string"] = _scrub_body_string(s)
    return response


@pytest.fixture(scope="module")
def vcr_config() -> dict[str, Any]:
    """pytest-recording reads this fixture for module-scoped VCR config."""
    return {
        "filter_headers": list(_SENSITIVE_HEADERS),
        "before_record_request": _scrub_request,
        "before_record_response": _scrub_response,
        "record_mode": "none",  # CI must never silently re-record
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
        "decode_compressed_response": True,
    }


def cassette_exists(test_module: str, test_name: str) -> bool:
    """Return True if the cassette file pytest-recording would replay exists."""
    return (CASSETTES_DIR / test_module / f"{test_name}.yaml").exists()


def skip_if_no_cassette(test_module: str, test_name: str) -> Any:
    """Decorator: skip a VCR-marked test if its cassette hasn't been recorded yet."""
    return pytest.mark.skipif(
        not cassette_exists(test_module, test_name),
        reason=(
            f"cassette tests/cassettes/{test_module}/{test_name}.yaml not recorded. "
            "Re-record with `pytest --record-mode=once tests/test_keyvault_vcr.py` "
            "after setting AZKV_TEST_RECORD_VAULT + AZURE_TENANT_ID + AZURE_SUBSCRIPTION_ID "
            "and authenticating with `az login`. See README's 'Recording cassettes' section."
        ),
    )
