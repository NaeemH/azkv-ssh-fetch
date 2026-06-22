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
import subprocess
import time
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
# NOTE: ``www-authenticate`` is deliberately NOT in this list — the Azure Key
# Vault SDK's challenge-auth policy parses this header to discover the tenant
# and resource to request a token for, and a hard-redacted value crashes the
# policy with ``IndexError``. Its content is anonymized in-place via
# ``_scrub_text`` (the tenant GUID gets the all-zero replacement) without
# destroying the ``Bearer authorization="...", resource="..."`` structure.
_SENSITIVE_HEADERS: tuple[str, ...] = (
    "authorization",
    "cookie",
    "set-cookie",
    "x-ms-keyvault-rb-auth-info",
    "x-ms-keyvault-network-info",
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
            # Preserve the original container shape: HTTP headers in cassette
            # YAML are typically ``[value]`` lists, and downstream code in the
            # vcrpy stub builds an ``HTTPMessage`` from this dict. Returning a
            # bare ``str`` instead of ``[str]`` for a list-typed header causes
            # the parser to treat each character as a separate header value.
            redacted[raw_key] = ["REDACTED"] if isinstance(raw_val, list) else "REDACTED"
            continue
        if isinstance(raw_val, list):
            redacted[raw_key] = [_scrub_text(str(v)) for v in raw_val]
        else:
            redacted[raw_key] = _scrub_text(str(raw_val))
    return redacted


def _scrub_body_string(body: str) -> str:
    """Try to JSON-load body and redact sensitive keys; fall back to text scrub.

    Subtle: Key Vault's paged endpoints wrap the page in ``{"value": [...]}``
    where ``value`` is the *list* of items, not a credential. The
    ``GET /secrets/{name}`` endpoint, in contrast, returns
    ``{"value": "<secret-material>", ...}``. Both share the key, so the
    scrubber only redacts ``value`` when it is a scalar — wholesale-replacing
    the paged list with the string ``"REDACTED"`` would corrupt every
    list-secrets cassette and surface as ``AttributeError: 'str' object has
    no attribute 'attributes'`` during replay.
    """
    scrubbed = _scrub_text(body)
    try:
        parsed = json.loads(scrubbed)
    except (ValueError, TypeError):
        return scrubbed

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for k, v in node.items():
                if (
                    isinstance(k, str)
                    and k.lower() in _SENSITIVE_BODY_KEYS
                    and not isinstance(v, (dict, list))
                ):
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
        was_bytes = isinstance(body, bytes)
        if was_bytes:
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError:
                return request
        scrubbed = _scrub_body_string(body)
        # Preserve original byte/str type. vcrpy's _before_record_response is
        # invoked on cassette *load* as well as record, so returning a str
        # where bytes were stored would break replay (VCRHTTPResponse expects
        # bytes for `body.string`).
        request.body = scrubbed.encode("utf-8") if was_bytes else scrubbed
    return request


def _scrub_response(response: dict[str, Any]) -> dict[str, Any]:
    """vcrpy before_record_response hook.

    Also runs at cassette load time (via ``Cassette.append`` → ``_load``),
    so it must preserve the bytes/str type of ``body.string`` — otherwise
    the second-pass scrub on load corrupts the payload and replay raises
    ``TypeError: a bytes-like object is required, not 'str'``.
    """
    if "headers" in response:
        response["headers"] = _scrub_headers(response["headers"])
    body = response.get("body")
    if isinstance(body, dict) and "string" in body:
        s = body["string"]
        was_bytes = isinstance(s, bytes)
        if was_bytes:
            try:
                s = s.decode("utf-8")
            except UnicodeDecodeError:
                return response
        scrubbed = _scrub_body_string(s)
        body["string"] = scrubbed.encode("utf-8") if was_bytes else scrubbed
    return response


@pytest.fixture(scope="module")
def vcr_config() -> dict[str, Any]:
    """pytest-recording reads this fixture for module-scoped VCR config.

    ``record_mode`` is ``"none"`` by default so CI never silently re-records
    against the network. The operator opts in to recording by setting
    ``AZKV_RECORDING=1``, which flips the mode to ``"once"`` (write the
    cassette on first run, replay thereafter) and lets ``--record-mode=...``
    on the CLI take precedence as usual.
    """
    record_mode = "once" if os.environ.get("AZKV_RECORDING") == "1" else "none"
    return {
        "filter_headers": list(_SENSITIVE_HEADERS),
        "before_record_request": _scrub_request,
        "before_record_response": _scrub_response,
        "record_mode": record_mode,
        "match_on": ["method", "scheme", "host", "port", "path", "query"],
        "decode_compressed_response": True,
    }


def cassette_exists(test_module: str, test_name: str) -> bool:
    """Return True if the cassette file pytest-recording would replay exists."""
    return (CASSETTES_DIR / test_module / f"{test_name}.yaml").exists()


def skip_if_no_cassette(test_module: str, test_name: str) -> Any:
    """Decorator: skip a VCR-marked test if its cassette hasn't been recorded yet.

    The skip is bypassed when ``AZKV_RECORDING=1`` is set so the operator can
    actually run ``pytest --record-mode=once`` to generate the cassette on the
    first pass. Without the bypass this decorator would skip the test before
    pytest-recording got a chance to write anything, making recording impossible.
    """
    recording = os.environ.get("AZKV_RECORDING") == "1"
    return pytest.mark.skipif(
        not cassette_exists(test_module, test_name) and not recording,
        reason=(
            f"cassette tests/cassettes/{test_module}/{test_name}.yaml not recorded. "
            "Re-record with `AZKV_RECORDING=1 pytest --record-mode=once "
            "tests/test_keyvault_vcr.py` after setting AZKV_TEST_RECORD_VAULT + "
            "AZURE_TENANT_ID + AZURE_SUBSCRIPTION_ID and authenticating with "
            "`az login`. See README's 'Recording cassettes' section."
        ),
    )


class _PinnedTenantCliCredential:
    """Test-only credential that pins token acquisition to a single tenant.

    Why this exists: some Azure Key Vault instances (notably those in
    MSA-rooted Azure Free subscriptions) emit a ``WWW-Authenticate`` challenge
    that names a tenant the principal does *not* belong to (an artifact of
    KV's auth-discovery path). The ``azure-identity`` challenge-auth policy
    treats that tenant as authoritative and asks the credential to fetch a
    token for it, which then fails with ``AADSTS50020``.

    The vault itself, however, accepts tokens issued for the tenant it was
    *created* in, and the role assignments live there too. So this credential
    ignores the ``tenant_id`` kwarg the policy passes and always returns a
    token minted via ``az account get-access-token --tenant <pinned>``.

    This is recording-only behavior — production code keeps
    ``DefaultAzureCredential`` and follows challenges normally.
    """

    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id
        self._cache: tuple[str, int] | None = None  # (token, epoch_seconds)

    def _fetch(self, resource: str) -> tuple[str, int]:
        proc = subprocess.run(
            [
                "az",
                "account",
                "get-access-token",
                "--resource",
                resource,
                "--tenant",
                self._tenant_id,
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout)
        # az emits expiresOn as a local-time string like "2026-06-22 21:34:19.000000".
        # Convert to epoch seconds; treat as local time (matches az convention).
        expires_struct = time.strptime(data["expiresOn"].split(".")[0], "%Y-%m-%d %H:%M:%S")
        expires_on = int(time.mktime(expires_struct))
        return data["accessToken"], expires_on

    def _token_obj(self, token: str, expires_on: int) -> Any:
        # Lazy import to avoid hard dep at module import time.
        from azure.core.credentials import AccessToken

        return AccessToken(token, expires_on)

    def get_token(self, *scopes: str, **_kwargs: Any) -> Any:
        if self._cache and self._cache[1] - time.time() > 60:
            return self._token_obj(*self._cache)
        scope = scopes[0] if scopes else "https://vault.azure.net/.default"
        resource = scope.removesuffix("/.default")
        self._cache = self._fetch(resource)
        return self._token_obj(*self._cache)

    def get_token_info(self, *scopes: str, **kwargs: Any) -> Any:
        # azure-identity's newer TokenCredential protocol asks for TokenRequestOptions/AccessTokenInfo.
        # We can satisfy it by delegating to get_token and wrapping the result.
        from azure.core.credentials import AccessTokenInfo

        tok = self.get_token(*scopes, **kwargs)
        return AccessTokenInfo(tok.token, tok.expires_on)


class _StaticReplayCredential:
    """Test-only credential that returns a placeholder token, no network calls.

    Used during cassette *replay* so the SDK's challenge-auth flow has
    something to put in the ``Authorization`` header for the retry request
    without ever touching ``login.microsoftonline.com``. The cassette
    rewrites ``Authorization`` to ``REDACTED`` and the VCR matcher does not
    compare on headers, so any value here works.
    """

    _TOKEN = "replay-token-not-a-real-bearer"

    def _token(self) -> Any:
        from azure.core.credentials import AccessToken

        # Far-future expiry so the SDK never tries to refresh mid-test.
        return AccessToken(self._TOKEN, 9999999999)

    def get_token(self, *_scopes: str, **_kwargs: Any) -> Any:
        return self._token()

    def get_token_info(self, *_scopes: str, **_kwargs: Any) -> Any:
        from azure.core.credentials import AccessTokenInfo

        return AccessTokenInfo(self._TOKEN, 9999999999)


@pytest.fixture(autouse=True)
def _inject_test_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap `DefaultAzureCredential` for a test credential during VCR tests.

    * **Recording** (``AZKV_RECORDING=1`` + ``AZKV_AUTH_TENANT_ID``): pin to
      a specific tenant via ``az`` so the broken-WWW-Authenticate path can be
      bypassed (see ``_PinnedTenantCliCredential``).
    * **Replay** (default): return a static placeholder token so the SDK's
      bearer-token retry has *something* to attach without hitting the real
      AAD token endpoint (no login.microsoftonline.com traffic = no extra
      cassette interactions needed = small, deterministic cassettes).
    """
    from azkv_ssh_fetch import keyvault

    if os.environ.get("AZKV_RECORDING") == "1":
        pinned = os.environ.get("AZKV_AUTH_TENANT_ID")
        if not pinned:
            return  # Operator opted out of tenant pinning; let DAC do its thing.
        replacement: Any = _PinnedTenantCliCredential(pinned)
    else:
        replacement = _StaticReplayCredential()

    monkeypatch.setattr(keyvault, "DefaultAzureCredential", lambda *_a, **_kw: replacement)
