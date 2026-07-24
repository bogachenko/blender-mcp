"""OAuth protection for the standalone BlenderMCP HTTP server.

This module intentionally follows the same self-hosted OAuth behavior used by
the user's existing MCP servers: dynamic client registration accepts standard
client metadata without rejecting extra grant/response declarations, while the
server advertises and issues authorization-code tokens protected by PKCE.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Route

DEFAULT_SCOPE = "blender"
ACCESS_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60
AUTHORIZATION_CODE_TTL_SECONDS = 10 * 60
MAX_REQUEST_BODY_BYTES = 64 * 1024

ASGIApp = Callable[
    [
        dict[str, Any],
        Callable[[], Awaitable[dict[str, Any]]],
        Callable[[dict[str, Any]], Awaitable[None]],
    ],
    Awaitable[None],
]


@dataclass(slots=True)
class OAuthClient:
    client_id: str
    client_secret: str
    redirect_uris: list[str]
    token_endpoint_auth_method: str
    client_name: str
    client_uri: str
    created_at: int


@dataclass(slots=True)
class AuthorizationCode:
    code: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    resource: str
    code_challenge: str
    code_challenge_method: str
    expires_at: int


@dataclass(slots=True)
class AccessTokenRecord:
    token: str
    client_id: str
    scope: str
    resource: str
    expires_at: int


class OAuthManager:
    """Own OAuth configuration, persisted state, routes, and MCP protection."""

    def __init__(
        self,
        *,
        owner_token: str,
        static_bearer_token: str,
        public_base_url: str,
        state_file: Path,
    ) -> None:
        self.owner_token = owner_token.strip()
        self.static_bearer_token = static_bearer_token.strip()
        self.configured_public_base_url = public_base_url.rstrip("/")
        self.state_file = state_file.expanduser()
        self._lock = threading.RLock()
        self._clients: dict[str, OAuthClient] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._tokens: dict[str, AccessTokenRecord] = {}
        self._load_state()

    @classmethod
    def from_environment(cls) -> "OAuthManager":
        owner_token = _first_environment_value(
            "BLENDER_MCP_OAUTH_OWNER_TOKEN",
            "MCP_OAUTH_OWNER_TOKEN",
        )
        static_bearer_token = _first_environment_value(
            "BLENDER_MCP_BEARER_TOKEN",
            "MCP_BEARER_TOKEN",
        )
        public_base_url = _first_environment_value(
            "BLENDER_MCP_PUBLIC_BASE_URL",
            "MCP_PUBLIC_BASE_URL",
        )
        state_file_value = _first_environment_value(
            "BLENDER_MCP_OAUTH_STATE_FILE",
            "MCP_OAUTH_STATE_FILE",
        )
        state_file = Path(
            state_file_value or "~/.config/blender-mcp/oauth-state.json"
        )
        return cls(
            owner_token=owner_token,
            static_bearer_token=static_bearer_token,
            public_base_url=public_base_url,
            state_file=state_file,
        )

    @property
    def enabled(self) -> bool:
        return bool(self.owner_token or self.static_bearer_token)

    def routes(self) -> list[Route]:
        return [
            Route(
                "/.well-known/oauth-protected-resource",
                self.protected_resource_metadata,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-protected-resource/mcp",
                self.protected_resource_metadata,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-authorization-server",
                self.authorization_server_metadata,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-authorization-server/mcp",
                self.authorization_server_metadata,
                methods=["GET"],
            ),
            Route("/oauth/register", self.register_client, methods=["POST"]),
            Route("/oauth/authorize", self.authorize, methods=["GET", "POST"]),
            Route("/oauth/token", self.issue_token, methods=["POST"]),
        ]

    def protect(self, app: ASGIApp) -> ASGIApp:
        if not self.enabled:
            return app

        async def protected(scope: dict[str, Any], receive, send) -> None:
            if scope.get("type") != "http":
                await app(scope, receive, send)
                return

            request = Request(scope, receive=receive)
            authorization = request.headers.get("authorization", "").strip()
            token = ""
            if authorization.lower().startswith("bearer "):
                token = authorization[7:].strip()

            if not self.validate_bearer_token(
                token,
                self.canonical_resource_uri(request),
            ):
                metadata_url = (
                    self.public_base_url(request)
                    + "/.well-known/oauth-protected-resource"
                )
                response = PlainTextResponse(
                    "Unauthorized",
                    status_code=401,
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer resource_metadata="{metadata_url}"'
                        ),
                        "Cache-Control": "no-store",
                    },
                )
                await response(scope, receive, send)
                return

            await app(scope, receive, send)

        return protected

    async def protected_resource_metadata(self, request: Request) -> Response:
        base = self.public_base_url(request)
        return JSONResponse(
            {
                "resource": base + "/mcp",
                "authorization_servers": [base],
                "bearer_methods_supported": ["header"],
                "scopes_supported": [DEFAULT_SCOPE],
                "resource_name": "Blender MCP",
                "resource_documentation": base + "/healthz",
            },
            headers={"Cache-Control": "no-store"},
        )

    async def authorization_server_metadata(
        self,
        request: Request,
    ) -> Response:
        base = self.public_base_url(request)
        return JSONResponse(
            {
                "issuer": base,
                "authorization_endpoint": base + "/oauth/authorize",
                "token_endpoint": base + "/oauth/token",
                "registration_endpoint": base + "/oauth/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256", "plain"],
                "token_endpoint_auth_methods_supported": [
                    "none",
                    "client_secret_post",
                    "client_secret_basic",
                ],
                "scopes_supported": [DEFAULT_SCOPE],
            },
            headers={"Cache-Control": "no-store"},
        )

    async def register_client(self, request: Request) -> Response:
        body = await _read_limited_body(request)
        if body is None:
            return _oauth_error(
                413,
                "invalid_client_metadata",
                "request body is too large",
            )

        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _oauth_error(
                400,
                "invalid_client_metadata",
                "invalid JSON",
            )
        if not isinstance(value, dict):
            return _oauth_error(
                400,
                "invalid_client_metadata",
                "JSON object is required",
            )

        redirect_uris = _clean_string_list(value.get("redirect_uris"))
        if not redirect_uris:
            return _oauth_error(
                400,
                "invalid_redirect_uri",
                "redirect_uris is required",
            )
        if any(not _is_allowed_redirect_uri(uri) for uri in redirect_uris):
            return _oauth_error(
                400,
                "invalid_redirect_uri",
                "redirect_uri must use HTTPS or loopback HTTP",
            )

        # Match the existing MCP servers: grant_types, response_types, scope,
        # and unknown registration fields do not cause registration to fail.
        # Some clients request refresh_token during registration even when this
        # single-owner server issues authorization-code access tokens only.
        auth_method = str(
            value.get("token_endpoint_auth_method") or "none"
        ).strip()
        allowed_auth_methods = {
            "none",
            "client_secret_post",
            "client_secret_basic",
        }
        if auth_method not in allowed_auth_methods:
            return _oauth_error(
                400,
                "invalid_client_metadata",
                "unsupported token_endpoint_auth_method",
            )

        client = OAuthClient(
            client_id="client_" + secrets.token_urlsafe(24),
            client_secret=secrets.token_urlsafe(32),
            redirect_uris=redirect_uris,
            token_endpoint_auth_method=auth_method,
            client_name=str(value.get("client_name") or "").strip(),
            client_uri=str(value.get("client_uri") or "").strip(),
            created_at=int(time.time()),
        )
        with self._lock:
            self._clients[client.client_id] = client
            self._save_state_locked()

        response: dict[str, Any] = {
            "client_id": client.client_id,
            "client_id_issued_at": client.created_at,
            "redirect_uris": client.redirect_uris,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": (
                client.token_endpoint_auth_method
            ),
            "scope": DEFAULT_SCOPE,
        }
        if auth_method != "none":
            response["client_secret"] = client.client_secret
            response["client_secret_expires_at"] = 0

        return JSONResponse(
            response,
            status_code=201,
            headers={"Cache-Control": "no-store"},
        )

    async def authorize(self, request: Request) -> Response:
        error_message = ""

        if request.method == "GET":
            supplied_owner_token = request.query_params.get(
                "owner_token",
                "",
            ).strip()
            if supplied_owner_token:
                if (
                    not self.owner_token
                    or not hmac.compare_digest(
                        supplied_owner_token,
                        self.owner_token,
                    )
                ):
                    error_message = "Неверный owner token"
                else:
                    return self._complete_authorization(request)

        elif request.method == "POST":
            body = await _read_limited_body(request)
            if body is None:
                return _oauth_error(
                    413,
                    "invalid_request",
                    "request body is too large",
                )
            form = parse_qs(
                body.decode("utf-8", errors="replace"),
                keep_blank_values=True,
            )
            supplied_owner_token = _first_form_value(
                form,
                "owner_token",
            )
            if (
                not self.owner_token
                or not hmac.compare_digest(
                    supplied_owner_token,
                    self.owner_token,
                )
            ):
                error_message = "Неверный owner token"
            else:
                return self._complete_authorization(request)

        return self._authorization_form(request, error_message)

    def _complete_authorization(self, request: Request) -> Response:
        query = request.query_params
        response_type = query.get("response_type", "")
        client_id = query.get("client_id", "")
        redirect_uri = query.get("redirect_uri", "")
        scope = query.get("scope", "").strip() or DEFAULT_SCOPE
        state = query.get("state", "")
        resource = (
            query.get("resource", "").strip()
            or self.canonical_resource_uri(request)
        )
        code_challenge = query.get("code_challenge", "").strip()
        code_challenge_method = (
            query.get("code_challenge_method", "").strip() or "plain"
        )

        if response_type != "code":
            return _oauth_error(
                400,
                "unsupported_response_type",
                "response_type must be code",
            )
        if not client_id or not redirect_uri:
            return _oauth_error(
                400,
                "invalid_request",
                "client_id and redirect_uri are required",
            )
        if not code_challenge:
            return _oauth_error(
                400,
                "invalid_request",
                "PKCE code_challenge is required",
            )
        if code_challenge_method not in {"S256", "plain"}:
            return _oauth_error(
                400,
                "invalid_request",
                "unsupported code_challenge_method",
            )

        with self._lock:
            client = self._clients.get(client_id)
        if client is None:
            return _oauth_error(
                400,
                "invalid_client",
                "unknown client_id",
            )
        if redirect_uri not in client.redirect_uris:
            return _oauth_error(
                400,
                "invalid_redirect_uri",
                "redirect_uri is not registered",
            )

        code = "code_" + secrets.token_urlsafe(32)
        authorization_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            resource=resource,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=(
                int(time.time()) + AUTHORIZATION_CODE_TTL_SECONDS
            ),
        )
        with self._lock:
            self._prune_locked()
            self._codes[code] = authorization_code

        parsed_redirect = urlparse(redirect_uri)
        redirect_query = parse_qs(
            parsed_redirect.query,
            keep_blank_values=True,
        )
        redirect_query["code"] = [code]
        if state:
            redirect_query["state"] = [state]
        location = urlunparse(
            parsed_redirect._replace(
                query=urlencode(redirect_query, doseq=True)
            )
        )
        return RedirectResponse(
            location,
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )

    async def issue_token(self, request: Request) -> Response:
        body = await _read_limited_body(request)
        if body is None:
            return _oauth_error(
                413,
                "invalid_request",
                "request body is too large",
            )
        form = parse_qs(
            body.decode("utf-8", errors="replace"),
            keep_blank_values=True,
        )

        grant_type = _first_form_value(form, "grant_type")
        code_value = _first_form_value(form, "code")
        redirect_uri = _first_form_value(form, "redirect_uri")
        client_id = _first_form_value(form, "client_id")
        client_secret = _first_form_value(form, "client_secret")
        code_verifier = _first_form_value(form, "code_verifier")
        resource = _first_form_value(form, "resource").strip()

        basic_client_id, basic_client_secret = _parse_basic_client_auth(
            request.headers.get("authorization", "")
        )
        if basic_client_id:
            client_id = basic_client_id
            client_secret = basic_client_secret

        if grant_type != "authorization_code":
            return _oauth_error(
                400,
                "unsupported_grant_type",
                "grant_type must be authorization_code",
            )
        if (
            not code_value
            or not redirect_uri
            or not client_id
            or not code_verifier
        ):
            return _oauth_error(
                400,
                "invalid_request",
                (
                    "code, redirect_uri, client_id and code_verifier "
                    "are required"
                ),
            )

        with self._lock:
            self._prune_locked()
            client = self._clients.get(client_id)
            authorization_code = self._codes.pop(
                code_value,
                None,
            )

        if client is None:
            return _oauth_error(
                401,
                "invalid_client",
                "unknown client_id",
            )
        if client.token_endpoint_auth_method != "none":
            if not hmac.compare_digest(
                client_secret,
                client.client_secret,
            ):
                return _oauth_error(
                    401,
                    "invalid_client",
                    "invalid client_secret",
                )
        if authorization_code is None:
            return _oauth_error(
                400,
                "invalid_grant",
                "invalid or expired code",
            )
        if (
            authorization_code.client_id != client_id
            or authorization_code.redirect_uri != redirect_uri
        ):
            return _oauth_error(
                400,
                "invalid_grant",
                "client_id or redirect_uri mismatch",
            )
        if not _validate_pkce(
            code_verifier,
            authorization_code.code_challenge,
            authorization_code.code_challenge_method,
        ):
            return _oauth_error(
                400,
                "invalid_grant",
                "invalid code_verifier",
            )

        final_resource = (
            resource
            or authorization_code.resource
            or self.canonical_resource_uri(request)
        )
        access_token = AccessTokenRecord(
            token="mcp_" + secrets.token_urlsafe(48),
            client_id=client_id,
            scope=authorization_code.scope,
            resource=final_resource,
            expires_at=int(time.time()) + ACCESS_TOKEN_TTL_SECONDS,
        )
        with self._lock:
            self._tokens[access_token.token] = access_token
            self._save_state_locked()

        return JSONResponse(
            {
                "access_token": access_token.token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECONDS,
                "scope": access_token.scope,
            },
            headers={"Cache-Control": "no-store"},
        )

    def validate_bearer_token(
        self,
        token: str,
        resource: str,
    ) -> bool:
        token = token.strip()
        if not token:
            return False

        if (
            self.static_bearer_token
            and hmac.compare_digest(
                token,
                self.static_bearer_token,
            )
        ):
            return True

        with self._lock:
            changed = self._prune_locked()
            record = self._tokens.get(token)
            if changed:
                self._save_state_locked()

        if record is None:
            return False
        if not record.resource or not resource:
            return True
        return _normalize_url(record.resource) == _normalize_url(resource)

    def public_base_url(self, request: Request) -> str:
        if self.configured_public_base_url:
            return self.configured_public_base_url

        scheme = (
            request.headers.get("x-forwarded-proto", "").strip()
            or request.url.scheme
            or "http"
        )
        host = (
            request.headers.get("x-forwarded-host", "").strip()
            or request.headers.get("host", "").strip()
        )
        return f"{scheme}://{host}".rstrip("/")

    def canonical_resource_uri(self, request: Request) -> str:
        return self.public_base_url(request) + "/mcp"

    def _authorization_form(
        self,
        request: Request,
        message: str,
    ) -> HTMLResponse:
        escaped_query = html.escape(request.url.query, quote=True)
        escaped_message = ""
        if message:
            escaped_message = (
                f'<p style="color:#b00020">{html.escape(message)}</p>'
            )

        page = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize Blender MCP</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 520px; margin: 48px auto; line-height: 1.45; padding: 0 16px; }}
    input {{ box-sizing: border-box; width: 100%; padding: 12px; font-size: 16px; margin: 8px 0 16px; }}
    button {{ padding: 10px 16px; font-size: 16px; cursor: pointer; }}
    .box {{ border: 1px solid #ddd; border-radius: 12px; padding: 20px; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>Authorize Blender MCP</h1>
    <p>Введите owner token локального сервера Blender MCP.</p>
    {escaped_message}
    <form method="post" action="/oauth/authorize?{escaped_query}">
      <label for="owner_token">Owner token</label>
      <input id="owner_token" name="owner_token" type="password" autocomplete="current-password" autofocus>
      <button type="submit">Authorize</button>
    </form>
  </div>
</body>
</html>"""
        return HTMLResponse(
            page,
            headers={"Cache-Control": "no-store"},
        )

    def _load_state(self) -> None:
        try:
            raw = self.state_file.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            return

        try:
            data = json.loads(raw)
            raw_clients = data.get("clients", [])
            raw_tokens = data.get("tokens", [])

            if isinstance(raw_clients, dict):
                clients = list(raw_clients.values())
            elif isinstance(raw_clients, list):
                clients = raw_clients
            else:
                clients = []

            if isinstance(raw_tokens, dict):
                tokens = list(raw_tokens.values())
            elif isinstance(raw_tokens, list):
                tokens = raw_tokens
            else:
                tokens = []

            with self._lock:
                for item in clients:
                    if not isinstance(item, dict):
                        continue
                    client = OAuthClient(**item)
                    self._clients[client.client_id] = client
                for item in tokens:
                    if not isinstance(item, dict):
                        continue
                    token = AccessTokenRecord(**item)
                    self._tokens[token.token] = token
                self._prune_locked()
        except (TypeError, ValueError, json.JSONDecodeError):
            self._clients.clear()
            self._tokens.clear()

    def _save_state_locked(self) -> None:
        self._prune_locked()
        parent = self.state_file.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

        payload = {
            "version": 1,
            "clients": [
                asdict(client)
                for client in self._clients.values()
            ],
            "tokens": [
                asdict(token)
                for token in self._tokens.values()
            ],
        }

        fd, temporary_path = tempfile.mkstemp(
            prefix=".oauth-state-",
            dir=parent,
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as stream:
                json.dump(
                    payload,
                    stream,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self.state_file)
            os.chmod(self.state_file, 0o600)
        finally:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass

    def _prune_locked(self) -> bool:
        now = int(time.time())
        expired_codes = [
            key
            for key, value in self._codes.items()
            if value.expires_at <= now
        ]
        expired_tokens = [
            key
            for key, value in self._tokens.items()
            if value.expires_at <= now
        ]

        for key in expired_codes:
            self._codes.pop(key, None)
        for key in expired_tokens:
            self._tokens.pop(key, None)

        return bool(expired_codes or expired_tokens)


def _first_environment_value(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def _clean_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    ]


def _is_allowed_redirect_uri(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False

    if parsed.scheme.lower() == "https" and parsed.netloc:
        return True
    if parsed.scheme.lower() != "http":
        return False
    return (parsed.hostname or "").lower() in {
        "localhost",
        "127.0.0.1",
        "::1",
    }


def _normalize_url(value: str) -> str:
    return value.strip().rstrip("/").lower()


def _validate_pkce(
    verifier: str,
    expected_challenge: str,
    method: str,
) -> bool:
    if not verifier or not expected_challenge:
        return False

    if method == "plain":
        return hmac.compare_digest(verifier, expected_challenge)
    if method == "S256":
        calculated = (
            base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("utf-8")).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        return hmac.compare_digest(
            calculated,
            expected_challenge,
        )
    return False


def _parse_basic_client_auth(value: str) -> tuple[str, str]:
    if not value.lower().startswith("basic "):
        return "", ""

    try:
        decoded = base64.b64decode(
            value[6:].strip(),
            validate=True,
        ).decode("utf-8")
        client_id, client_secret = decoded.split(":", 1)
        return client_id, client_secret
    except (ValueError, UnicodeDecodeError):
        return "", ""


async def _read_limited_body(request: Request) -> bytes | None:
    content_length = request.headers.get(
        "content-length",
        "",
    ).strip()
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                return None
        except ValueError:
            return None

    body = await request.body()
    if len(body) > MAX_REQUEST_BODY_BYTES:
        return None
    return body


def _first_form_value(
    form: dict[str, list[str]],
    name: str,
) -> str:
    values = form.get(name, [])
    return values[0] if values else ""


def _oauth_error(
    status_code: int,
    code: str,
    description: str,
) -> JSONResponse:
    return JSONResponse(
        {
            "error": code,
            "error_description": description,
        },
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )
