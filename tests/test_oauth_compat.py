from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from starlette.applications import Starlette
from starlette.testclient import TestClient

from blender_mcp.oauth import OAuthManager


PUBLIC_BASE_URL = "https://blender-mcp.example.com"
REDIRECT_URI = "https://chatgpt.com/connector/oauth/callback"


class OAuthCompatibilityTests(unittest.TestCase):
    def make_client(self) -> TestClient:
        state_file = Path(tempfile.mkdtemp()) / "oauth-state.json"
        oauth = OAuthManager(
            owner_token="owner-token",
            static_bearer_token="",
            public_base_url=PUBLIC_BASE_URL,
            state_file=state_file,
        )
        return TestClient(Starlette(routes=oauth.routes()))

    def register_chatgpt_client(self, client: TestClient) -> dict:
        response = client.post(
            "/oauth/register",
            json={
                "redirect_uris": [REDIRECT_URI],
                "client_name": "ChatGPT",
                "client_uri": "https://chatgpt.com",
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "blender offline_access",
                "application_type": "web",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        value = response.json()
        self.assertEqual(value["grant_types"], ["authorization_code"])
        self.assertEqual(value["response_types"], ["code"])
        self.assertEqual(value["token_endpoint_auth_method"], "none")
        return value

    def test_dynamic_registration_ignores_extra_grant_metadata(self) -> None:
        client = self.make_client()
        self.register_chatgpt_client(client)

    def test_metadata_matches_existing_mcp_servers(self) -> None:
        client = self.make_client()
        response = client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(response.status_code, 200)
        metadata = response.json()
        self.assertEqual(
            metadata["code_challenge_methods_supported"],
            ["S256", "plain"],
        )
        self.assertEqual(
            metadata["grant_types_supported"],
            ["authorization_code"],
        )

    def test_s256_and_plain_pkce_flows(self) -> None:
        for method in ("S256", "plain"):
            with self.subTest(method=method):
                client = self.make_client()
                registration = self.register_chatgpt_client(client)
                verifier = "test-verifier-with-enough-entropy-1234567890"
                if method == "S256":
                    challenge = base64.urlsafe_b64encode(
                        hashlib.sha256(verifier.encode("utf-8")).digest()
                    ).rstrip(b"=").decode("ascii")
                else:
                    challenge = verifier

                authorize_url = "/oauth/authorize?" + urlencode(
                    {
                        "response_type": "code",
                        "client_id": registration["client_id"],
                        "redirect_uri": REDIRECT_URI,
                        "scope": "blender",
                        "state": "state-value",
                        "resource": PUBLIC_BASE_URL + "/mcp",
                        "code_challenge": challenge,
                        "code_challenge_method": method,
                    }
                )
                authorization = client.post(
                    authorize_url,
                    data={"owner_token": "owner-token"},
                    follow_redirects=False,
                )
                self.assertEqual(
                    authorization.status_code,
                    302,
                    authorization.text,
                )
                query = parse_qs(
                    urlparse(authorization.headers["location"]).query
                )
                code = query["code"][0]

                token = client.post(
                    "/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": REDIRECT_URI,
                        "client_id": registration["client_id"],
                        "code_verifier": verifier,
                        "resource": PUBLIC_BASE_URL + "/mcp",
                    },
                )
                self.assertEqual(token.status_code, 200, token.text)
                self.assertEqual(token.json()["token_type"], "Bearer")


if __name__ == "__main__":
    unittest.main()
