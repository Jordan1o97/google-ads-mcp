"""Mocked end-to-end tests for FastMCP's upstream OAuth browser flow."""

import asyncio
import base64
import hashlib
import os
import pathlib
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

import httpx2
from cryptography.fernet import Fernet
from fastmcp.server.auth.oauth_proxy.upstream import AsyncOAuth2Client
from fastmcp.server.auth.providers.google import GoogleProvider
from mcp.server.auth.provider import AuthorizationCode, AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
from starlette.requests import Request

from ads_mcp.auth_storage import create_client_storage


class TestOAuthBrowserFlow(unittest.TestCase):
    """Exercise FastMCP OAuth transaction behavior without external accounts."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.env = patch.dict(
            os.environ,
            {
                "GOOGLE_ADS_MCP_STORAGE_TYPE": "filetree",
                "GOOGLE_ADS_MCP_STORAGE_PATH": self.temp_dir.name,
                "GOOGLE_ADS_MCP_STORAGE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                "GOOGLE_ADS_MCP_STORAGE_DISABLE_ENCRYPTION": "false",
            },
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client_storage = create_client_storage()
        self.provider = GoogleProvider(
            client_id="mock-client-id",
            client_secret="mock-client-secret",
            base_url="https://mcp.example.test",
            required_scopes=[
                "openid",
                "https://www.googleapis.com/auth/adwords",
            ],
            client_storage=self.client_storage,
            jwt_signing_key="mock-jwt-signing-key-for-tests",
            require_authorization_consent=False,
        )
        self.provider.get_routes()
        self.client = OAuthClientInformationFull(
            client_id="local-mcp-client",
            redirect_uris=["http://localhost:43210/callback"],
            token_endpoint_auth_method="none",
        )

    def test_authorize_callback_token_exchange_refresh_and_encrypted_storage(
        self,
    ):
        """State and PKCE survive mocked callback, exchange, refresh and storage."""

        async def run_flow():
            verifier = "client-pkce-verifier-value-with-43-characters-minimum"
            challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(verifier.encode()).digest()
                )
                .decode()
                .rstrip("=")
            )
            params = AuthorizationParams(
                state="client-state-123",
                scopes=["openid", "https://www.googleapis.com/auth/adwords"],
                code_challenge=challenge,
                redirect_uri="http://localhost:43210/callback",
                redirect_uri_provided_explicitly=True,
            )
            authorize_url = await self.provider.authorize(self.client, params)
            parsed = urlparse(authorize_url)
            upstream_params = parse_qs(parsed.query)
            self.assertEqual(parsed.hostname, "accounts.google.com")
            self.assertNotEqual(upstream_params["state"][0], "client-state-123")
            txn_id = upstream_params["state"][0]
            self.assertEqual(upstream_params["code_challenge_method"], ["S256"])
            transaction = await self.provider._transaction_store.get(key=txn_id)
            self.assertEqual(transaction.client_state, "client-state-123")
            self.assertEqual(transaction.code_challenge, challenge)
            self.assertEqual(
                upstream_params["code_challenge"][0],
                base64.urlsafe_b64encode(
                    hashlib.sha256(
                        transaction.proxy_code_verifier.encode()
                    ).digest()
                )
                .decode()
                .rstrip("="),
            )

            requests = []
            responses = [
                {
                    "access_token": "upstream-access-secret",
                    "refresh_token": "upstream-refresh-secret",
                    "expires_in": 3600,
                    "scope": "openid https://www.googleapis.com/auth/adwords",
                },
                {
                    "access_token": "rotated-upstream-access",
                    "refresh_token": "rotated-upstream-refresh",
                    "expires_in": 3600,
                },
            ]

            def mock_upstream_client():
                oauth_client = AsyncOAuth2Client(
                    client_id="mock-client-id",
                    client_secret="mock-client-secret",
                )

                async def handle(request):
                    body = parse_qs(request.content.decode())
                    requests.append((request.url, body, request.headers))
                    return httpx2.Response(200, json=responses.pop(0))

                oauth_client._client = httpx2.AsyncClient(
                    transport=httpx2.MockTransport(handle)
                )
                return oauth_client

            with patch.object(
                self.provider,
                "_create_upstream_oauth_client",
                side_effect=mock_upstream_client,
            ):
                callback = Request(
                    {
                        "type": "http",
                        "method": "GET",
                        "scheme": "https",
                        "server": ("mcp.example.test", 443),
                        "client": ("127.0.0.1", 1234),
                        "root_path": "",
                        "path": "/auth/callback",
                        "raw_path": b"/auth/callback",
                        "query_string": f"code=mock-upstream-code&state={txn_id}".encode(),
                        "headers": [],
                    }
                )
                callback_response = await self.provider._handle_idp_callback(
                    callback
                )
                self.assertEqual(callback_response.status_code, 302)
                callback_params = parse_qs(
                    urlparse(callback_response.headers["location"]).query
                )
                self.assertEqual(callback_params["state"], ["client-state-123"])
                self.assertIn("code", callback_params)
                client_code = callback_params["code"][0]

                token = await self.provider.exchange_authorization_code(
                    self.client,
                    AuthorizationCode(
                        code=client_code,
                        client_id=self.client.client_id,
                        redirect_uri="http://localhost:43210/callback",
                        redirect_uri_provided_explicitly=True,
                        scopes=params.scopes,
                        expires_at=9999999999,
                        code_challenge=challenge,
                    ),
                )
                self.assertNotEqual(
                    token.access_token, "upstream-access-secret"
                )
                self.assertTrue(token.refresh_token)
                self.assertEqual(
                    requests[0][0], "https://oauth2.googleapis.com/token"
                )
                self.assertEqual(
                    requests[0][1]["code_verifier"],
                    [transaction.proxy_code_verifier],
                )
                self.assertEqual(requests[0][1]["code"], ["mock-upstream-code"])

                refresh = await self.provider.load_refresh_token(
                    self.client, token.refresh_token
                )
                self.assertIsNotNone(refresh)
                refreshed = await self.provider.exchange_refresh_token(
                    self.client, refresh, params.scopes
                )
                self.assertNotEqual(
                    refreshed.refresh_token, token.refresh_token
                )
                self.assertEqual(
                    requests[1][1]["grant_type"], ["refresh_token"]
                )
                self.assertEqual(
                    requests[1][1]["refresh_token"], ["upstream-refresh-secret"]
                )
                self.assertEqual(
                    await self.provider.load_refresh_token(
                        self.client, token.refresh_token
                    ),
                    None,
                )
                self.assertIsNotNone(
                    await self.provider.load_refresh_token(
                        self.client, refreshed.refresh_token
                    )
                )

            raw_files = [
                pathlib.Path(self.temp_dir.name, directory, filename)
                for directory, _, filenames in os.walk(self.temp_dir.name)
                for filename in filenames
            ]
            raw_data = b"\n".join(path.read_bytes() for path in raw_files)
            self.assertNotIn(b"upstream-access-secret", raw_data)
            self.assertNotIn(b"upstream-refresh-secret", raw_data)
            self.assertNotIn(b"rotated-upstream-access", raw_data)
            self.assertNotIn(b"rotated-upstream-refresh", raw_data)
            stored = await self.provider._upstream_token_store.get(
                key=(
                    await self.provider._jti_mapping_store.get(
                        key=self.provider.jwt_issuer.verify_token(
                            token.access_token, expected_token_use="access"
                        )["jti"]
                    )
                ).upstream_token_id
            )
            self.assertEqual(stored.access_token, "rotated-upstream-access")

        asyncio.run(run_flow())

    def test_callback_rejects_unknown_state_without_token_exchange(self):
        """A callback with an unknown transaction state is rejected locally."""

        async def run_flow():
            request = Request(
                {
                    "type": "http",
                    "method": "GET",
                    "scheme": "https",
                    "server": ("mcp.example.test", 443),
                    "client": ("127.0.0.1", 1234),
                    "root_path": "",
                    "path": "/auth/callback",
                    "raw_path": b"/auth/callback",
                    "query_string": b"code=mock-code&state=unknown-transaction",
                    "headers": [],
                }
            )
            response = await self.provider._handle_idp_callback(request)
            self.assertEqual(response.status_code, 400)
            self.assertIn(
                b"Invalid or expired authorization transaction", response.body
            )

        asyncio.run(run_flow())


if __name__ == "__main__":
    unittest.main()
