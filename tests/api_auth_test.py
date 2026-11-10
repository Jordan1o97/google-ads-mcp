"""Authentication integration tests for the generic API executor."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ads_mcp import utils
from ads_mcp.tools.api import execute_method


class TestApiExecutorAuthentication(unittest.TestCase):
    def test_stdio_execution_uses_application_default_credentials(self):
        credentials = Mock()
        mock_client = Mock()
        mock_client.get_service.return_value.search.return_value = "result"
        with (
            patch(
                "fastmcp.server.dependencies.get_access_token",
                return_value=None,
            ),
            patch(
                "google.auth.default", return_value=(credentials, "project")
            ) as adc,
            patch(
                "ads_mcp.utils.GoogleAdsClient", return_value=mock_client
            ) as client_type,
        ):
            result = execute_method(
                "GoogleAdsService",
                "Search",
                {
                    "customer_id": "123",
                    "query": "SELECT customer.id FROM customer",
                },
                service_factory=utils.get_googleads_service,
            )

        self.assertEqual(result, "result")
        adc.assert_called_once_with(
            scopes=["https://www.googleapis.com/auth/adwords"]
        )
        self.assertIs(client_type.call_args.kwargs["credentials"], credentials)
        mock_client.get_service.assert_called_once()

    def test_http_execution_uses_fastmcp_oauth_access_token(self):
        mock_client = Mock()
        mock_client.get_service.return_value.search.return_value = "result"
        with (
            patch(
                "fastmcp.server.dependencies.get_access_token",
                return_value=SimpleNamespace(token="oauth-access-token"),
            ),
            patch("google.auth.default") as adc,
            patch(
                "ads_mcp.utils.GoogleAdsClient", return_value=mock_client
            ) as client_type,
        ):
            result = execute_method(
                "GoogleAdsService",
                "Search",
                {
                    "customer_id": "123",
                    "query": "SELECT customer.id FROM customer",
                },
                service_factory=utils.get_googleads_service,
            )

        self.assertEqual(result, "result")
        adc.assert_not_called()
        self.assertEqual(
            client_type.call_args.kwargs["credentials"].token,
            "oauth-access-token",
        )
        mock_client.get_service.assert_called_once()


if __name__ == "__main__":
    unittest.main()
