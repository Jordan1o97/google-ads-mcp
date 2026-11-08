"""Tests for the dynamically discovered, allowlisted API namespace."""

import unittest
from unittest.mock import Mock, patch

from fastmcp.exceptions import ToolError

from ads_mcp.tools import api


class TestApiDiscovery(unittest.TestCase):
    def test_catalog_lists_sdk_methods_but_marks_only_allowlisted_read_methods(
        self,
    ):
        catalog = api.build_method_catalog(
            {
                "CampaignService": ["GetCampaign", "MutateCampaigns"],
                "GoogleAdsService": ["Search", "SearchStream", "Mutate"],
                "AssetGenerationService": ["GenerateImages"],
            }
        )

        by_method = {
            f'{item["service"]}.{item["method"]}': item for item in catalog
        }
        self.assertIn("CampaignService.GetCampaign", by_method)
        self.assertIn("GoogleAdsService.Search", by_method)
        self.assertFalse(by_method["CampaignService.GetCampaign"]["executable"])
        self.assertTrue(by_method["GoogleAdsService.Search"]["executable"])
        self.assertFalse(by_method["GoogleAdsService.Mutate"]["executable"])
        self.assertFalse(
            by_method["AssetGenerationService.GenerateImages"]["executable"]
        )

    def test_execute_calls_only_exact_allowlisted_method_through_existing_auth(
        self,
    ):
        response = object()
        service = Mock()
        service.search.return_value = response
        service_factory = Mock(return_value=service)

        result = api.execute_method(
            "GoogleAdsService",
            "Search",
            {"customer_id": "123", "query": "SELECT customer.id FROM customer"},
            service_factory=service_factory,
        )

        self.assertIs(result, response)
        service_factory.assert_called_once_with(
            "GoogleAdsService", login_customer_id=None
        )
        service.search.assert_called_once_with(
            customer_id="123", query="SELECT customer.id FROM customer"
        )

    def test_execute_rejects_mutations_without_explicit_write_configuration(
        self,
    ):
        service_factory = Mock()
        with self.assertRaises(ToolError):
            api.execute_method(
                "CampaignService",
                "MutateCampaigns",
                {"customer_id": "123", "operations": []},
                service_factory=service_factory,
            )
        service_factory.assert_not_called()

    def test_execute_never_allows_generation_even_if_configured(self):
        service_factory = Mock()
        with self.assertRaises(ToolError):
            api.execute_method(
                "AssetGenerationService",
                "GenerateImages",
                {"customer_id": "123"},
                service_factory=service_factory,
                config={
                    "allow_writes": True,
                    "allowed_methods": [
                        "AssetGenerationService.GenerateImages"
                    ],
                },
            )
        service_factory.assert_not_called()

    def test_execute_allows_write_only_with_explicit_exact_allowlist(self):
        service = Mock()
        service.mutate_campaigns.return_value = "ok"
        service_factory = Mock(return_value=service)

        result = api.execute_method(
            "CampaignService",
            "MutateCampaigns",
            {"customer_id": "123", "operations": []},
            service_factory=service_factory,
            config={
                "allow_writes": True,
                "allowed_methods": ["CampaignService.MutateCampaigns"],
            },
        )

        self.assertEqual(result, "ok")
        service.mutate_campaigns.assert_called_once_with(
            customer_id="123", operations=[]
        )

    def test_discovers_methods_from_installed_sdk_without_api_calls(self):
        methods = api.discover_sdk_methods()

        self.assertIn("Search", methods["GoogleAdsService"])
        self.assertIn("Mutate", methods["GoogleAdsService"])
        self.assertNotIn("Search", methods.get("CampaignService", []))
        self.assertNotIn("CampaignPath", methods["CampaignService"])
        self.assertNotIn("ParseCampaignPath", methods["CampaignService"])
        catalog = api.build_method_catalog(methods)
        search = next(
            item
            for item in catalog
            if item["service"] == "GoogleAdsService"
            and item["method"] == "Search"
        )
        mutate = next(
            item
            for item in catalog
            if item["service"] == "GoogleAdsService"
            and item["method"] == "Mutate"
        )
        self.assertTrue(search["executable"])
        self.assertFalse(mutate["executable"])

    def test_write_configuration_is_read_from_shared_tools_config(self):
        from ads_mcp.config import ToolsConfig

        configured = {
            "namespaces": {
                "api": {
                    "allow_writes": True,
                    "allowed_methods": ["CampaignService.MutateCampaigns"],
                }
            }
        }
        with patch(
            "ads_mcp.config.ToolsConfig.load",
            return_value=ToolsConfig(configured),
        ):
            self.assertEqual(
                api._configured_execution(), configured["namespaces"]["api"]
            )

    def test_shipped_config_enables_catalog_and_disables_write_namespaces(self):
        from ads_mcp.config import ToolsConfig

        config = ToolsConfig.load()

        self.assertTrue(config.is_namespace_enabled("api"))
        self.assertFalse(config.is_namespace_enabled("labels"))
        self.assertFalse(config.is_namespace_enabled("assets"))

    def test_service_discovery_excludes_non_service_modules(self):
        services = api.discover_services(
            [
                "campaign_service",
                "campaign",
                "google_ads_service",
                "internal_tools",
            ]
        )
        self.assertEqual(services, ["CampaignService", "GoogleAdsService"])


if __name__ == "__main__":
    unittest.main()
