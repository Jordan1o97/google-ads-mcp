"""Tests for the PAUSED-only / no-billing write policy of the generic executor."""

import unittest
from unittest import mock

from fastmcp.exceptions import ToolError

from ads_mcp.tools import api

WRITE_CONFIG = {
    "allow_writes": True,
    "allowed_methods": [
        "CustomerService.CreateCustomerClient",
        "CampaignService.MutateCampaigns",
        "AdGroupAdService.MutateAdGroupAds",
        "AdGroupCriterionService.MutateAdGroupCriteria",
        "BillingSetupService.MutateBillingSetup",
        "GoogleAdsService.Mutate",
    ],
}


def _run(service, method, params):
    svc = mock.MagicMock()
    getattr(svc, api._snake_case(method)).return_value = {"ok": True}
    return api.execute_method(
        service,
        method,
        params,
        service_factory=lambda *a, **k: svc,
        config=WRITE_CONFIG,
    ), svc


class WritePolicyTest(unittest.TestCase):
    def test_billing_and_bulk_mutate_never_executable(self):
        for service, method in [
            ("BillingSetupService", "MutateBillingSetup"),
            ("GoogleAdsService", "Mutate"),
        ]:
            with self.assertRaises(ToolError):
                _run(service, method, {"customer_id": "1"})

    def test_paused_campaign_create_allowed(self):
        result, svc = _run(
            "CampaignService",
            "MutateCampaigns",
            {
                "customer_id": "1",
                "operations": [{"create": {"name": "x", "status": "PAUSED"}}],
            },
        )
        self.assertIsNotNone(result)
        svc.mutate_campaigns.assert_called_once()

    def test_paused_via_request_object_allowed(self):
        _run(
            "CampaignService",
            "MutateCampaigns",
            {
                "request": {
                    "customer_id": "1",
                    "validate_only": True,
                    "operations": [{"create": {"name": "x", "status": 3}}],
                }
            },
        )

    def test_enabled_rejected_anywhere(self):
        cases = [
            {"operations": [{"create": {"status": "ENABLED"}}]},
            {"operations": [{"create": {"status": "enabled"}}]},
            {"operations": [{"update": {"status": 2}}]},
            {"request": {"operations": [{"update": {"status": "ENABLED"}}]}},
        ]
        for params in cases:
            with self.subTest(params=params), self.assertRaises(ToolError):
                _run("CampaignService", "MutateCampaigns", params)

    def test_create_without_status_rejected(self):
        with self.assertRaises(ToolError):
            _run(
                "AdGroupAdService",
                "MutateAdGroupAds",
                {"customer_id": "1", "operations": [{"create": {"ad": {}}}]},
            )

    def test_non_dict_operations_rejected(self):
        with self.assertRaises(ToolError):
            _run("CampaignService", "MutateCampaigns", {"customer_id": "1"})

    def test_keywords_and_customer_creation_unaffected(self):
        _run(
            "AdGroupCriterionService",
            "MutateAdGroupCriteria",
            {"customer_id": "1", "operations": [{"create": {"status": "ENABLED"}}]},
        )
        _run(
            "CustomerService",
            "CreateCustomerClient",
            {"customer_id": "7706257507", "customer_client": {"descriptive_name": "x"}},
        )

    def test_bundled_config_has_no_billing_methods(self):
        from ads_mcp.config import ToolsConfig

        cfg = ToolsConfig.load()._config["namespaces"]["api"]
        for ident in cfg["allowed_methods"]:
            service = ident.split(".")[0]
            self.assertNotIn(service, api.NEVER_EXECUTABLE_SERVICES)
            self.assertNotIn(ident, api.NEVER_EXECUTABLE_METHODS)


if __name__ == "__main__":
    unittest.main()
