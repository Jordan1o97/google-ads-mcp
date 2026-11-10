# Copyright 2026 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Dynamically discover SDK methods with strict execution allowlisting."""

from __future__ import annotations

import importlib
import pkgutil
import re
from typing import Any, Callable

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from ads_mcp import utils

api_mcp = FastMCP("api")

# Exact, reviewed read-only RPC allowlist. Method discovery is broader than
# execution: no discovered endpoint becomes callable merely by being present
# in the installed SDK. Extend this tuple only after reviewing endpoint docs.
SAFE_READ_METHODS = frozenset(
    {
        "CustomerService.ListAccessibleCustomers",
        "GoogleAdsFieldService.GetGoogleAdsField",
        "GoogleAdsFieldService.SearchGoogleAdsFields",
        "GoogleAdsService.Search",
        "GoogleAdsService.SearchStream",
    }
)


def _camel_case(value: str) -> str:
    """Converts a generated SDK snake_case method to its RPC name."""
    return "".join(part[:1].upper() + part[1:] for part in value.split("_"))


def _snake_case(value: str) -> str:
    """Converts an RPC name to the SDK's snake_case method name."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()


def discover_services(module_names: list[str]) -> list[str]:
    """Converts generated `*_service` modules into SDK service names."""
    services = {
        f"{_camel_case(name.removesuffix('_service'))}Service"
        for name in module_names
        if name.endswith("_service")
    }
    return sorted(services)


def discover_sdk_methods(
    version: str | None = None,
) -> dict[str, list[str]]:
    """Returns service and RPC names from the installed Google Ads SDK."""
    from google.ads.googleads.client import _DEFAULT_VERSION

    api_version = version or _DEFAULT_VERSION
    services_package = importlib.import_module(
        f"google.ads.googleads.{api_version}.services.services"
    )
    service_names = discover_services(
        [
            entry.name
            for entry in pkgutil.iter_modules(services_package.__path__)
        ]
    )
    result: dict[str, list[str]] = {}
    for service_name in service_names:
        module_name = _snake_case(service_name)
        module = importlib.import_module(
            f"{services_package.__name__}.{module_name}"
        )
        client_class = getattr(module, f"{service_name}Client", None)
        if client_class is None:
            continue
        methods = {
            _camel_case(name)
            for name, value in vars(client_class).items()
            if not name.startswith("_")
            and not isinstance(value, (staticmethod, classmethod))
            and callable(value)
        }
        if methods:
            result[service_name] = sorted(methods)
    return result


# Billing, payments, account-linking and user-access RPCs are never executable,
# even if an operator adds them to `allowed_methods`. GoogleAdsService.Mutate is
# denied because it bundles arbitrary resource operations past the per-service
# status guard below.
NEVER_EXECUTABLE_SERVICES = frozenset(
    {
        "BillingSetupService",
        "AccountBudgetProposalService",
        "PaymentsAccountService",
        "InvoiceService",
        "CustomerManagerLinkService",
        "CustomerClientLinkService",
        "CustomerUserAccessService",
        "CustomerUserAccessInvitationService",
    }
)
NEVER_EXECUTABLE_METHODS = frozenset({"GoogleAdsService.Mutate"})

# Services whose entities can start serving (and spending). Writes through them
# may only create or keep entities PAUSED; ENABLED is rejected anywhere in the
# request, and creates must state PAUSED explicitly.
PAUSED_ONLY_SERVICES = frozenset(
    {"CampaignService", "AdGroupAdService", "AdGroupService"}
)
_PAUSED_VALUES = {"PAUSED", 3}
_ENABLED_VALUES = {"ENABLED", 2}


def _status_value(value: Any) -> Any:
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name.upper()
    if isinstance(value, str):
        return value.strip().upper()
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return value


def _iter_status_values(obj: Any):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "status":
                yield _status_value(value)
            yield from _iter_status_values(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _iter_status_values(item)


def enforce_write_policy(service_name: str, parameters: dict[str, Any]) -> None:
    """Rejects writes that would enable serving entities.

    Campaigns, ad groups and ads may be created or updated only as PAUSED.
    The check is structural: every ``status`` field anywhere in the request
    is inspected, and every ``create`` operation must carry PAUSED.
    """
    if service_name not in PAUSED_ONLY_SERVICES:
        return
    for status in _iter_status_values(parameters):
        if status in _ENABLED_VALUES:
            raise ToolError(
                f"{service_name}: setting status ENABLED is blocked by server "
                "policy; create and keep entities PAUSED and enable them in "
                "the Google Ads UI after review."
            )
        if status not in _PAUSED_VALUES and status != "REMOVED" and status != 4:
            raise ToolError(
                f"{service_name}: status must be PAUSED (got {status!r})."
            )
    request = parameters.get("request")
    operations = (
        request.get("operations") if isinstance(request, dict) else None
    ) or parameters.get("operations")
    if operations is None:
        raise ToolError(
            f"{service_name}: writes must pass `operations` as JSON objects "
            "so the PAUSED-only policy can be verified."
        )
    if not isinstance(operations, list) or not all(
        isinstance(op, dict) for op in operations
    ):
        raise ToolError(f"{service_name}: `operations` must be a list of objects.")
    for op in operations:
        create = op.get("create")
        if create is not None and (
            not isinstance(create, dict)
            or _status_value(create.get("status")) not in _PAUSED_VALUES
        ):
            raise ToolError(
                f"{service_name}: create operations must set status PAUSED."
            )


def _method_allowed(
    service_name: str,
    method_name: str,
    config: dict[str, Any] | None = None,
) -> bool:
    """Checks exact read allowlisting or an explicitly enabled write allowlist."""
    identifier = f"{service_name}.{method_name}"
    if identifier in SAFE_READ_METHODS:
        return True
    if (
        service_name in NEVER_EXECUTABLE_SERVICES
        or identifier in NEVER_EXECUTABLE_METHODS
    ):
        return False
    # Generation methods can incur costs and remain denied even if accidentally
    # added to a write allowlist.
    if "generate" in method_name.casefold():
        return False
    config = config or {}
    return bool(
        config.get("allow_writes") is True
        and isinstance(config.get("allowed_methods"), list)
        and identifier in config["allowed_methods"]
    )


def build_method_catalog(
    services: dict[str, list[str]],
    config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Builds a discoverable catalog while marking only allowlisted methods executable."""
    return [
        {
            "service": service_name,
            "method": method_name,
            "executable": _method_allowed(service_name, method_name, config),
        }
        for service_name in sorted(services)
        for method_name in sorted(services[service_name])
    ]


def _configured_execution() -> dict[str, Any]:
    """Loads optional per-method write configuration using shared resolution."""
    from ads_mcp.config import ToolsConfig

    config = ToolsConfig.load()._config
    namespace_config = config.get("namespaces", {}).get("api", {})
    return namespace_config if isinstance(namespace_config, dict) else {}


@api_mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def discover_api_methods() -> list[dict[str, Any]]:
    """Lists methods available in the installed SDK and their execution policy.

    The catalog is generated from the installed Google Ads API version. Only
    exact reviewed read methods are executable by default. Writes require
    `allow_writes: true` and an exact `allowed_methods` entry in the `api`
    namespace configuration. Generation methods are never executable.
    """
    return build_method_catalog(discover_sdk_methods(), _configured_execution())


@api_mcp.tool()
def execute_api_method(
    service_name: str,
    method_name: str,
    parameters: dict[str, Any],
    login_customer_id: str | None = None,
) -> Any:
    """Executes an explicitly allowlisted SDK RPC using upstream authentication.

    This tool is deliberately not marked read-only because an operator may
    explicitly enable an exact write RPC in configuration. No endpoint is
    treated as safe based on naming or validation-only request fields.
    """
    return execute_method(
        service_name,
        method_name,
        parameters,
        login_customer_id=login_customer_id,
        service_factory=utils.get_googleads_service,
        config=_configured_execution(),
    )


def execute_method(
    service_name: str,
    method_name: str,
    parameters: dict[str, Any],
    *,
    login_customer_id: str | None = None,
    service_factory: Callable[..., Any] = utils.get_googleads_service,
    config: dict[str, Any] | None = None,
) -> Any:
    """Invokes one method after exact allowlist and input validation."""
    if not isinstance(parameters, dict):
        raise ToolError("parameters must be a JSON object")
    if not _method_allowed(service_name, method_name, config):
        raise ToolError(
            f"Method {service_name}.{method_name} is not allowlisted for execution"
        )
    if f"{service_name}.{method_name}" not in SAFE_READ_METHODS:
        enforce_write_policy(service_name, parameters)
    try:
        service = service_factory(
            service_name, login_customer_id=login_customer_id
        )
        method = getattr(service, _snake_case(method_name), None)
        if method is None or not callable(method):
            raise ToolError(
                f"Method {service_name}.{method_name} is unavailable in this SDK"
            )
        return utils.format_output_value(method(**parameters))
    except ToolError:
        raise
    except Exception as ex:
        from google.ads.googleads.errors import GoogleAdsException

        if isinstance(ex, GoogleAdsException):
            # Only the request ID and Google's per-error messages are returned;
            # never the request payload or credentials.
            raise ToolError(utils.format_google_ads_error(ex)) from None
        # SDK exceptions can include request data or credentials. Do not return
        # or chain untrusted exception text into an MCP response or traceback.
        raise ToolError("Google Ads API call failed") from None
