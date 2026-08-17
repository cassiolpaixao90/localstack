import dataclasses
from typing import Any

DEFAULT_API_CATEGORY_LIMITS = {
    "UserAuthentication": 120,
    "UserCreation": 50,
    "UserFederation": 25,
    "UserRead": 120,
    "UserResourceRead": 50,
    "UserToken": 120,
}


class ProvisionedLimitError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass
class ProvisionedLimitState:
    values: dict[tuple[str, str, str], int] = dataclasses.field(default_factory=dict)


def get_provisioned_limit(
    state: ProvisionedLimitState,
    *,
    account_id: Any,
    region: Any,
    definition: Any,
    free_limits: dict[str, int] = DEFAULT_API_CATEGORY_LIMITS,
) -> dict[str, Any]:
    account_id, region = _scope(account_id, region)
    category = _definition(definition, free_limits)
    free = free_limits[category]
    provisioned = state.values.get((account_id, region, category), free)
    return {"Limit": _response(category, provisioned, free)}


def update_provisioned_limit(
    state: ProvisionedLimitState,
    *,
    account_id: Any,
    region: Any,
    definition: Any,
    requested_value: Any,
    account_maxima: dict[str, int],
    free_limits: dict[str, int] = DEFAULT_API_CATEGORY_LIMITS,
) -> dict[str, Any]:
    account_id, region = _scope(account_id, region)
    category = _definition(definition, free_limits)
    free = free_limits[category]
    maximum = account_maxima.get(category, free)
    if not isinstance(requested_value, int) or isinstance(requested_value, bool):
        raise ProvisionedLimitError("InvalidParameterException", "Invalid RequestedLimitValue")
    if requested_value < free:
        raise ProvisionedLimitError(
            "InvalidParameterException", "Requested limit is below the free limit"
        )
    if requested_value > maximum:
        raise ProvisionedLimitError(
            "ServiceQuotaExceededException", "Requested limit exceeds the account maximum"
        )
    state.values[(account_id, region, category)] = requested_value
    return {"Limit": _response(category, requested_value, free)}


def _scope(account_id: Any, region: Any) -> tuple[str, str]:
    if (
        not isinstance(account_id, str)
        or len(account_id) != 12
        or not account_id.isdigit()
        or not isinstance(region, str)
        or not 5 <= len(region) <= 32
    ):
        raise ProvisionedLimitError("InvalidParameterException", "Invalid account/Region scope")
    return account_id, region


def _definition(value: Any, free_limits: dict[str, int]) -> str:
    if not isinstance(value, dict) or set(value) != {"Attributes", "LimitClass"}:
        raise ProvisionedLimitError("InvalidParameterException", "Invalid LimitDefinition")
    if value.get("LimitClass") != "API_CATEGORY":
        raise ProvisionedLimitError("InvalidParameterException", "Unsupported LimitClass")
    attributes = value.get("Attributes")
    if not isinstance(attributes, dict) or set(attributes) != {"Category"}:
        raise ProvisionedLimitError("InvalidParameterException", "Invalid limit Attributes")
    category = attributes.get("Category")
    if not isinstance(category, str) or category not in free_limits:
        raise ProvisionedLimitError("ResourceNotFoundException", "API category does not exist")
    return category


def _response(category: str, provisioned: int, free: int) -> dict[str, Any]:
    return {
        "FreeLimitValue": free,
        "LimitDefinition": {
            "Attributes": {"Category": category},
            "LimitClass": "API_CATEGORY",
        },
        "ProvisionedLimitValue": provisioned,
    }
