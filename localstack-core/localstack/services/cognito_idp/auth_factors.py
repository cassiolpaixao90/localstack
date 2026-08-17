from typing import Any

_AUTH_FACTORS = {"EMAIL_OTP", "PASSWORD", "SMS_OTP", "SOFTWARE_TOKEN", "WEB_AUTHN"}
_MFA_SETTINGS = {"EMAIL_OTP", "SMS_MFA", "SOFTWARE_TOKEN_MFA"}


class AuthFactorsError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def admin_auth_factors_response(
    username: Any,
    *,
    configured_factors: set[str],
    enabled_mfa_settings: set[str] | None = None,
    preferred_mfa_setting: str | None = None,
) -> dict[str, Any]:
    """Build the AdminGetUserAuthFactors response from already-authorized user state."""
    if not isinstance(username, str) or not 1 <= len(username) <= 128:
        raise AuthFactorsError("InvalidParameterException", "Invalid Username")
    if (
        not isinstance(configured_factors, set)
        or len(configured_factors) > 8
        or not configured_factors <= _AUTH_FACTORS
    ):
        raise AuthFactorsError("InvalidParameterException", "Invalid configured auth factors")
    enabled_mfa_settings = set(enabled_mfa_settings or ())
    if not enabled_mfa_settings <= _MFA_SETTINGS:
        raise AuthFactorsError("InvalidParameterException", "Invalid MFA settings")
    if preferred_mfa_setting is not None and preferred_mfa_setting not in enabled_mfa_settings:
        raise AuthFactorsError("InvalidParameterException", "Preferred MFA setting must be enabled")
    response: dict[str, Any] = {
        "ConfiguredUserAuthFactors": sorted(configured_factors, key=_factor_sort_key),
        "Username": username,
    }
    if enabled_mfa_settings:
        response["UserMFASettingList"] = sorted(enabled_mfa_settings)
    if preferred_mfa_setting is not None:
        response["PreferredMfaSetting"] = preferred_mfa_setting
    return response


def _factor_sort_key(value: str) -> tuple[int, str]:
    order = {
        "PASSWORD": 0,
        "EMAIL_OTP": 1,
        "SMS_OTP": 2,
        "WEB_AUTHN": 3,
        "SOFTWARE_TOKEN": 4,
    }
    return order[value], value
