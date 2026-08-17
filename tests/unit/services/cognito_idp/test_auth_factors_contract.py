import pytest

from localstack.services.cognito_idp.auth_factors import (
    AuthFactorsError,
    admin_auth_factors_response,
)


def test_admin_auth_factors_response_matches_new_botocore_contract():
    assert admin_auth_factors_response(
        "alice",
        configured_factors={"SOFTWARE_TOKEN", "PASSWORD", "WEB_AUTHN"},
        enabled_mfa_settings={"SOFTWARE_TOKEN_MFA"},
        preferred_mfa_setting="SOFTWARE_TOKEN_MFA",
    ) == {
        "ConfiguredUserAuthFactors": ["PASSWORD", "WEB_AUTHN", "SOFTWARE_TOKEN"],
        "PreferredMfaSetting": "SOFTWARE_TOKEN_MFA",
        "UserMFASettingList": ["SOFTWARE_TOKEN_MFA"],
        "Username": "alice",
    }


def test_admin_auth_factors_rejects_unknown_or_inconsistent_factors():
    with pytest.raises(AuthFactorsError, match="Invalid configured auth factors"):
        admin_auth_factors_response("alice", configured_factors={"CUSTOM"})
    with pytest.raises(AuthFactorsError, match="must be enabled"):
        admin_auth_factors_response(
            "alice",
            configured_factors={"PASSWORD"},
            preferred_mfa_setting="SMS_MFA",
        )
