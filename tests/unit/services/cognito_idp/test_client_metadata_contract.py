import pytest

from localstack.services.cognito_idp.client_metadata_contract import (
    ClientMetadataError,
    transient_client_metadata,
)

OFFICIAL_OPERATIONS = {
    "SignUp",
    "ConfirmSignUp",
    "ForgotPassword",
    "ConfirmForgotPassword",
    "ResendConfirmationCode",
    "GetTokensFromRefreshToken",
}


@pytest.mark.parametrize("operation", sorted(OFFICIAL_OPERATIONS))
def test_metadata_is_propagated_to_trigger_payload_for_all_official_operations(operation):
    source = {"tenant": "enterprise", "surface": "amplify-web"}
    context = transient_client_metadata(operation, source)
    source["tenant"] = "mutated-after-request"

    first = context.trigger_payload()
    first["clientMetadata"]["tenant"] = "mutated-by-trigger"

    assert context.trigger_payload() == {
        "clientMetadata": {"tenant": "enterprise", "surface": "amplify-web"}
    }
    assert context.operation == operation


def test_empty_keys_values_and_more_than_32_entries_follow_official_map_shape():
    metadata = {str(index): "" for index in range(64)}
    metadata[""] = "empty-key-is-valid"
    context = transient_client_metadata("SignUp", metadata)
    assert context.trigger_payload()["clientMetadata"] == metadata


@pytest.mark.parametrize(
    "metadata",
    [
        {1: "value"},
        {"key": 1},
        {"x" * 131_073: "value"},
        {"key": "x" * 131_073},
    ],
)
def test_shape_invalid_metadata_fails_before_trigger_dispatch(metadata):
    with pytest.raises(ClientMetadataError):
        transient_client_metadata("SignUp", metadata)


def test_unknown_api_is_rejected_and_context_cannot_be_persisted():
    with pytest.raises(ClientMetadataError):
        transient_client_metadata("AdminCreateUser", {})

    context = transient_client_metadata("ForgotPassword", {"request": "ephemeral"})
    with pytest.raises(TypeError):
        context.__getstate__()
