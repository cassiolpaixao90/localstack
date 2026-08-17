import base64
import json
import threading
import time
import uuid

import pytest

from localstack.services.cognito_idp.lambda_triggers import (
    EncryptionAdapter,
    LambdaFunctionDescriptor,
    LambdaPermission,
    LambdaTriggerError,
    LocalLambdaInvoker,
    TriggerIdentity,
    build_operation_metadata,
    encrypt_custom_sender_secret,
    invoke_authentication_trigger,
    invoke_custom_message,
    invoke_custom_sender,
    invoke_inbound_federation,
    invoke_pre_token_generation,
    invoke_user_migration,
    parse_lambda_configuration,
)


@pytest.fixture
def identity():
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    region_name = f"aa-{uuid.uuid4().hex[:4]}-1"
    return TriggerIdentity(
        partition="aws",
        account_id=account_id,
        region=region_name,
        pool_id=f"{region_name}_pool123",
        client_id="client123",
        username="alice",
    )


@pytest.fixture
def function_arn(identity):
    return (
        f"arn:{identity.partition}:lambda:{identity.region}:{identity.account_id}:"
        "function:cognito-trigger"
    )


@pytest.fixture
def pool_arn(identity):
    return (
        f"arn:{identity.partition}:cognito-idp:{identity.region}:{identity.account_id}:"
        f"userpool/{identity.pool_id}"
    )


@pytest.fixture
def descriptor(function_arn, pool_arn, identity):
    return LambdaFunctionDescriptor(
        function_arn=function_arn,
        state="Active",
        timeout_seconds=3,
        permissions=(
            LambdaPermission(
                action="lambda:InvokeFunction",
                principal="cognito-idp.amazonaws.com",
                source_arn=pool_arn,
                source_account=identity.account_id,
            ),
        ),
    )


@pytest.fixture
def invoker(descriptor):
    calls = []

    def invoke(_arn, event):
        calls.append(event)
        return event

    instance = LocalLambdaInvoker(
        lookup=lambda _arn: descriptor,
        invoke=invoke,
        maximum_concurrency=2,
        invocation_timeout_seconds=1,
    )
    yield instance, calls
    instance.close()


def test_lambda_configuration_covers_official_nested_versions(identity, function_arn):
    kms_arn = (
        f"arn:{identity.partition}:kms:{identity.region}:{identity.account_id}:"
        "key/01234567-89ab-cdef-0123-456789abcdef"
    )
    config = parse_lambda_configuration(
        {
            "CustomMessage": function_arn,
            "PreAuthentication": function_arn,
            "PostAuthentication": function_arn,
            "UserMigration": function_arn,
            "CustomEmailSender": {"LambdaArn": function_arn, "LambdaVersion": "V1_0"},
            "CustomSMSSender": {"LambdaArn": function_arn, "LambdaVersion": "V1_0"},
            "KMSKeyID": kms_arn,
            "InboundFederation": {"LambdaArn": function_arn, "LambdaVersion": "V1_0"},
            "PreTokenGenerationConfig": {
                "LambdaArn": function_arn,
                "LambdaVersion": "V3_0",
            },
        },
        identity=identity,
    )
    assert config.lambda_arn("PreTokenGeneration") == function_arn
    assert config.pre_token_version == "V3_0"
    assert config.kms_key_arn == kms_arn


@pytest.mark.parametrize(
    "change",
    [
        {"CustomEmailSender": {"LambdaArn": "not-an-arn", "LambdaVersion": "V1_0"}},
        {"PreTokenGenerationConfig": {"LambdaArn": "not-an-arn", "LambdaVersion": "V4_0"}},
        {"InboundFederation": {"LambdaArn": "not-an-arn", "LambdaVersion": "V2_0"}},
        {"KMSKeyID": "not-an-arn"},
        {"unknown": "value"},
    ],
)
def test_lambda_configuration_rejects_partial_wrong_version_and_unknown(identity, change):
    with pytest.raises(LambdaTriggerError, match="LambdaConfig"):
        parse_lambda_configuration(change, identity=identity)


def test_custom_sender_requires_kms_and_pre_token_forms_are_exclusive(identity, function_arn):
    with pytest.raises(LambdaTriggerError, match="KMSKeyID"):
        parse_lambda_configuration(
            {"CustomEmailSender": {"LambdaArn": function_arn, "LambdaVersion": "V1_0"}},
            identity=identity,
        )
    with pytest.raises(LambdaTriggerError, match="PreTokenGeneration"):
        parse_lambda_configuration(
            {
                "PreTokenGeneration": function_arn,
                "PreTokenGenerationConfig": {
                    "LambdaArn": function_arn,
                    "LambdaVersion": "V2_0",
                },
            },
            identity=identity,
        )


def test_local_invoker_enforces_policy_shape_and_bounds_before_invocation(
    identity, function_arn, pool_arn, descriptor
):
    calls = []
    wrong = LambdaFunctionDescriptor(
        function_arn=function_arn,
        state="Active",
        timeout_seconds=3,
        permissions=(
            LambdaPermission(
                action="lambda:InvokeFunction",
                principal="cognito-idp.amazonaws.com",
                source_arn=f"{pool_arn}-other",
                source_account=identity.account_id,
            ),
        ),
    )
    invoker = LocalLambdaInvoker(
        lookup=lambda _: wrong,
        invoke=lambda arn, event: calls.append((arn, event)),
    )
    with pytest.raises(LambdaTriggerError, match="permission"):
        invoker.invoke(function_arn, identity, {"response": {}})
    assert calls == []
    invoker.close()

    invoker = LocalLambdaInvoker(lookup=lambda _: descriptor, invoke=lambda _arn, event: event)
    with pytest.raises(LambdaTriggerError, match="event"):
        invoker.invoke(function_arn, identity, {"payload": "x" * 1_000_000})
    invoker.close()


def test_local_invoker_timeout_and_admission_are_bounded(identity, function_arn, descriptor):
    release = threading.Event()

    def slow(_arn, event):
        release.wait(1)
        return event

    invoker = LocalLambdaInvoker(
        lookup=lambda _: descriptor,
        invoke=slow,
        maximum_concurrency=1,
        invocation_timeout_seconds=0.03,
    )
    with pytest.raises(LambdaTriggerError, match="timed out"):
        invoker.invoke(function_arn, identity, {"response": {}})
    with pytest.raises(LambdaTriggerError, match="capacity"):
        invoker.invoke(function_arn, identity, {"response": {}})
    release.set()
    time.sleep(0.02)
    invoker.close()


def test_operation_metadata_routes_official_fields_without_persisting_raw_context():
    metadata = build_operation_metadata(
        "AdminRespondToAuthChallenge",
        {
            "ClientMetadata": {"tenant": "acme"},
            "AnalyticsMetadata": {"AnalyticsEndpointId": "endpoint-1"},
            "ContextData": {
                "EncodedData": "sensitive-device-fingerprint",
                "HttpHeaders": [{"headerName": "User-Agent", "headerValue": "Browser"}],
                "IpAddress": "192.0.2.10",
                "ServerName": "auth.example.test",
                "ServerPath": "/login",
            },
        },
    )
    assert metadata.client_metadata_for("PostAuthentication") == {"tenant": "acme"}
    assert metadata.risk_context()["IpAddress"] == "192.0.2.10"
    assert "sensitive-device-fingerprint" not in repr(metadata)

    attribute = build_operation_metadata(
        "UpdateUserAttributes", {"ClientMetadata": {"locale": "pt-BR"}}
    )
    assert attribute.client_metadata_for("CustomMessage") == {"locale": "pt-BR"}
    reset = build_operation_metadata(
        "AdminResetUserPassword", {"ClientMetadata": {"reason": "support"}}
    )
    assert reset.client_metadata_for("CustomMessage") == {"reason": "support"}
    confirmation = build_operation_metadata(
        "ConfirmForgotPassword", {"ClientMetadata": {"flow": "reset"}}
    )
    assert confirmation.client_metadata_for("PostConfirmation") == {"flow": "reset"}
    with pytest.raises(LambdaTriggerError, match="metadata"):
        build_operation_metadata(
            "UpdateUserAttributes",
            {"AnalyticsMetadata": {"AnalyticsEndpointId": "not-supported"}},
        )


def test_pre_and_post_authentication_event_shapes(identity, function_arn, invoker):
    executor, calls = invoker
    pre = invoke_authentication_trigger(
        executor,
        function_arn=function_arn,
        identity=identity,
        phase="PRE",
        user_attributes={"sub": "user-sub"},
        client_metadata={"risk": "high"},
        user_not_found=True,
    )
    post = invoke_authentication_trigger(
        executor,
        function_arn=function_arn,
        identity=identity,
        phase="POST",
        user_attributes={"sub": "user-sub"},
        client_metadata={"step": "complete"},
        new_device_used=True,
    )
    assert pre["request"]["validationData"] == {"risk": "high"}
    assert pre["request"]["userNotFound"] is True
    assert post["request"]["clientMetadata"] == {"step": "complete"}
    assert post["request"]["newDeviceUsed"] is True
    assert len(calls) == 2


def test_custom_message_requires_placeholders_and_developer_email(
    identity, function_arn, descriptor
):
    def custom(_arn, event):
        event["response"] = {
            "emailMessage": "Use {####}",
            "emailSubject": "Confirm",
            "smsMessage": "Use {####}",
        }
        return event

    executor = LocalLambdaInvoker(lookup=lambda _: descriptor, invoke=custom)
    result = invoke_custom_message(
        executor,
        function_arn=function_arn,
        identity=identity,
        trigger_source="CustomMessage_SignUp",
        user_attributes={"email": "alice@example.test"},
        code_parameter="{####}",
        username_parameter=None,
        client_metadata={"locale": "pt-BR"},
        email_sending_account="DEVELOPER",
    )
    assert result.email_subject == "Confirm"
    executor.close()

    executor = LocalLambdaInvoker(lookup=lambda _: descriptor, invoke=custom)
    with pytest.raises(LambdaTriggerError, match="DEVELOPER"):
        invoke_custom_message(
            executor,
            function_arn=function_arn,
            identity=identity,
            trigger_source="CustomMessage_SignUp",
            user_attributes={},
            code_parameter="{####}",
            username_parameter=None,
            client_metadata={},
            email_sending_account="COGNITO_DEFAULT",
        )
    executor.close()


def test_user_migration_password_is_ephemeral_and_response_is_strict(
    identity, function_arn, descriptor
):
    seen = []

    def migrate(_arn, event):
        seen.append(event)
        event["response"] = {
            "desiredDeliveryMediums": ["EMAIL"],
            "enableSMSMFA": False,
            "finalUserStatus": "CONFIRMED",
            "forceAliasCreation": False,
            "messageAction": "SUPPRESS",
            "userAttributes": {"email": "alice@example.test", "email_verified": "true"},
        }
        return event

    executor = LocalLambdaInvoker(lookup=lambda _: descriptor, invoke=migrate)
    result = invoke_user_migration(
        executor,
        function_arn=function_arn,
        identity=identity,
        trigger_source="UserMigration_Authentication",
        password="DoNotPersist9!",
        validation_data={"tenant": "acme"},
        client_metadata={},
    )
    assert result.final_user_status == "CONFIRMED"
    assert result.user_attributes["email_verified"] == "true"
    assert "DoNotPersist9!" not in repr(result)
    assert seen[0]["request"]["password"] == "DoNotPersist9!"
    executor.close()


def test_custom_sender_encrypts_secret_and_never_sends_plaintext(
    identity, function_arn, descriptor
):
    kms_arn = (
        f"arn:{identity.partition}:kms:{identity.region}:{identity.account_id}:"
        "key/01234567-89ab-cdef-0123-456789abcdef"
    )
    adapter = EncryptionAdapter(
        describe=lambda _: {
            "Arn": kms_arn,
            "Enabled": True,
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Owner": identity.account_id,
            "Grants": [
                {
                    "GranteePrincipal": "cognito-idp.amazonaws.com",
                    "Operations": ["GenerateDataKey"],
                    "EncryptionContext": {"userpool-id": identity.pool_id},
                }
            ],
        },
        encrypt=lambda _arn, plaintext, context: b"ciphertext:" + plaintext[::-1],
    )
    encrypted = encrypt_custom_sender_secret(
        adapter,
        kms_key_arn=kms_arn,
        identity=identity,
        secret="123456",
    )
    events = []
    executor = LocalLambdaInvoker(
        lookup=lambda _: descriptor,
        invoke=lambda _arn, event: events.append(event) or event,
    )
    invoke_custom_sender(
        executor,
        function_arn=function_arn,
        identity=identity,
        medium="SMS",
        trigger_source="CustomSMSSender_Authentication",
        encrypted_code=encrypted,
        user_attributes={"phone_number": "+12065550123"},
        client_metadata={"channel": "mobile"},
    )
    assert events[0]["request"]["type"] == "customSMSSenderRequestV1"
    assert base64.b64decode(events[0]["request"]["code"]) != b"123456"
    assert "123456" not in json.dumps(events[0])
    executor.close()


def test_custom_sender_encryption_rejects_wrong_or_disabled_local_key(identity):
    kms_arn = f"arn:{identity.partition}:kms:{identity.region}:{identity.account_id}:key/key-id"
    calls = []
    adapter = EncryptionAdapter(
        describe=lambda _: {"Arn": kms_arn, "Enabled": False},
        encrypt=lambda *args: calls.append(args),
    )
    with pytest.raises(LambdaTriggerError, match="KMS"):
        encrypt_custom_sender_secret(
            adapter,
            kms_key_arn=kms_arn,
            identity=identity,
            secret="123456",
        )
    assert calls == []


def test_custom_email_sender_has_official_type_and_allows_no_return(
    identity, function_arn, descriptor
):
    events = []
    executor = LocalLambdaInvoker(
        lookup=lambda _: descriptor,
        invoke=lambda _arn, event: events.append(event),
    )
    invoke_custom_sender(
        executor,
        function_arn=function_arn,
        identity=identity,
        medium="EMAIL",
        trigger_source="CustomEmailSender_AccountTakeOverNotification",
        encrypted_code=base64.b64encode(b"opaque-ciphertext").decode(),
        user_attributes={"email": "alice@example.test"},
        client_metadata={},
    )
    assert events[0]["request"]["type"] == "customEmailSenderRequestV1"
    executor.close()


def test_inbound_federation_maps_bounded_attributes_and_empty_is_noop(
    identity, function_arn, descriptor
):
    def transform(_arn, event):
        event["response"] = {
            "userAttributesToMap": {"email": "alice@example.test", "custom:tier": "pro"}
        }
        return event

    executor = LocalLambdaInvoker(lookup=lambda _: descriptor, invoke=transform)
    mapped = invoke_inbound_federation(
        executor,
        function_arn=function_arn,
        identity=identity,
        provider_name="ExampleOIDC",
        provider_type="OIDC",
        attributes={
            "idToken": {"sub": "external-sub", "email": "alice@example.test"},
            "tokenResponse": {"access_token": "ephemeral-token", "token_type": "Bearer"},
            "userInfo": {"name": "Alice"},
        },
        original_attributes={"email": "old@example.test"},
    )
    assert mapped == {"email": "alice@example.test", "custom:tier": "pro"}
    executor.close()


def test_pre_token_v2_v3_claims_and_scopes_are_strict(identity, function_arn, descriptor):
    def override(_arn, event):
        event["response"] = {
            "claimsAndScopeOverrideDetails": {
                "accessTokenGeneration": {
                    "claimsToAddOrOverride": {"tenant": "acme"},
                    "claimsToSuppress": ["legacy"],
                    "scopesToAdd": ["orders/read"],
                    "scopesToSuppress": ["orders/write"],
                },
                "idTokenGeneration": {
                    "claimsToAddOrOverride": {"preferences": {"locale": "pt-BR"}},
                    "claimsToSuppress": [],
                },
            }
        }
        return event

    executor = LocalLambdaInvoker(lookup=lambda _: descriptor, invoke=override)
    result = invoke_pre_token_generation(
        executor,
        function_arn=function_arn,
        identity=identity,
        lambda_version="V2_0",
        trigger_source="TokenGeneration_Authentication",
        user_attributes={"sub": "user-sub"},
        groups=[],
        scopes=["orders/read", "orders/write"],
        client_metadata={"tenant": "acme"},
        machine_identity=False,
    )
    assert result.access_claims_to_add == {"tenant": "acme"}
    assert result.scopes_to_add == ("orders/read",)
    assert result.id_claims_to_add["preferences"] == {"locale": "pt-BR"}
    executor.close()


def test_pre_token_v1_and_v3_machine_events_use_distinct_contracts(
    identity, function_arn, descriptor
):
    versions = []

    def override(_arn, event):
        versions.append(event["version"])
        key = (
            "claimsOverrideDetails"
            if event["version"] == "1"
            else ("claimsAndScopeOverrideDetails")
        )
        event["response"] = {key: {}}
        return event

    executor = LocalLambdaInvoker(lookup=lambda _: descriptor, invoke=override)
    v1 = invoke_pre_token_generation(
        executor,
        function_arn=function_arn,
        identity=identity,
        lambda_version="V1_0",
        trigger_source="TokenGeneration_Authentication",
        user_attributes={"sub": "user-sub"},
        groups=[],
        scopes=[],
        client_metadata={},
        machine_identity=False,
    )
    v3 = invoke_pre_token_generation(
        executor,
        function_arn=function_arn,
        identity=identity,
        lambda_version="V3_0",
        trigger_source="TokenGeneration_ClientCredentials",
        user_attributes={},
        groups=[],
        scopes=["orders/read"],
        client_metadata={"tenant": "acme"},
        machine_identity=True,
    )
    assert versions == ["1", "3"]
    assert v1.access_claims_to_add == {}
    assert v3.scopes_to_add == ()
    executor.close()


def test_pre_token_protected_claim_override_fails_closed(identity, function_arn, descriptor):
    def override(_arn, event):
        event["response"] = {
            "claimsAndScopeOverrideDetails": {
                "accessTokenGeneration": {
                    "claimsToAddOrOverride": {"iss": "https://attacker.invalid"}
                }
            }
        }
        return event

    executor = LocalLambdaInvoker(lookup=lambda _: descriptor, invoke=override)
    with pytest.raises(LambdaTriggerError, match="Protected"):
        invoke_pre_token_generation(
            executor,
            function_arn=function_arn,
            identity=identity,
            lambda_version="V2_0",
            trigger_source="TokenGeneration_Authentication",
            user_attributes={"sub": "user-sub"},
            groups=[],
            scopes=[],
            client_metadata={},
            machine_identity=False,
        )
    executor.close()

    executor = LocalLambdaInvoker(lookup=lambda _: descriptor, invoke=override)
    with pytest.raises(LambdaTriggerError, match="V3_0"):
        invoke_pre_token_generation(
            executor,
            function_arn=function_arn,
            identity=identity,
            lambda_version="V2_0",
            trigger_source="TokenGeneration_ClientCredentials",
            user_attributes={},
            groups=[],
            scopes=["orders/read"],
            client_metadata={},
            machine_identity=True,
        )
    executor.close()
