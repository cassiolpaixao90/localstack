import base64
import binascii
import copy
import dataclasses
import hmac
import json
import re
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Any

MAX_LAMBDA_EVENT_BYTES = 900_000
MAX_LAMBDA_RESPONSE_BYTES = 1_000_000
MAX_METADATA_BYTES = 16_384
MAX_ATTRIBUTES = 50
MAX_CLAIMS = 128
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
_ACCOUNT = re.compile(r"[0-9]{12}")
_POOL = re.compile(r"[\w-]+_[0-9A-Za-z]+")
_CLIENT = re.compile(r"[\w+-]{1,128}")
_SIMPLE_TRIGGERS = {
    "CreateAuthChallenge",
    "CustomMessage",
    "DefineAuthChallenge",
    "PostAuthentication",
    "PostConfirmation",
    "PreAuthentication",
    "PreSignUp",
    "PreTokenGeneration",
    "UserMigration",
    "VerifyAuthChallengeResponse",
}
_NESTED_TRIGGERS = {"CustomEmailSender", "CustomSMSSender", "InboundFederation"}
_CONFIG_FIELDS = (
    _SIMPLE_TRIGGERS
    | _NESTED_TRIGGERS
    | {
        "KMSKeyID",
        "PreTokenGenerationConfig",
    }
)
_CUSTOM_MESSAGE_SOURCES = {
    "CustomMessage_AdminCreateUser",
    "CustomMessage_Authentication",
    "CustomMessage_ForgotPassword",
    "CustomMessage_ResendCode",
    "CustomMessage_SignUp",
    "CustomMessage_UpdateUserAttribute",
    "CustomMessage_VerifyUserAttribute",
}
_CUSTOM_SENDER_SUFFIXES = {
    "AccountTakeOverNotification",
    "AdminCreateUser",
    "Authentication",
    "ForgotPassword",
    "ResendCode",
    "SignUp",
    "UpdateUserAttribute",
    "VerifyUserAttribute",
}
_TOKEN_SOURCES = {
    "TokenGeneration_AuthenticateDevice",
    "TokenGeneration_Authentication",
    "TokenGeneration_ClientCredentials",
    "TokenGeneration_HostedAuth",
    "TokenGeneration_NewPasswordChallenge",
    "TokenGeneration_RefreshTokens",
}
_PROTECTED_CLAIMS = {
    "acr",
    "amr",
    "at_hash",
    "auth_time",
    "azp",
    "client_id",
    "device_key",
    "event_id",
    "exp",
    "iat",
    "iss",
    "jti",
    "nbf",
    "nonce",
    "origin_jti",
    "sub",
    "token_use",
    "username",
    "version",
}
_METADATA_FIELDS = {"AnalyticsMetadata", "ClientMetadata", "ContextData", "UserContextData"}
_OPERATION_METADATA = {
    "AdminConfirmSignUp": {"ClientMetadata"},
    "AdminInitiateAuth": {"AnalyticsMetadata", "ClientMetadata", "ContextData"},
    "AdminResetUserPassword": {"ClientMetadata"},
    "AdminRespondToAuthChallenge": {"AnalyticsMetadata", "ClientMetadata", "ContextData"},
    "AdminUpdateUserAttributes": {"ClientMetadata"},
    "ConfirmForgotPassword": {"AnalyticsMetadata", "ClientMetadata", "UserContextData"},
    "ConfirmSignUp": {"AnalyticsMetadata", "ClientMetadata", "UserContextData"},
    "ForgotPassword": {"AnalyticsMetadata", "ClientMetadata", "UserContextData"},
    "GetUserAttributeVerificationCode": {"ClientMetadata"},
    "InitiateAuth": {"AnalyticsMetadata", "ClientMetadata", "UserContextData"},
    "ResendConfirmationCode": {"AnalyticsMetadata", "ClientMetadata", "UserContextData"},
    "RespondToAuthChallenge": {"AnalyticsMetadata", "ClientMetadata", "UserContextData"},
    "SignUp": {"AnalyticsMetadata", "ClientMetadata", "UserContextData"},
    "UpdateUserAttributes": {"ClientMetadata"},
}
_TRIGGER_METADATA_OPERATIONS = {
    "CustomAuth": {"AdminRespondToAuthChallenge", "RespondToAuthChallenge"},
    "CustomMessage": {
        "AdminResetUserPassword",
        "AdminRespondToAuthChallenge",
        "AdminUpdateUserAttributes",
        "ForgotPassword",
        "GetUserAttributeVerificationCode",
        "ResendConfirmationCode",
        "SignUp",
        "UpdateUserAttributes",
    },
    "CustomSender": {
        "AdminRespondToAuthChallenge",
        "ForgotPassword",
        "RespondToAuthChallenge",
        "SignUp",
    },
    "PostAuthentication": {"AdminRespondToAuthChallenge", "RespondToAuthChallenge"},
    "PostConfirmation": {"AdminConfirmSignUp", "ConfirmForgotPassword", "ConfirmSignUp"},
    "PreAuthentication": {"AdminInitiateAuth", "InitiateAuth"},
    "PreTokenGeneration": {"AdminRespondToAuthChallenge", "RespondToAuthChallenge"},
    "UserMigration": {
        "AdminInitiateAuth",
        "AdminRespondToAuthChallenge",
        "ForgotPassword",
        "InitiateAuth",
    },
}


class LambdaTriggerError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class TriggerIdentity:
    partition: str
    account_id: str
    region: str
    pool_id: str
    client_id: str
    username: str

    def __post_init__(self) -> None:
        if (
            self.partition not in {"aws", "aws-cn", "aws-iso", "aws-iso-b", "aws-us-gov"}
            or _ACCOUNT.fullmatch(self.account_id) is None
            or _REGION.fullmatch(self.region) is None
            or _POOL.fullmatch(self.pool_id) is None
            or not self.pool_id.startswith(f"{self.region}_")
            or _CLIENT.fullmatch(self.client_id) is None
            or not isinstance(self.username, str)
            or not 1 <= len(self.username) <= 128
        ):
            _invalid("Invalid Lambda trigger identity")

    @property
    def pool_arn(self) -> str:
        return (
            f"arn:{self.partition}:cognito-idp:{self.region}:{self.account_id}:"
            f"userpool/{self.pool_id}"
        )


@dataclasses.dataclass(frozen=True)
class LambdaTriggerConfiguration:
    functions: tuple[tuple[str, str], ...]
    pre_token_version: str
    kms_key_arn: str | None

    def lambda_arn(self, trigger: str) -> str | None:
        return dict(self.functions).get(trigger)


@dataclasses.dataclass(frozen=True)
class LambdaPermission:
    action: str
    principal: str
    source_arn: str
    source_account: str


@dataclasses.dataclass(frozen=True)
class LambdaFunctionDescriptor:
    function_arn: str
    state: str
    timeout_seconds: int
    permissions: tuple[LambdaPermission, ...]


@dataclasses.dataclass(frozen=True)
class OperationMetadata:
    operation: str
    client_metadata: dict[str, str]
    analytics_metadata: dict[str, str] = dataclasses.field(repr=False)
    user_context_data: dict[str, Any] = dataclasses.field(repr=False)
    context_data: dict[str, Any] = dataclasses.field(repr=False)

    def client_metadata_for(self, trigger: str) -> dict[str, str]:
        if self.operation not in _TRIGGER_METADATA_OPERATIONS.get(trigger, set()):
            return {}
        return dict(self.client_metadata)

    def risk_context(self) -> dict[str, Any]:
        context = self.context_data or self.user_context_data
        result = copy.deepcopy(context)
        endpoint = self.analytics_metadata.get("AnalyticsEndpointId")
        if endpoint is not None:
            result["AnalyticsEndpointId"] = endpoint
        return result


@dataclasses.dataclass(frozen=True)
class CustomMessageResult:
    sms_message: str | None
    email_message: str | None
    email_subject: str | None


@dataclasses.dataclass(frozen=True)
class UserMigrationResult:
    user_attributes: dict[str, str]
    final_user_status: str
    message_action: str | None
    desired_delivery_mediums: tuple[str, ...]
    force_alias_creation: bool
    enable_sms_mfa: bool


@dataclasses.dataclass(frozen=True)
class PreTokenGenerationResult:
    id_claims_to_add: dict[str, Any]
    id_claims_to_suppress: tuple[str, ...]
    access_claims_to_add: dict[str, Any]
    access_claims_to_suppress: tuple[str, ...]
    scopes_to_add: tuple[str, ...]
    scopes_to_suppress: tuple[str, ...]
    groups_to_override: tuple[str, ...] | None
    iam_roles_to_override: tuple[str, ...] | None
    preferred_role: str | None


@dataclasses.dataclass(frozen=True)
class EncryptionAdapter:
    describe: Callable[[str], Mapping[str, Any]] = dataclasses.field(repr=False)
    encrypt: Callable[[str, bytes, Mapping[str, str]], bytes] = dataclasses.field(repr=False)


class LocalLambdaInvoker:
    def __init__(
        self,
        *,
        lookup: Callable[[str], LambdaFunctionDescriptor],
        invoke: Callable[[str, dict[str, Any]], Any],
        maximum_concurrency: int = 16,
        invocation_timeout_seconds: float = 5,
    ):
        if (
            not callable(lookup)
            or not callable(invoke)
            or not isinstance(maximum_concurrency, int)
            or isinstance(maximum_concurrency, bool)
            or not 1 <= maximum_concurrency <= 256
            or not isinstance(invocation_timeout_seconds, (int, float))
            or isinstance(invocation_timeout_seconds, bool)
            or not 0 < invocation_timeout_seconds <= 5
        ):
            _invalid("Invalid local Lambda invoker")
        self._lookup = lookup
        self._invoke = invoke
        self._timeout = float(invocation_timeout_seconds)
        self._admission = threading.BoundedSemaphore(maximum_concurrency)
        self._executor = ThreadPoolExecutor(
            max_workers=maximum_concurrency,
            thread_name_prefix="cognito-lambda-trigger",
        )
        self._closed = False
        self._lock = threading.Lock()

    def invoke(
        self,
        function_arn: str,
        identity: TriggerIdentity,
        event: Mapping[str, Any],
        *,
        allow_none: bool = False,
    ) -> dict[str, Any] | None:
        _lambda_arn(function_arn, identity)
        try:
            descriptor = self._lookup(function_arn)
        except Exception as error:
            raise LambdaTriggerError(
                "InvalidParameterException", "Local Lambda function could not be resolved"
            ) from error
        _validate_lambda_descriptor(descriptor, function_arn, identity)
        safe_event = _json_copy(event, "Lambda event", MAX_LAMBDA_EVENT_BYTES)
        with self._lock:
            if self._closed:
                _unexpected("Local Lambda invoker is closed")
        if not self._admission.acquire(blocking=False):
            raise LambdaTriggerError(
                "TooManyRequestsException", "Local Lambda trigger capacity exhausted"
            )
        try:
            future = self._executor.submit(self._invoke, function_arn, safe_event)
        except Exception as error:
            self._admission.release()
            raise LambdaTriggerError(
                "UnexpectedLambdaException", "Local Lambda trigger submission failed"
            ) from error
        future.add_done_callback(lambda _: self._admission.release())
        try:
            returned = future.result(timeout=self._timeout)
        except TimeoutError as error:
            future.cancel()
            raise LambdaTriggerError(
                "UnexpectedLambdaException", "Local Lambda trigger timed out"
            ) from error
        except LambdaTriggerError:
            raise
        except Exception as error:
            raise LambdaTriggerError(
                "UnexpectedLambdaException", "Local Lambda trigger invocation failed"
            ) from error
        if returned is None and allow_none:
            return None
        if not isinstance(returned, Mapping):
            _lambda_error("Invalid Lambda trigger response")
        return _json_copy(returned, "Lambda response", MAX_LAMBDA_RESPONSE_BYTES)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)


def parse_lambda_configuration(
    value: Any, *, identity: TriggerIdentity
) -> LambdaTriggerConfiguration:
    if not isinstance(identity, TriggerIdentity):
        _invalid("Invalid LambdaConfig identity")
    if not isinstance(value, Mapping) or not value or set(value) - _CONFIG_FIELDS:
        _invalid("Invalid LambdaConfig")
    functions: dict[str, str] = {}
    for trigger in _SIMPLE_TRIGGERS:
        if trigger in value:
            functions[trigger] = _lambda_arn(value[trigger], identity)
    for trigger in _NESTED_TRIGGERS:
        if trigger not in value:
            continue
        nested = value[trigger]
        if (
            not isinstance(nested, Mapping)
            or set(nested) != {"LambdaArn", "LambdaVersion"}
            or nested.get("LambdaVersion") != "V1_0"
        ):
            _invalid(f"Invalid LambdaConfig {trigger}")
        functions[trigger] = _lambda_arn(nested.get("LambdaArn"), identity)
    version = "V1_0"
    if "PreTokenGenerationConfig" in value:
        if "PreTokenGeneration" in value:
            _invalid("LambdaConfig PreTokenGeneration forms are mutually exclusive")
        nested = value["PreTokenGenerationConfig"]
        if (
            not isinstance(nested, Mapping)
            or set(nested) != {"LambdaArn", "LambdaVersion"}
            or nested.get("LambdaVersion") not in {"V1_0", "V2_0", "V3_0"}
        ):
            _invalid("Invalid LambdaConfig PreTokenGenerationConfig")
        version = nested["LambdaVersion"]
        functions["PreTokenGeneration"] = _lambda_arn(nested.get("LambdaArn"), identity)
    kms_arn = None
    if "KMSKeyID" in value:
        kms_arn = _kms_arn(value["KMSKeyID"], identity)
    if {"CustomEmailSender", "CustomSMSSender"}.intersection(value) and kms_arn is None:
        _invalid("LambdaConfig custom senders require KMSKeyID")
    return LambdaTriggerConfiguration(
        functions=tuple(sorted(functions.items())),
        pre_token_version=version,
        kms_key_arn=kms_arn,
    )


def build_operation_metadata(operation: Any, request: Any) -> OperationMetadata:
    if operation not in _OPERATION_METADATA or not isinstance(request, Mapping):
        _invalid("Invalid operation metadata")
    supplied = set(request).intersection(_METADATA_FIELDS)
    if supplied - _OPERATION_METADATA[operation]:
        _invalid("Unsupported operation metadata")
    client = _metadata_map(request.get("ClientMetadata", {}), "ClientMetadata")
    analytics = _analytics_metadata(request.get("AnalyticsMetadata"))
    user_context = _user_context(request.get("UserContextData"))
    context = _admin_context(request.get("ContextData"))
    return OperationMetadata(
        operation=operation,
        client_metadata=client,
        analytics_metadata=analytics,
        user_context_data=user_context,
        context_data=context,
    )


def invoke_authentication_trigger(
    executor: LocalLambdaInvoker,
    *,
    function_arn: str,
    identity: TriggerIdentity,
    phase: str,
    user_attributes: Mapping[str, str],
    client_metadata: Mapping[str, str],
    user_not_found: bool = False,
    new_device_used: bool = False,
) -> dict[str, Any]:
    attributes = _attribute_map(user_attributes, "userAttributes")
    metadata = _metadata_map(client_metadata, "ClientMetadata")
    if phase == "PRE":
        if not isinstance(user_not_found, bool):
            _invalid("Invalid PreAuthentication userNotFound")
        request = {
            "userAttributes": attributes,
            "validationData": metadata,
            "userNotFound": user_not_found,
        }
        source = "PreAuthentication_Authentication"
    elif phase == "POST":
        if not isinstance(new_device_used, bool):
            _invalid("Invalid PostAuthentication newDeviceUsed")
        request = {
            "userAttributes": attributes,
            "newDeviceUsed": new_device_used,
            "clientMetadata": metadata,
        }
        source = "PostAuthentication_Authentication"
    else:
        _invalid("Invalid authentication trigger phase")
    event = _event(identity, source, request)
    returned = executor.invoke(function_arn, identity, event)
    _unchanged_event(returned, event, allowed_response=set())
    return returned


def invoke_custom_message(
    executor: LocalLambdaInvoker,
    *,
    function_arn: str,
    identity: TriggerIdentity,
    trigger_source: str,
    user_attributes: Mapping[str, str],
    code_parameter: Any,
    username_parameter: Any,
    client_metadata: Mapping[str, str],
    email_sending_account: Any,
) -> CustomMessageResult:
    if trigger_source not in _CUSTOM_MESSAGE_SOURCES:
        _invalid("Invalid CustomMessage trigger source")
    code = _text(code_parameter, "codeParameter", 1, 128)
    username = None
    if username_parameter is not None:
        username = _text(username_parameter, "usernameParameter", 1, 128)
    if trigger_source == "CustomMessage_AdminCreateUser" and username is None:
        _invalid("CustomMessage_AdminCreateUser requires usernameParameter")
    request = {
        "userAttributes": _attribute_map(user_attributes, "userAttributes"),
        "codeParameter": code,
        "clientMetadata": _metadata_map(client_metadata, "ClientMetadata"),
    }
    if username is not None:
        request["usernameParameter"] = username
    event = _event(identity, trigger_source, request)
    returned = executor.invoke(function_arn, identity, event)
    response = _unchanged_event(
        returned,
        event,
        allowed_response={"emailMessage", "emailSubject", "smsMessage"},
    )
    sms = _optional_text(response.get("smsMessage"), "smsMessage", 140)
    email = _optional_text(response.get("emailMessage"), "emailMessage", 20_000)
    subject = _optional_text(response.get("emailSubject"), "emailSubject", 140)
    for message in (sms, email):
        if message is not None and code not in message:
            _lambda_error("CustomMessage response must contain codeParameter")
    if trigger_source == "CustomMessage_AdminCreateUser":
        for message in (sms, email):
            if message is not None and username not in message:
                _lambda_error("CustomMessage response must contain usernameParameter")
    if email_sending_account not in {"COGNITO_DEFAULT", "DEVELOPER"}:
        _invalid("Invalid EmailSendingAccount")
    if email_sending_account != "DEVELOPER" and (email is not None or subject is not None):
        _lambda_error("CustomMessage email response requires DEVELOPER EmailSendingAccount")
    return CustomMessageResult(sms_message=sms, email_message=email, email_subject=subject)


def invoke_user_migration(
    executor: LocalLambdaInvoker,
    *,
    function_arn: str,
    identity: TriggerIdentity,
    trigger_source: str,
    password: Any,
    validation_data: Mapping[str, str],
    client_metadata: Mapping[str, str],
) -> UserMigrationResult:
    if trigger_source not in {"UserMigration_Authentication", "UserMigration_ForgotPassword"}:
        _invalid("Invalid UserMigration trigger source")
    request: dict[str, Any] = {
        "validationData": _metadata_map(validation_data, "ValidationData"),
        "clientMetadata": _metadata_map(client_metadata, "ClientMetadata"),
    }
    if trigger_source == "UserMigration_Authentication":
        request["password"] = _text(password, "password", 1, 256)
    elif password is not None:
        _invalid("Forgot-password migration cannot include a password")
    event = _event(identity, trigger_source, request)
    returned = executor.invoke(function_arn, identity, event)
    allowed = {
        "desiredDeliveryMediums",
        "enableSMSMFA",
        "finalUserStatus",
        "forceAliasCreation",
        "messageAction",
        "userAttributes",
    }
    response = _unchanged_event(returned, event, allowed_response=allowed)
    if "userAttributes" not in response:
        _lambda_error("UserMigration response requires userAttributes")
    attributes = _attribute_map(response["userAttributes"], "userAttributes")
    if not attributes:
        _lambda_error("UserMigration response requires userAttributes")
    status = response.get("finalUserStatus", "RESET_REQUIRED")
    if status not in {"CONFIRMED", "RESET_REQUIRED"}:
        _lambda_error("Invalid UserMigration finalUserStatus")
    action = response.get("messageAction")
    if action not in {None, "SUPPRESS"}:
        _lambda_error("Invalid UserMigration messageAction")
    media = response.get("desiredDeliveryMediums", ["SMS"])
    if (
        not isinstance(media, list)
        or not 1 <= len(media) <= 2
        or len(media) != len(set(media))
        or set(media) - {"EMAIL", "SMS"}
    ):
        _lambda_error("Invalid UserMigration desiredDeliveryMediums")
    force_alias = response.get("forceAliasCreation", False)
    sms_mfa = response.get("enableSMSMFA", False)
    if not isinstance(force_alias, bool) or not isinstance(sms_mfa, bool):
        _lambda_error("Invalid UserMigration Boolean response")
    if sms_mfa and "phone_number" not in attributes:
        _lambda_error("UserMigration SMS MFA requires phone_number")
    return UserMigrationResult(
        user_attributes=attributes,
        final_user_status=status,
        message_action=action,
        desired_delivery_mediums=tuple(media),
        force_alias_creation=force_alias,
        enable_sms_mfa=sms_mfa,
    )


def encrypt_custom_sender_secret(
    adapter: EncryptionAdapter,
    *,
    kms_key_arn: Any,
    identity: TriggerIdentity,
    secret: Any,
) -> str:
    if not isinstance(adapter, EncryptionAdapter):
        _invalid("Invalid custom-sender encryption adapter")
    arn = _kms_arn(kms_key_arn, identity)
    plaintext = _text(secret, "custom sender secret", 1, 2048).encode()
    try:
        descriptor = adapter.describe(arn)
    except Exception as error:
        raise LambdaTriggerError(
            "InvalidParameterException", "KMSKeyID could not be validated locally"
        ) from error
    if (
        not isinstance(descriptor, Mapping)
        or descriptor.get("Arn") != arn
        or descriptor.get("Enabled") is not True
        or descriptor.get("KeySpec") != "SYMMETRIC_DEFAULT"
        or descriptor.get("KeyUsage") != "ENCRYPT_DECRYPT"
        or descriptor.get("Owner") != identity.account_id
    ):
        _invalid("KMSKeyID must identify an enabled local symmetric KMS key")
    grants = descriptor.get("Grants")
    if (
        not isinstance(grants, list)
        or len(grants) > 100
        or not any(
            isinstance(grant, Mapping)
            and grant.get("GranteePrincipal") == "cognito-idp.amazonaws.com"
            and "GenerateDataKey" in grant.get("Operations", [])
            and grant.get("EncryptionContext") == {"userpool-id": identity.pool_id}
            for grant in grants
        )
    ):
        _invalid("KMSKeyID has no scoped Cognito encryption grant")
    encryption_context = {"userpool-id": identity.pool_id}
    try:
        ciphertext = adapter.encrypt(arn, plaintext, encryption_context)
    except Exception as error:
        raise LambdaTriggerError(
            "InvalidParameterException", "KMS custom-sender encryption failed"
        ) from error
    if (
        not isinstance(ciphertext, bytes)
        or not 16 <= len(ciphertext) <= MAX_LAMBDA_EVENT_BYTES
        or hmac.compare_digest(ciphertext, plaintext)
        or plaintext in ciphertext
    ):
        _invalid("KMS custom-sender encryption returned invalid ciphertext")
    return base64.b64encode(ciphertext).decode()


def invoke_custom_sender(
    executor: LocalLambdaInvoker,
    *,
    function_arn: str,
    identity: TriggerIdentity,
    medium: str,
    trigger_source: str,
    encrypted_code: Any,
    user_attributes: Mapping[str, str],
    client_metadata: Mapping[str, str],
) -> None:
    if medium not in {"EMAIL", "SMS"}:
        _invalid("Invalid custom sender medium")
    prefix = "CustomEmailSender" if medium == "EMAIL" else "CustomSMSSender"
    if trigger_source not in {f"{prefix}_{suffix}" for suffix in _CUSTOM_SENDER_SUFFIXES}:
        _invalid("Invalid custom sender trigger source")
    if not isinstance(encrypted_code, str) or not 1 <= len(encrypted_code) <= 1_300_000:
        _invalid("Invalid encrypted custom sender code")
    try:
        decoded = base64.b64decode(encrypted_code, validate=True)
    except (binascii.Error, ValueError) as error:
        raise LambdaTriggerError(
            "InvalidParameterException", "Invalid encrypted sender code"
        ) from error
    if not 16 <= len(decoded) <= MAX_LAMBDA_EVENT_BYTES:
        _invalid("Invalid encrypted custom sender code")
    event = _event(
        identity,
        trigger_source,
        {
            "type": (
                "customEmailSenderRequestV1" if medium == "EMAIL" else "customSMSSenderRequestV1"
            ),
            "code": encrypted_code,
            "clientMetadata": _metadata_map(client_metadata, "ClientMetadata"),
            "userAttributes": _attribute_map(user_attributes, "userAttributes"),
        },
    )
    returned = executor.invoke(function_arn, identity, event, allow_none=True)
    if returned is not None:
        _unchanged_event(returned, event, allowed_response=set())


def invoke_inbound_federation(
    executor: LocalLambdaInvoker,
    *,
    function_arn: str,
    identity: TriggerIdentity,
    provider_name: Any,
    provider_type: Any,
    attributes: Any,
    original_attributes: Mapping[str, str],
) -> dict[str, str]:
    provider_name = _text(provider_name, "providerName", 1, 128)
    if provider_type not in {
        "Facebook",
        "Google",
        "LoginWithAmazon",
        "OIDC",
        "SAML",
        "SignInWithApple",
    }:
        _invalid("Invalid inbound federation providerType")
    safe_attributes = _json_copy(attributes, "inbound federation attributes", 512_000)
    if not isinstance(safe_attributes, dict) or len(safe_attributes) > 8:
        _invalid("Invalid inbound federation attributes")
    original = _attribute_map(original_attributes, "originalAttributes")
    event = _event(
        identity,
        "InboundFederation_ExternalProvider",
        {
            "providerName": provider_name,
            "providerType": provider_type,
            "attributes": safe_attributes,
        },
    )
    returned = executor.invoke(function_arn, identity, event)
    response = _unchanged_event(returned, event, allowed_response={"userAttributesToMap"})
    if "userAttributesToMap" not in response:
        _lambda_error("InboundFederation response requires userAttributesToMap")
    mapped = _attribute_map(response["userAttributesToMap"], "userAttributesToMap")
    return original if not mapped else mapped


def invoke_pre_token_generation(
    executor: LocalLambdaInvoker,
    *,
    function_arn: str,
    identity: TriggerIdentity,
    lambda_version: str,
    trigger_source: str,
    user_attributes: Mapping[str, str],
    groups: Any,
    scopes: Any,
    client_metadata: Mapping[str, str],
    machine_identity: bool,
) -> PreTokenGenerationResult:
    if lambda_version not in {"V1_0", "V2_0", "V3_0"} or trigger_source not in _TOKEN_SOURCES:
        _invalid("Invalid PreTokenGeneration configuration")
    if not isinstance(machine_identity, bool):
        _invalid("Invalid PreTokenGeneration identity type")
    if machine_identity and (
        lambda_version != "V3_0" or trigger_source != "TokenGeneration_ClientCredentials"
    ):
        _invalid("Machine tokens require PreTokenGeneration V3_0")
    if not machine_identity and trigger_source == "TokenGeneration_ClientCredentials":
        _invalid("ClientCredentials trigger requires a machine identity")
    group_list = _string_list(groups, "groups", 100, 128)
    scope_list = _scope_list(scopes, "scopes")
    request: dict[str, Any] = {
        "userAttributes": _attribute_map(user_attributes, "userAttributes"),
        "groupConfiguration": {
            "groupsToOverride": list(group_list),
            "iamRolesToOverride": [],
            "preferredRole": None,
        },
        "clientMetadata": _metadata_map(client_metadata, "ClientMetadata"),
    }
    if lambda_version in {"V2_0", "V3_0"}:
        request["scopes"] = list(scope_list)
    event = _event(identity, trigger_source, request, version=lambda_version[1])
    returned = executor.invoke(function_arn, identity, event)
    response = _unchanged_event(
        returned,
        event,
        allowed_response={
            "claimsOverrideDetails" if lambda_version == "V1_0" else "claimsAndScopeOverrideDetails"
        },
    )
    key = "claimsOverrideDetails" if lambda_version == "V1_0" else "claimsAndScopeOverrideDetails"
    details = response.get(key, {})
    if not isinstance(details, Mapping):
        _lambda_error("Invalid PreTokenGeneration response")
    if lambda_version == "V1_0":
        if set(details) - {"claimsToAddOrOverride", "claimsToSuppress", "groupOverrideDetails"}:
            _lambda_error("Invalid PreTokenGeneration V1 response")
        id_add = _claims(details.get("claimsToAddOrOverride", {}), identity, complex_values=False)
        id_suppress = _claim_names(details.get("claimsToSuppress", []))
        access_add: dict[str, Any] = {}
        access_suppress: tuple[str, ...] = ()
        scopes_add: tuple[str, ...] = ()
        scopes_suppress: tuple[str, ...] = ()
        group_override = details.get("groupOverrideDetails")
    else:
        if set(details) - {"accessTokenGeneration", "groupOverrideDetails", "idTokenGeneration"}:
            _lambda_error("Invalid PreTokenGeneration advanced response")
        identifier = _token_generation_block(details.get("idTokenGeneration", {}), identity)
        access = _token_generation_block(
            details.get("accessTokenGeneration", {}), identity, access=True
        )
        id_add, id_suppress = identifier[0], identifier[1]
        access_add, access_suppress = access[0], access[1]
        scopes_add, scopes_suppress = access[2], access[3]
        group_override = details.get("groupOverrideDetails")
    groups_override, roles_override, preferred_role = _group_override(group_override)
    return PreTokenGenerationResult(
        id_claims_to_add=id_add,
        id_claims_to_suppress=id_suppress,
        access_claims_to_add=access_add,
        access_claims_to_suppress=access_suppress,
        scopes_to_add=scopes_add,
        scopes_to_suppress=scopes_suppress,
        groups_to_override=groups_override,
        iam_roles_to_override=roles_override,
        preferred_role=preferred_role,
    )


def _event(
    identity: TriggerIdentity,
    trigger_source: str,
    request: dict[str, Any],
    *,
    version: str = "1",
) -> dict[str, Any]:
    return {
        "version": version,
        "triggerSource": trigger_source,
        "region": identity.region,
        "userPoolId": identity.pool_id,
        "userName": identity.username,
        "callerContext": {"awsSdkVersion": "localstack", "clientId": identity.client_id},
        "request": request,
        "response": {},
    }


def _unchanged_event(
    returned: Any, original: dict[str, Any], *, allowed_response: set[str]
) -> dict[str, Any]:
    if not isinstance(returned, dict) or set(returned) != set(original):
        _lambda_error("Lambda trigger must return the complete event")
    for key, value in original.items():
        if key != "response" and returned.get(key) != value:
            _lambda_error("Lambda trigger modified immutable event fields")
    response = returned.get("response")
    if not isinstance(response, dict) or set(response) - allowed_response:
        _lambda_error("Invalid Lambda trigger response shape")
    return response


def _validate_lambda_descriptor(
    descriptor: Any, function_arn: str, identity: TriggerIdentity
) -> None:
    if (
        not isinstance(descriptor, LambdaFunctionDescriptor)
        or descriptor.function_arn != function_arn
        or descriptor.state != "Active"
        or not isinstance(descriptor.timeout_seconds, int)
        or isinstance(descriptor.timeout_seconds, bool)
        or not 1 <= descriptor.timeout_seconds <= 900
        or not isinstance(descriptor.permissions, tuple)
        or len(descriptor.permissions) > 100
    ):
        _invalid("Invalid local Lambda function descriptor")
    allowed = any(
        isinstance(permission, LambdaPermission)
        and permission.action == "lambda:InvokeFunction"
        and permission.principal == "cognito-idp.amazonaws.com"
        and permission.source_arn == identity.pool_arn
        and permission.source_account == identity.account_id
        for permission in descriptor.permissions
    )
    if not allowed:
        raise LambdaTriggerError(
            "InvalidParameterException", "Local Lambda resource policy denies Cognito permission"
        )


def _token_generation_block(
    value: Any, identity: TriggerIdentity, *, access: bool = False
) -> tuple[dict[str, Any], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if not isinstance(value, Mapping):
        _lambda_error("Invalid token generation block")
    allowed = {"claimsToAddOrOverride", "claimsToSuppress"}
    if access:
        allowed |= {"scopesToAdd", "scopesToSuppress"}
    if set(value) - allowed:
        _lambda_error("Invalid token generation block")
    additions = _claims(value.get("claimsToAddOrOverride", {}), identity, complex_values=True)
    suppressions = _claim_names(value.get("claimsToSuppress", []))
    scopes_add = _scope_list(value.get("scopesToAdd", []), "scopesToAdd") if access else ()
    scopes_suppress = (
        _scope_list(value.get("scopesToSuppress", []), "scopesToSuppress") if access else ()
    )
    return additions, suppressions, scopes_add, scopes_suppress


def _claims(value: Any, identity: TriggerIdentity, *, complex_values: bool) -> dict[str, Any]:
    if not isinstance(value, Mapping) or len(value) > MAX_CLAIMS:
        _lambda_error("Invalid token claim overrides")
    result = {}
    for name, item in value.items():
        if not isinstance(name, str) or not 1 <= len(name) <= 128:
            _lambda_error("Invalid token claim name")
        if name in _PROTECTED_CLAIMS or name.startswith("cognito:"):
            _lambda_error("Protected token claim cannot be overridden")
        if name == "aud" and item != identity.client_id:
            _lambda_error("Access-token aud must match the app client")
        if complex_values:
            safe = _json_copy(item, "token claim", 16_384)
        elif not isinstance(item, str) or len(item) > 2048:
            _lambda_error("V1 token claim values must be strings")
        else:
            safe = item
        result[name] = safe
    return result


def _claim_names(value: Any) -> tuple[str, ...]:
    names = _string_list(value, "claimsToSuppress", MAX_CLAIMS, 128)
    if any(name in _PROTECTED_CLAIMS for name in names):
        _lambda_error("Protected token claim cannot be suppressed")
    return names


def _group_override(
    value: Any,
) -> tuple[tuple[str, ...] | None, tuple[str, ...] | None, str | None]:
    if value is None:
        return None, None, None
    if not isinstance(value, Mapping) or set(value) - {
        "groupsToOverride",
        "iamRolesToOverride",
        "preferredRole",
    }:
        _lambda_error("Invalid groupOverrideDetails")
    groups = _string_list(value.get("groupsToOverride", []), "groupsToOverride", 100, 128)
    roles = _string_list(value.get("iamRolesToOverride", []), "iamRolesToOverride", 100, 2048)
    preferred = value.get("preferredRole")
    if preferred is not None:
        preferred = _text(preferred, "preferredRole", 1, 2048)
        if preferred not in roles:
            _lambda_error("preferredRole must be present in iamRolesToOverride")
    return groups, roles, preferred


def _scope_list(value: Any, field: str) -> tuple[str, ...]:
    values = _string_list(value, field, 50, 256)
    if any(any(character.isspace() for character in item) for item in values):
        _lambda_error(f"Invalid {field}")
    return values


def _string_list(value: Any, field: str, maximum: int, item_maximum: int) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or any(not isinstance(item, str) or not 1 <= len(item) <= item_maximum for item in value)
        or len(value) != len(set(value))
    ):
        _lambda_error(f"Invalid {field}")
    return tuple(value)


def _attribute_map(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > MAX_ATTRIBUTES:
        _invalid(f"Invalid {field}")
    result = {}
    for name, item in value.items():
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 128
            or not isinstance(item, str)
            or len(item) > 2048
            or "\x00" in name
            or "\x00" in item
        ):
            _invalid(f"Invalid {field}")
        result[name] = item
    return result


def _metadata_map(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > 32:
        _invalid(f"Invalid {field}")
    result = {}
    total = 0
    for name, item in value.items():
        if (
            not isinstance(name, str)
            or not isinstance(item, str)
            or len(name) > 131_072
            or len(item) > 131_072
            or "\x00" in name
            or "\x00" in item
        ):
            _invalid(f"Invalid {field}")
        total += len(name.encode()) + len(item.encode())
        if total > MAX_METADATA_BYTES:
            _invalid(f"Invalid {field}")
        result[name] = item
    return result


def _analytics_metadata(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or set(value) != {"AnalyticsEndpointId"}:
        _invalid("Invalid AnalyticsMetadata")
    endpoint = value["AnalyticsEndpointId"]
    if not isinstance(endpoint, str) or len(endpoint) > 131_072 or "\x00" in endpoint:
        _invalid("Invalid AnalyticsMetadata")
    return {"AnalyticsEndpointId": endpoint}


def _user_context(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or set(value) - {"EncodedData", "IpAddress"}:
        _invalid("Invalid UserContextData")
    return _bounded_context_strings(value, "UserContextData")


def _admin_context(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    required = {"HttpHeaders", "IpAddress", "ServerName", "ServerPath"}
    if (
        not isinstance(value, Mapping)
        or not required <= set(value)
        or set(value) - (required | {"EncodedData"})
    ):
        _invalid("Invalid ContextData")
    result: dict[str, Any] = _bounded_context_strings(
        {key: item for key, item in value.items() if key != "HttpHeaders"}, "ContextData"
    )
    headers = value["HttpHeaders"]
    if not isinstance(headers, list) or len(headers) > 64:
        _invalid("Invalid ContextData")
    normalized = []
    for header in headers:
        if not isinstance(header, Mapping) or set(header) != {"headerName", "headerValue"}:
            _invalid("Invalid ContextData")
        normalized.append(_bounded_context_strings(header, "ContextData"))
    result["HttpHeaders"] = normalized
    return result


def _bounded_context_strings(value: Mapping[str, Any], field: str) -> dict[str, str]:
    result = {}
    total = 0
    for name, item in value.items():
        if (
            not isinstance(name, str)
            or not isinstance(item, str)
            or len(item) > 131_072
            or "\x00" in name
            or "\x00" in item
        ):
            _invalid(f"Invalid {field}")
        total += len(name.encode()) + len(item.encode())
        if total > 262_144:
            _invalid(f"Invalid {field}")
        result[name] = item
    return result


def _lambda_arn(value: Any, identity: TriggerIdentity) -> str:
    return _scoped_arn(value, identity, "lambda", "function:", "LambdaConfig")


def _kms_arn(value: Any, identity: TriggerIdentity) -> str:
    return _scoped_arn(value, identity, "kms", "key/", "LambdaConfig KMSKeyID")


def _scoped_arn(
    value: Any,
    identity: TriggerIdentity,
    service: str,
    resource_prefix: str,
    field: str,
) -> str:
    if not isinstance(value, str) or not 20 <= len(value) <= 2048:
        _invalid(f"Invalid {field}")
    parts = value.split(":", 5)
    if (
        len(parts) != 6
        or parts[:3] != ["arn", identity.partition, service]
        or parts[3] != identity.region
        or parts[4] != identity.account_id
        or not parts[5].startswith(resource_prefix)
        or len(parts[5]) <= len(resource_prefix)
        or any(character.isspace() for character in value)
    ):
        _invalid(f"Invalid {field}")
    return value


def _json_copy(value: Any, field: str, maximum: int) -> Any:
    try:
        encoded = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        if len(encoded) > maximum:
            _invalid(f"Invalid {field}: size exceeded")
        result = json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as error:
        raise LambdaTriggerError("InvalidParameterException", f"Invalid {field}") from error
    _json_depth(result, 0, field)
    return result


def _json_depth(value: Any, depth: int, field: str) -> None:
    if depth > 16:
        _invalid(f"Invalid {field}: nesting exceeded")
    if isinstance(value, dict):
        if len(value) > 512:
            _invalid(f"Invalid {field}: item count exceeded")
        for key, item in value.items():
            if not isinstance(key, str):
                _invalid(f"Invalid {field}")
            _json_depth(item, depth + 1, field)
    elif isinstance(value, list):
        if len(value) > 512:
            _invalid(f"Invalid {field}: item count exceeded")
        for item in value:
            _json_depth(item, depth + 1, field)


def _optional_text(value: Any, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    return _text(value, field, 1, maximum, lambda_response=True)


def _text(
    value: Any,
    field: str,
    minimum: int,
    maximum: int,
    *,
    lambda_response: bool = False,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum or "\x00" in value:
        if lambda_response:
            _lambda_error(f"Invalid {field}")
        _invalid(f"Invalid {field}")
    return value


def _invalid(message: str) -> None:
    raise LambdaTriggerError("InvalidParameterException", message)


def _lambda_error(message: str) -> None:
    raise LambdaTriggerError("InvalidLambdaResponseException", message)


def _unexpected(message: str) -> None:
    raise LambdaTriggerError("UnexpectedLambdaException", message)
