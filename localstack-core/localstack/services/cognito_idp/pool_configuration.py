import copy
import dataclasses
import hmac
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

from localstack.utils.aws.arns import parse_arn

from .lambda_triggers import LambdaTriggerError, TriggerIdentity, parse_lambda_configuration


class PoolConfigurationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class PoolIdentity:
    partition: str
    region: str
    account_id: str


@dataclasses.dataclass(frozen=True)
class PoolConfiguration:
    configured_fields: tuple[str, ...] = ()
    deletion_protection: str = "INACTIVE"
    attributes_require_verification: tuple[str, ...] = ()
    advanced_security_mode: str = "OFF"
    sms_authentication_message: str | None = None
    issuer_type: str = "ORIGINAL"
    key_type: str = "AWS_OWNED_KEY"
    kms_key_arn: str | None = None
    kms_key_snapshot: str | None = dataclasses.field(default=None, repr=False, compare=True)
    lambda_config: tuple[tuple[str, Any], ...] = ()
    password_minimum_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_symbols: bool = True
    password_history_size: int = 0
    temporary_password_validity_days: int = 7

    def lambda_arn(self, trigger: str) -> str | None:
        return dict(self.lambda_config).get(trigger)

    def to_response(self) -> dict[str, Any]:
        key_configuration = {"KeyType": self.key_type}
        if self.kms_key_arn is not None:
            key_configuration["KmsKeyArn"] = self.kms_key_arn
        values: dict[str, Any] = {
            "DeletionProtection": self.deletion_protection,
            "IssuerConfiguration": {"Type": self.issuer_type},
            "KeyConfiguration": key_configuration,
            "LambdaConfig": dict(self.lambda_config),
            "Policies": {
                "PasswordPolicy": {
                    "MinimumLength": self.password_minimum_length,
                    "PasswordHistorySize": self.password_history_size,
                    "RequireLowercase": self.password_require_lowercase,
                    "RequireNumbers": self.password_require_numbers,
                    "RequireSymbols": self.password_require_symbols,
                    "RequireUppercase": self.password_require_uppercase,
                    "TemporaryPasswordValidityDays": self.temporary_password_validity_days,
                }
            },
            "UserAttributeUpdateSettings": {
                "AttributesRequireVerificationBeforeUpdate": list(
                    self.attributes_require_verification
                )
            },
            "UserPoolAddOns": {"AdvancedSecurityMode": self.advanced_security_mode},
        }
        if self.sms_authentication_message is not None:
            values["SmsAuthenticationMessage"] = self.sms_authentication_message
        return {
            name: copy.deepcopy(values[name]) for name in self.configured_fields if name in values
        }


@dataclasses.dataclass(frozen=True)
class AttributeUpdatePlan:
    attributes: dict[str, str]
    pending: dict[str, str]


@dataclasses.dataclass(frozen=True)
class PreSignUpResult:
    auto_confirm_user: bool = False
    auto_verify_email: bool = False
    auto_verify_phone: bool = False


class PasswordVerifier(Protocol):
    def verify(self, candidate: str) -> bool: ...


KmsKeyValidator = Callable[[str], str]
PreSignUpExecutor = Callable[[str, dict[str, Any]], Mapping[str, Any]]


_PRE_SIGN_UP_SOURCES = {
    "PreSignUp_AdminCreateUser",
    "PreSignUp_ExternalProvider",
    "PreSignUp_SignUp",
}
_PASSWORD_POLICY_FIELDS = {
    "MinimumLength",
    "PasswordHistorySize",
    "RequireLowercase",
    "RequireNumbers",
    "RequireSymbols",
    "RequireUppercase",
    "TemporaryPasswordValidityDays",
}


def parse_pool_configuration(
    request: Mapping[str, Any],
    *,
    identity: PoolIdentity,
    kms_key_validator: KmsKeyValidator | None = None,
) -> PoolConfiguration:
    if not isinstance(request, Mapping):
        _invalid("Invalid user pool configuration")
    _validate_identity(identity)
    deletion_protection = request.get("DeletionProtection", "INACTIVE")
    if deletion_protection not in {"ACTIVE", "INACTIVE"}:
        _invalid("DeletionProtection must be ACTIVE or INACTIVE")

    verification_attributes = _verification_attributes(request.get("UserAttributeUpdateSettings"))
    advanced_security_mode = _advanced_security_mode(request.get("UserPoolAddOns"))
    sms_authentication_message = _sms_authentication_message(
        request.get("SmsAuthenticationMessage")
    )
    issuer_type = _issuer_type(request.get("IssuerConfiguration"))
    key_type, kms_key_arn, kms_key_snapshot = _key_configuration(
        request.get("KeyConfiguration"), identity, kms_key_validator
    )
    lambda_config = _lambda_configuration(request.get("LambdaConfig"), identity)
    password_policy = _password_policy(request.get("Policies"))

    return PoolConfiguration(
        configured_fields=tuple(
            name
            for name in (
                "DeletionProtection",
                "IssuerConfiguration",
                "KeyConfiguration",
                "LambdaConfig",
                "Policies",
                "SmsAuthenticationMessage",
                "UserAttributeUpdateSettings",
                "UserPoolAddOns",
            )
            if name in request
        ),
        deletion_protection=deletion_protection,
        attributes_require_verification=verification_attributes,
        advanced_security_mode=advanced_security_mode,
        sms_authentication_message=sms_authentication_message,
        issuer_type=issuer_type,
        key_type=key_type,
        kms_key_arn=kms_key_arn,
        kms_key_snapshot=kms_key_snapshot,
        lambda_config=tuple(lambda_config.items()),
        **password_policy,
    )


def assert_pool_delete_allowed(configuration: PoolConfiguration) -> None:
    if configuration.deletion_protection == "ACTIVE":
        raise PoolConfigurationError(
            "InvalidParameterException",
            "Deletion protection is active for this user pool",
        )


def revalidate_customer_managed_key(
    configuration: PoolConfiguration, validator: KmsKeyValidator
) -> None:
    if configuration.key_type == "AWS_OWNED_KEY":
        return
    if configuration.kms_key_arn is None or configuration.kms_key_snapshot is None:
        _invalid("Invalid persisted customer-managed key configuration")
    snapshot = _kms_snapshot(configuration.kms_key_arn, validator)
    if not hmac.compare_digest(snapshot, configuration.kms_key_snapshot):
        _invalid("Customer-managed key changed during user pool mutation")


def plan_attribute_updates(
    current: Mapping[str, str],
    updates: Mapping[str, str],
    configuration: PoolConfiguration,
    *,
    pending: Mapping[str, str] | None = None,
) -> AttributeUpdatePlan:
    attributes = _attribute_map(current, "current attributes")
    requested = _attribute_map(updates, "attribute updates")
    pending_values = _attribute_map(pending or {}, "pending attribute updates")
    required = set(configuration.attributes_require_verification)
    for name, value in requested.items():
        previous = attributes.get(name)
        if name in required and previous != value:
            pending_values[name] = value
            continue
        attributes[name] = value
        pending_values.pop(name, None)
        if name in {"email", "phone_number"} and previous != value:
            attributes[f"{name}_verified"] = "false"
    return AttributeUpdatePlan(attributes=attributes, pending=pending_values)


def commit_verified_attribute(
    plan: AttributeUpdatePlan, attribute_name: str
) -> AttributeUpdatePlan:
    if attribute_name not in {"email", "phone_number"} or attribute_name not in plan.pending:
        _invalid("No pending verified attribute update exists")
    attributes = dict(plan.attributes)
    pending = dict(plan.pending)
    attributes[attribute_name] = pending.pop(attribute_name)
    attributes[f"{attribute_name}_verified"] = "true"
    return AttributeUpdatePlan(attributes=attributes, pending=pending)


def invoke_pre_sign_up(
    configuration: PoolConfiguration,
    executor: PreSignUpExecutor,
    *,
    identity: PoolIdentity,
    pool_id: str,
    client_id: str,
    username: str,
    trigger_source: str,
    user_attributes: Mapping[str, str],
    validation_data: Mapping[str, str],
    client_metadata: Mapping[str, str],
) -> PreSignUpResult:
    function_arn = configuration.lambda_arn("PreSignUp")
    if function_arn is None:
        return PreSignUpResult()
    _validate_identity(identity)
    if trigger_source not in _PRE_SIGN_UP_SOURCES:
        _invalid("Invalid PreSignUp trigger source")
    _bounded_text(pool_id, "UserPoolId", minimum=1, maximum=55)
    _bounded_text(client_id, "ClientId", minimum=1, maximum=128)
    _bounded_text(username, "Username", minimum=1, maximum=128)
    attributes = _attribute_map(user_attributes, "user attributes")
    validation = _metadata_map(validation_data, "ValidationData")
    metadata = _metadata_map(client_metadata, "ClientMetadata")
    event = {
        "version": "1",
        "triggerSource": trigger_source,
        "region": identity.region,
        "userPoolId": pool_id,
        "userName": username,
        "callerContext": {"awsSdkVersion": "localstack", "clientId": client_id},
        "request": {
            "userAttributes": attributes,
            "validationData": validation,
            "clientMetadata": metadata,
        },
        "response": {
            "autoConfirmUser": False,
            "autoVerifyEmail": False,
            "autoVerifyPhone": False,
        },
    }
    try:
        returned = executor(function_arn, copy.deepcopy(event))
    except PoolConfigurationError:
        raise
    except Exception as error:
        raise PoolConfigurationError(
            "UnexpectedLambdaException", "PreSignUp Lambda invocation failed"
        ) from error
    if not isinstance(returned, Mapping) or set(returned) - set(event):
        _lambda_error("Invalid PreSignUp Lambda response")
    response = returned.get("response")
    allowed = {"autoConfirmUser", "autoVerifyEmail", "autoVerifyPhone"}
    if (
        not isinstance(response, Mapping)
        or set(response) - allowed
        or any(not isinstance(value, bool) for value in response.values())
    ):
        _lambda_error("Invalid PreSignUp Lambda response")
    return PreSignUpResult(
        auto_confirm_user=response.get("autoConfirmUser", False),
        auto_verify_email=response.get("autoVerifyEmail", False),
        auto_verify_phone=response.get("autoVerifyPhone", False),
    )


def assert_password_not_reused(
    candidate: str,
    current: PasswordVerifier,
    history: Sequence[PasswordVerifier],
    configuration: PoolConfiguration,
) -> None:
    _bounded_text(candidate, "Password", minimum=1, maximum=256)
    size = configuration.password_history_size
    if size and (
        current.verify(candidate) or any(item.verify(candidate) for item in history[:size])
    ):
        raise PoolConfigurationError(
            "PasswordHistoryPolicyViolationException",
            "Password was used too recently",
        )


def rotate_password_history(
    current: PasswordVerifier,
    history: Sequence[PasswordVerifier],
    configuration: PoolConfiguration,
) -> list[PasswordVerifier]:
    size = configuration.password_history_size
    if size == 0:
        return []
    return [current, *list(history[: max(0, size - 1)])]


def _verification_attributes(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Mapping) or set(value) != {
        "AttributesRequireVerificationBeforeUpdate"
    }:
        _invalid("Invalid UserAttributeUpdateSettings")
    attributes = value["AttributesRequireVerificationBeforeUpdate"]
    if (
        not isinstance(attributes, list)
        or len(attributes) > 2
        or len(attributes) != len(set(attributes))
        or set(attributes) - {"email", "phone_number"}
    ):
        _invalid("Invalid AttributesRequireVerificationBeforeUpdate")
    return tuple(attributes)


def _advanced_security_mode(value: Any) -> str:
    if value is None:
        return "OFF"
    if not isinstance(value, Mapping) or not set(value) <= {
        "AdvancedSecurityAdditionalFlows",
        "AdvancedSecurityMode",
    }:
        _invalid("Invalid UserPoolAddOns")
    mode = value.get("AdvancedSecurityMode")
    if mode not in {"OFF", "AUDIT", "ENFORCED"}:
        _invalid("Invalid AdvancedSecurityMode")
    additional = value.get("AdvancedSecurityAdditionalFlows")
    if additional not in (None, {}):
        if (
            not isinstance(additional, Mapping)
            or set(additional) != {"CustomAuthMode"}
            or additional.get("CustomAuthMode") not in {"AUDIT", "ENFORCED"}
        ):
            _invalid("Invalid AdvancedSecurityAdditionalFlows")
        _advanced_security_unavailable()
    if mode != "OFF":
        _advanced_security_unavailable()
    return mode


def _advanced_security_unavailable() -> None:
    raise PoolConfigurationError(
        "InvalidParameterException",
        "A local advanced-security engine is required for AUDIT or ENFORCED mode",
    )


def _sms_authentication_message(value: Any) -> str | None:
    if value is None:
        return None
    _bounded_text(value, "SmsAuthenticationMessage", minimum=6, maximum=140)
    if "{####}" not in value:
        _invalid("SmsAuthenticationMessage must contain a {####} placeholder")
    return value


def _issuer_type(value: Any) -> str:
    if value is None:
        return "ORIGINAL"
    if not isinstance(value, Mapping) or set(value) != {"Type"}:
        _invalid("Invalid IssuerConfiguration")
    issuer_type = value.get("Type")
    if issuer_type not in {"ORIGINAL", "UPDATED"}:
        _invalid("Invalid IssuerConfiguration Type")
    if issuer_type == "UPDATED":
        raise PoolConfigurationError(
            "InvalidParameterException",
            "UPDATED issuer semantics are not implemented locally",
        )
    return issuer_type


def _key_configuration(
    value: Any,
    identity: PoolIdentity,
    validator: KmsKeyValidator | None,
) -> tuple[str, str | None, str | None]:
    if value is None:
        return "AWS_OWNED_KEY", None, None
    if not isinstance(value, Mapping) or set(value) - {"KeyType", "KmsKeyArn"}:
        _invalid("Invalid KeyConfiguration")
    key_type = value.get("KeyType", "AWS_OWNED_KEY")
    key_arn = value.get("KmsKeyArn")
    if key_type == "AWS_OWNED_KEY":
        if key_arn is not None:
            _invalid("AWS_OWNED_KEY cannot include KmsKeyArn")
        return key_type, None, None
    if key_type != "CUSTOMER_MANAGED_KEY" or not isinstance(key_arn, str):
        _invalid("CUSTOMER_MANAGED_KEY requires KmsKeyArn")
    _validate_scoped_arn(key_arn, identity, service="kms", resource_prefix="key/")
    if validator is None:
        raise PoolConfigurationError(
            "InvalidParameterException",
            "Customer-managed keys require a local KMS validator",
        )
    snapshot = _kms_snapshot(key_arn, validator)
    return key_type, key_arn, snapshot


def _kms_snapshot(key_arn: str, validator: KmsKeyValidator) -> str:
    try:
        snapshot = validator(key_arn)
    except Exception as error:
        raise PoolConfigurationError(
            "InvalidParameterException", "KmsKeyArn could not be validated"
        ) from error
    if (
        not isinstance(snapshot, str)
        or not 1 <= len(snapshot) <= 512
        or "\x00" in snapshot
        or "\r" in snapshot
    ):
        _invalid("KmsKeyArn does not identify an enabled local key")
    return snapshot


def _lambda_configuration(value: Any, identity: PoolIdentity) -> dict[str, Any]:
    if value is None:
        return {}
    try:
        parse_lambda_configuration(
            value,
            identity=TriggerIdentity(
                partition=identity.partition,
                account_id=identity.account_id,
                region=identity.region,
                pool_id=f"{identity.region}_configuration",
                client_id="configuration",
                username="configuration",
            ),
        )
    except LambdaTriggerError as error:
        raise PoolConfigurationError(error.code, str(error)) from error
    return copy.deepcopy(dict(value))


def _password_policy(value: Any) -> dict[str, Any]:
    if value is None:
        policy: Mapping[str, Any] = {}
    else:
        if not isinstance(value, Mapping):
            _invalid("Invalid Policies")
        nested = value.get("PasswordPolicy", {})
        if not isinstance(nested, Mapping) or set(nested) - _PASSWORD_POLICY_FIELDS:
            _invalid("Unsupported PasswordPolicy fields")
        policy = nested
    minimum = _bounded_integer(policy.get("MinimumLength", 8), "MinimumLength", 6, 99)
    history = _bounded_integer(policy.get("PasswordHistorySize", 0), "PasswordHistorySize", 0, 24)
    temporary = _bounded_integer(
        policy.get("TemporaryPasswordValidityDays", 7),
        "TemporaryPasswordValidityDays",
        0,
        365,
    )
    if temporary == 0:
        temporary = 7
    booleans = {}
    for field in (
        "RequireLowercase",
        "RequireNumbers",
        "RequireSymbols",
        "RequireUppercase",
    ):
        item = policy.get(field, True)
        if not isinstance(item, bool):
            _invalid(f"Invalid {field}")
        booleans[f"password_require_{_snake_case(field.removeprefix('Require'))}"] = item
    return {
        "password_minimum_length": minimum,
        "password_history_size": history,
        "temporary_password_validity_days": temporary,
        **booleans,
    }


def _attribute_map(value: Mapping[str, str], field: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > 50:
        _invalid(f"Invalid {field}")
    result = {}
    for name, item in value.items():
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 64
            or not isinstance(item, str)
            or len(item) > 2_048
            or "\x00" in name
            or "\x00" in item
        ):
            _invalid(f"Invalid {field}")
        result[name] = item
    return result


def _metadata_map(value: Mapping[str, str], field: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > 32:
        _invalid(f"Invalid {field}")
    result = {}
    total = 0
    for name, item in value.items():
        if not isinstance(name, str) or not isinstance(item, str):
            _invalid(f"Invalid {field}")
        _bounded_text(name, field, minimum=1, maximum=128)
        _bounded_text(item, field, minimum=0, maximum=2_048)
        total += len(name.encode()) + len(item.encode())
        if total > 16_384:
            _invalid(f"Invalid {field}")
        result[name] = item
    return result


def _validate_scoped_arn(
    value: str,
    identity: PoolIdentity,
    *,
    service: str,
    resource_prefix: str,
) -> None:
    if not 20 <= len(value) <= 2_048 or any(character.isspace() for character in value):
        _invalid(f"Invalid {service} ARN")
    try:
        parsed = parse_arn(value)
    except (KeyError, TypeError, ValueError):
        _invalid(f"Invalid {service} ARN")
    if (
        parsed["partition"] != identity.partition
        or parsed["service"] != service
        or parsed["region"] != identity.region
        or parsed["account"] != identity.account_id
        or not parsed["resource"].startswith(resource_prefix)
        or len(parsed["resource"]) <= len(resource_prefix)
    ):
        _invalid(f"Invalid or cross-scope {service} ARN")


def _validate_identity(identity: PoolIdentity) -> None:
    if (
        not isinstance(identity, PoolIdentity)
        or identity.partition not in {"aws", "aws-cn", "aws-us-gov"}
        or not identity.region
        or not identity.account_id.isdigit()
        or len(identity.account_id) != 12
    ):
        _invalid("Invalid pool identity")


def _bounded_integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        _invalid(f"Invalid {field}")
    return value


def _bounded_text(value: Any, field: str, *, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or "\x00" in value
        or "\r" in value
    ):
        _invalid(f"Invalid {field}")
    return value


def _snake_case(value: str) -> str:
    return "".join(
        f"_{character.lower()}" if character.isupper() else character for character in value
    ).lstrip("_")


def _invalid(message: str) -> None:
    raise PoolConfigurationError("InvalidParameterException", message)


def _lambda_error(message: str) -> None:
    raise PoolConfigurationError("InvalidLambdaResponseException", message)
