"""Isolated Cognito user-notification rendering and local SES/SNS delivery.

The provider integration deliberately lives outside this module. Callers must not hold a
Cognito store or pool lock while invoking :meth:`NotificationDispatcher.deliver`.

SMS role/trust is validated here, but the local SNS call uses the request account. This module
does not claim downstream IAM policy enforcement or STS role-session fidelity.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Literal

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.connect import connect_to
from localstack.utils.aws.arns import parse_arn

NotificationMedium = Literal["EMAIL", "SMS"]
NotificationPurpose = Literal[
    "EMAIL_MFA",
    "EMAIL_OTP",
    "SMS_MFA",
    "SMS_OTP",
    "admin_invitation",
    "attribute_verification",
    "forgot_password",
    "resend_confirmation",
    "signup_confirmation",
]

_CODE_PURPOSES = {
    "EMAIL_MFA",
    "EMAIL_OTP",
    "SMS_MFA",
    "SMS_OTP",
    "attribute_verification",
    "forgot_password",
    "resend_confirmation",
    "signup_confirmation",
}
_PURPOSES = {*_CODE_PURPOSES, "admin_invitation"}
_MAX_EMAIL_BODY = 20_000
_MAX_EMAIL_SUBJECT = 140
_MAX_SMS_MESSAGE = 140
_MAX_RESULT_ID = 2_048
_E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")
_POOL_ID = re.compile(r"^[\w-]+_[0-9A-Za-z]+$")
_DEFAULT_EMAIL_LOCK = threading.RLock()


class NotificationConfigurationError(ValueError):
    """Fail-closed configuration error suitable for mapping to InvalidParameterException."""


class InvalidEmailDeliveryConfiguration(NotificationConfigurationError):
    code = "InvalidEmailRoleAccessPolicyException"


class InvalidSmsDeliveryConfiguration(NotificationConfigurationError):
    code = "InvalidSmsRoleAccessPolicyException"


class NotificationDeliveryError(RuntimeError):
    """Sanitized delivery failure suitable for mapping to CodeDeliveryFailureException."""

    code = "CodeDeliveryFailureException"

    def __init__(self, medium: NotificationMedium, purpose: NotificationPurpose):
        super().__init__(f"{medium} notification delivery failed for {purpose}")
        self.medium = medium
        self.purpose = purpose


class NotificationCommitError(RuntimeError):
    """A delivered notification couldn't be atomically activated in Cognito state."""

    def __init__(self):
        super().__init__("Notification state changed before delivery could be committed")


@dataclass(frozen=True)
class EmailDeliveryConfiguration:
    sending_account: Literal["COGNITO_DEFAULT", "DEVELOPER"] = "COGNITO_DEFAULT"
    source_arn: str | None = None
    from_address: str | None = None
    reply_to_address: str | None = None
    configuration_set: str | None = None


@dataclass(frozen=True)
class SmsDeliveryConfiguration:
    caller_arn: str
    region: str
    external_id: str | None = None


@dataclass(frozen=True)
class NotificationConfiguration:
    email: EmailDeliveryConfiguration
    sms: SmsDeliveryConfiguration | None


@dataclass(frozen=True)
class NotificationTemplates:
    verification_email_message: str = "Your verification code is {####}."
    verification_email_subject: str = "Your verification code"
    verification_sms_message: str = "Your verification code is {####}."
    invitation_email_message: str = (
        "Your username is {username} and your temporary password is {####}."
    )
    invitation_email_subject: str = "Your temporary password"
    invitation_sms_message: str = "Username: {username} Temporary password: {####}"


@dataclass(frozen=True)
class NotificationRequest:
    pool_id: str
    purpose: NotificationPurpose
    medium: NotificationMedium
    destination: str
    secret: str
    username: str


@dataclass(frozen=True)
class NotificationReservation:
    """Opaque binding to PENDING provider state; it never contains the delivery secret."""

    reservation_id: str


def _invalid(message: str) -> None:
    raise NotificationConfigurationError(message)


def _context_partition(context: RequestContext) -> str:
    return getattr(context, "partition", None) or "aws"


def _parsed_arn(value: Any, *, context: RequestContext, service: str) -> dict[str, str]:
    if not isinstance(value, str) or not 20 <= len(value) <= 2_048:
        _invalid(f"Invalid {service} ARN")
    try:
        parsed = parse_arn(value)
    except (KeyError, TypeError, ValueError):
        _invalid(f"Invalid {service} ARN")
    if (
        parsed["partition"] != _context_partition(context)
        or parsed["service"] != service
        or parsed["account"] != context.account_id
    ):
        _invalid(f"{service} resource must belong to the user-pool account and partition")
    return parsed


def _safe_header(value: Any, field: str, *, maximum: int) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or "\x00" in value
    ):
        _invalid(f"Invalid {field}")
    return value


def _email_address(value: Any, field: str) -> str:
    safe = _safe_header(value, field, maximum=131_072)
    _, address = parseaddr(safe or "")
    local, separator, domain = address.rpartition("@")
    if (
        not separator
        or not local
        or not domain
        or len(address) > 320
        or any(character.isspace() for character in address)
    ):
        _invalid(f"Invalid {field}")
    return address


def validate_email_configuration(value: Any, context: RequestContext) -> EmailDeliveryConfiguration:
    if value is None:
        return EmailDeliveryConfiguration()
    allowed = {
        "ConfigurationSet",
        "EmailSendingAccount",
        "From",
        "ReplyToEmailAddress",
        "SourceArn",
    }
    if not isinstance(value, dict) or set(value) - allowed:
        _invalid("Invalid EmailConfiguration shape")
    sending_account = value.get("EmailSendingAccount", "COGNITO_DEFAULT")
    if sending_account not in {"COGNITO_DEFAULT", "DEVELOPER"}:
        _invalid("Invalid EmailSendingAccount")
    source_arn = value.get("SourceArn")
    if sending_account == "DEVELOPER" and source_arn is None:
        _invalid("DEVELOPER email delivery requires SourceArn")
    if source_arn is not None:
        parsed = _parsed_arn(source_arn, context=context, service="ses")
        if parsed["region"] != context.region or not parsed["resource"].startswith("identity/"):
            _invalid("SES identity must be in the local user-pool region")
        identity = parsed["resource"].removeprefix("identity/")
        if not identity or len(identity) > 320:
            _invalid("Invalid SES identity")
    configuration_set = _safe_header(value.get("ConfigurationSet"), "ConfigurationSet", maximum=64)
    if configuration_set is not None and (
        sending_account != "DEVELOPER" or re.fullmatch(r"[A-Za-z0-9_-]+", configuration_set) is None
    ):
        _invalid("ConfigurationSet requires DEVELOPER email delivery")
    from_address = value.get("From")
    if from_address is not None:
        parsed_from = _email_address(from_address, "From")
        if source_arn is None:
            _invalid("A custom From address requires SourceArn")
        identity = parse_arn(source_arn)["resource"].removeprefix("identity/")
        if "@" in identity:
            matches_identity = parsed_from.casefold() == identity.casefold()
        else:
            matches_identity = parsed_from.rpartition("@")[2].casefold() == identity.casefold()
        if not matches_identity:
            _invalid("From address must belong to the configured SES identity")
    reply_to = value.get("ReplyToEmailAddress")
    if reply_to is not None:
        _email_address(reply_to, "ReplyToEmailAddress")
    return EmailDeliveryConfiguration(
        sending_account=sending_account,
        source_arn=source_arn,
        from_address=from_address,
        reply_to_address=reply_to,
        configuration_set=configuration_set,
    )


def validate_sms_configuration(
    value: Any, context: RequestContext
) -> SmsDeliveryConfiguration | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"ExternalId", "SnsCallerArn", "SnsRegion"}:
        _invalid("Invalid SmsConfiguration shape")
    parsed = _parsed_arn(value.get("SnsCallerArn"), context=context, service="iam")
    if parsed["region"] or not parsed["resource"].startswith("role/"):
        _invalid("SnsCallerArn must be an IAM role ARN")
    region = value.get("SnsRegion", context.region)
    if region != context.region:
        _invalid("Only same-region local SNS delivery is supported")
    external_id = value.get("ExternalId")
    if not isinstance(external_id, (str, type(None))) or (
        isinstance(external_id, str) and (len(external_id) > 131_072 or "\x00" in external_id)
    ):
        _invalid("Invalid SmsConfiguration ExternalId")
    return SmsDeliveryConfiguration(
        caller_arn=value["SnsCallerArn"], region=region, external_id=external_id
    )


def validate_notification_configuration(
    email: Any, sms: Any, context: RequestContext
) -> NotificationConfiguration:
    return NotificationConfiguration(
        email=validate_email_configuration(email, context),
        sms=validate_sms_configuration(sms, context),
    )


def validate_templates(templates: NotificationTemplates) -> None:
    values = (
        (templates.verification_email_message, _MAX_EMAIL_BODY, "{####}"),
        (templates.verification_email_subject, _MAX_EMAIL_SUBJECT, None),
        (templates.verification_sms_message, _MAX_SMS_MESSAGE, "{####}"),
        (templates.invitation_email_message, _MAX_EMAIL_BODY, "{####}"),
        (templates.invitation_email_subject, _MAX_EMAIL_SUBJECT, None),
        (templates.invitation_sms_message, _MAX_SMS_MESSAGE, "{####}"),
    )
    for value, maximum, placeholder in values:
        if not isinstance(value, str) or not 1 <= len(value) <= maximum or "\x00" in value:
            _invalid("Invalid notification template")
        if placeholder is not None and placeholder not in value:
            _invalid("Notification template is missing {####}")
    if any(
        character in templates.verification_email_subject + templates.invitation_email_subject
        for character in "\r\n"
    ):
        _invalid("Notification email subject contains a header delimiter")


def _validate_request(request: NotificationRequest) -> None:
    if request.purpose not in _PURPOSES:
        _invalid("Invalid notification purpose")
    if request.medium not in {"EMAIL", "SMS"}:
        _invalid("Invalid notification medium")
    if request.purpose in {"EMAIL_MFA", "EMAIL_OTP", "SMS_MFA", "SMS_OTP"} and not (
        request.purpose.startswith(request.medium)
    ):
        _invalid("Authentication notification purpose does not match its delivery medium")
    if not _POOL_ID.fullmatch(request.pool_id) or len(request.pool_id) > 55:
        _invalid("Invalid notification user pool")
    if not 1 <= len(request.username) <= 128 or any(
        ord(character) < 0x20 for character in request.username
    ):
        _invalid("Invalid notification username")
    maximum_secret = 256 if request.purpose == "admin_invitation" else 2_048
    if not 1 <= len(request.secret) <= maximum_secret or any(
        ord(character) < 0x20 for character in request.secret
    ):
        _invalid("Invalid notification secret")
    if request.medium == "EMAIL":
        _email_address(request.destination, "email destination")
    elif not _E164.fullmatch(request.destination):
        _invalid("SMS destination must be an E.164 phone number")


def _render(request: NotificationRequest, templates: NotificationTemplates) -> tuple[str, str]:
    invitation = request.purpose == "admin_invitation"
    if request.medium == "EMAIL":
        subject = (
            templates.invitation_email_subject
            if invitation
            else templates.verification_email_subject
        )
        message = (
            templates.invitation_email_message
            if invitation
            else templates.verification_email_message
        )
    else:
        subject = ""
        message = (
            templates.invitation_sms_message if invitation else templates.verification_sms_message
        )
    rendered = message.replace("{username}", request.username).replace("{####}", request.secret)
    maximum = _MAX_EMAIL_BODY if request.medium == "EMAIL" else _MAX_SMS_MESSAGE
    if len(rendered) > maximum:
        _invalid("Rendered notification exceeds its service bound")
    return subject, rendered


def _client_factory(context: RequestContext, region: str):
    return connect_to(aws_access_key_id=context.account_id, region_name=region)


def _source_address(configuration: EmailDeliveryConfiguration) -> str:
    if configuration.from_address is not None:
        return configuration.from_address
    if configuration.source_arn is not None:
        return parse_arn(configuration.source_arn)["resource"].removeprefix("identity/")
    return "no-reply@verificationemail.com"


def _save_cognito_default_email(
    context: RequestContext, destination: str, source: str, subject: str, message: str
) -> dict[str, str]:
    # COGNITO_DEFAULT uses an AWS-managed SES account. The local equivalent writes through the
    # SES-owned retrospection API without creating an identity in the request account.
    from localstack.services.ses.models import SentEmail, SentEmailBody
    from localstack.services.ses.provider import EMAILS, save_for_retrospection

    with _DEFAULT_EMAIL_LOCK:
        for _attempt in range(8):
            message_id = str(uuid.uuid4())
            if message_id not in EMAILS:
                break
        else:
            raise RuntimeError("service-owned SES message identifier allocation failed")
        sent_email: Any = SentEmail(
            Id=message_id,
            Region=context.region,
            Destination={"ToAddresses": [destination]},
            Source=source,
            Subject=subject,
            Body=SentEmailBody(text_part=message, html_part=None),
        )
        sent_email["AccountId"] = context.account_id
        sent_email["ServiceOwned"] = "cognito-idp"
        try:
            save_for_retrospection(sent_email)
        except Exception:
            EMAILS.pop(message_id, None)
            path = Path(config.dirs.data or config.dirs.tmp) / "ses" / f"{message_id}.json"
            path.unlink(missing_ok=True)
            raise
    return {"MessageId": message_id}


def _role_name(caller_arn: str) -> str:
    return parse_arn(caller_arn)["resource"].removeprefix("role/").rsplit("/", 1)[-1]


def _as_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def _bounded_iam_pages(call: Callable[..., dict], key: str, **request: Any) -> list[Any]:
    result: list[Any] = []
    marker = None
    for _page in range(10):
        payload = dict(request, MaxItems=100)
        if marker is not None:
            payload["Marker"] = marker
        response = call(**payload)
        items = response.get(key, [])
        if not isinstance(items, list) or len(items) > 100:
            raise InvalidSmsDeliveryConfiguration("IAM policy pagination is invalid")
        result.extend(items)
        marker = response.get("Marker") if response.get("IsTruncated") else None
        if marker is None:
            return result
    raise InvalidSmsDeliveryConfiguration("IAM policy pagination exceeded its bound")


def _sns_publish_decision(documents: list[dict[str, Any]]) -> bool:
    allowed = False
    for document in documents:
        statements = document.get("Statement", []) if isinstance(document, dict) else []
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            actions = _as_values(statement.get("Action"))
            resources = _as_values(statement.get("Resource"))
            if (
                statement.get("Effect") == "Deny"
                and resources & {"*"}
                and (actions & {"sns:Publish", "sns:*", "*"})
            ):
                return False
            if (
                statement.get("Effect") == "Allow"
                and actions == {"sns:Publish"}
                and resources == {"*"}
                and "Condition" not in statement
                and "NotAction" not in statement
                and "NotResource" not in statement
            ):
                allowed = True
    return allowed


def _role_publish_policy_snapshot(
    context: RequestContext, iam: Any, role_name: str, role: dict[str, Any]
) -> str:
    documents: list[dict[str, Any]] = []
    inline_names = _bounded_iam_pages(iam.list_role_policies, "PolicyNames", RoleName=role_name)
    for name in sorted(inline_names):
        response = iam.get_role_policy(RoleName=role_name, PolicyName=name)
        document = response.get("PolicyDocument")
        if not isinstance(document, dict):
            raise InvalidSmsDeliveryConfiguration("IAM inline policy is invalid")
        documents.append(document)
    attached = _bounded_iam_pages(
        iam.list_attached_role_policies, "AttachedPolicies", RoleName=role_name
    )
    expected_prefix = f"arn:{_context_partition(context)}:iam::{context.account_id}:policy/"
    for descriptor in sorted(attached, key=lambda item: item.get("PolicyArn", "")):
        arn = descriptor.get("PolicyArn") if isinstance(descriptor, dict) else None
        if not isinstance(arn, str) or not arn.startswith(expected_prefix):
            raise InvalidSmsDeliveryConfiguration("IAM attached policy must be account-local")
        policy = iam.get_policy(PolicyArn=arn).get("Policy", {})
        version_id = policy.get("DefaultVersionId")
        if not isinstance(version_id, str):
            raise InvalidSmsDeliveryConfiguration("IAM attached policy version is invalid")
        document = (
            iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            .get("PolicyVersion", {})
            .get("Document")
        )
        if not isinstance(document, dict):
            raise InvalidSmsDeliveryConfiguration("IAM attached policy document is invalid")
        documents.append(document)
    if not _sns_publish_decision(documents):
        raise InvalidSmsDeliveryConfiguration(
            "SNS caller role does not allow sns:Publish to local phone destinations"
        )
    role_id = role.get("RoleId")
    if not isinstance(role_id, str) or not role_id:
        raise InvalidSmsDeliveryConfiguration("SNS caller role has no stable identity")
    canonical = json.dumps(
        {
            "documents": documents,
            "roleArn": role.get("Arn"),
            "roleId": role_id,
            "trustPolicy": role.get("AssumeRolePolicyDocument"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_local_resources(
    context: RequestContext, pool_id: str, configuration: NotificationConfiguration
) -> str:
    email = configuration.email
    clients = _client_factory(context, context.region)
    if email.source_arn is not None:
        try:
            identity = parse_arn(email.source_arn)["resource"].removeprefix("identity/")
            listed: set[str] = set()
            token = None
            for _page in range(10):
                request = {"MaxItems": 100}
                if token is not None:
                    request["NextToken"] = token
                response = clients.ses.list_identities(**request)
                listed.update(response.get("Identities", []))
                token = response.get("NextToken")
                if token is None:
                    break
            else:
                raise InvalidEmailDeliveryConfiguration(
                    "SES identity pagination exceeded its bound"
                )
            verification = clients.ses.get_identity_verification_attributes(Identities=[identity])
            status = (
                verification.get("VerificationAttributes", {})
                .get(identity, {})
                .get("VerificationStatus")
            )
            if identity not in listed or status != "Success":
                raise InvalidEmailDeliveryConfiguration("SES identity is not locally verified")
            if email.configuration_set is not None:
                clients.ses.describe_configuration_set(ConfigurationSetName=email.configuration_set)
        except InvalidEmailDeliveryConfiguration:
            raise
        except Exception:
            raise InvalidEmailDeliveryConfiguration(
                "SES delivery resources are unavailable"
            ) from None
    sms = configuration.sms
    if sms is None:
        return "email-only"
    try:
        role = clients.iam.get_role(RoleName=_role_name(sms.caller_arn))["Role"]
    except Exception:
        raise InvalidSmsDeliveryConfiguration("SNS caller role is unavailable") from None
    if role.get("Arn") != sms.caller_arn:
        raise InvalidSmsDeliveryConfiguration("SNS caller role ARN mismatch")
    policy = role.get("AssumeRolePolicyDocument")
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    trusted = False
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        services = _as_values(principal.get("Service")) if isinstance(principal, dict) else set()
        actions = _as_values(statement.get("Action"))
        if services != {"cognito-idp.amazonaws.com"} or actions != {"sts:AssumeRole"}:
            continue
        conditions = statement.get("Condition", {})
        equals = conditions.get("StringEquals", {}) if isinstance(conditions, dict) else {}
        if sms.external_id is not None and equals.get("sts:ExternalId") != sms.external_id:
            continue
        trusted = True
        break
    if not trusted:
        raise InvalidSmsDeliveryConfiguration(
            f"SNS caller role does not trust Cognito for pool {pool_id}"
        )
    return _role_publish_policy_snapshot(context, clients.iam, _role_name(sms.caller_arn), role)


FailureReporter = Callable[[RequestContext, str, dict[str, str]], None]


class NotificationDispatcher:
    def __init__(
        self,
        configuration: NotificationConfiguration,
        templates: NotificationTemplates | None = None,
        failure_reporter: FailureReporter | None = None,
    ):
        self.configuration = configuration
        self.templates = templates or NotificationTemplates()
        self.failure_reporter = failure_reporter
        validate_templates(self.templates)

    def deliver(self, context: RequestContext, request: NotificationRequest) -> str:
        _validate_request(request)
        subject, message = _render(request, self.templates)
        delivery_failed = False
        try:
            if request.medium == "EMAIL":
                response = self._deliver_email(context, request.destination, subject, message)
            else:
                response = self._deliver_sms(context, request.destination, message)
            message_id = response.get("MessageId")
            if not isinstance(message_id, str) or not 1 <= len(message_id) <= _MAX_RESULT_ID:
                raise ValueError("delivery service returned an invalid identifier")
            return message_id
        except Exception as error:
            self._report_failure(context, request, error)
            delivery_failed = True
        if delivery_failed:
            raise NotificationDeliveryError(request.medium, request.purpose)
        raise AssertionError("unreachable notification delivery state")

    def deliver_reserved(
        self,
        context: RequestContext,
        request: NotificationRequest,
        reservation: NotificationReservation,
        *,
        commit: Callable[[str], bool],
        rollback: Callable[[str], None],
        pre_commit: Callable[[], None] | None = None,
    ) -> str:
        """Deliver outside provider locks, then activate only the matching pending generation."""
        reservation_id = reservation.reservation_id
        if (
            not isinstance(reservation_id, str)
            or not 16 <= len(reservation_id) <= 256
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in reservation_id)
        ):
            _invalid("Invalid notification reservation")
        try:
            message_id = self.deliver(context, request)
            if pre_commit is not None:
                pre_commit()
        except Exception:
            self._rollback(reservation_id, rollback)
            raise
        try:
            committed = commit(reservation_id)
        except Exception:
            committed = False
        if committed is not True:
            self._rollback(reservation_id, rollback)
            raise NotificationCommitError()
        return message_id

    @staticmethod
    def _rollback(reservation_id: str, rollback: Callable[[str], None]) -> None:
        try:
            rollback(reservation_id)
        except Exception:
            return

    def _deliver_email(
        self, context: RequestContext, destination: str, subject: str, message: str
    ) -> dict:
        configuration = self.configuration.email
        source = _source_address(configuration)
        if configuration.sending_account == "COGNITO_DEFAULT" and configuration.source_arn is None:
            return _save_cognito_default_email(context, destination, source, subject, message)
        request: dict[str, Any] = {
            "Destination": {"ToAddresses": [destination]},
            "Message": {
                "Body": {"Text": {"Charset": "UTF-8", "Data": message}},
                "Subject": {"Charset": "UTF-8", "Data": subject},
            },
            "Source": source,
        }
        if configuration.source_arn is not None:
            request["SourceArn"] = configuration.source_arn
        if configuration.reply_to_address is not None:
            request["ReplyToAddresses"] = [configuration.reply_to_address]
        if configuration.configuration_set is not None:
            request["ConfigurationSetName"] = configuration.configuration_set
        return _client_factory(context, context.region).ses.send_email(**request)

    def _deliver_sms(self, context: RequestContext, destination: str, message: str) -> dict:
        configuration = self.configuration.sms
        if configuration is None:
            _invalid("SMS delivery is not configured")
        return _client_factory(context, configuration.region).sns.publish(
            PhoneNumber=destination,
            Message=message,
            MessageAttributes={
                "AWS.SNS.SMS.SMSType": {
                    "DataType": "String",
                    "StringValue": "Transactional",
                }
            },
        )

    def _report_failure(
        self, context: RequestContext, request: NotificationRequest, error: Exception
    ) -> None:
        if self.failure_reporter is None:
            return
        event = {
            "deliveryMedium": request.medium,
            "failureType": type(error).__name__,
            "notificationPurpose": request.purpose,
        }
        try:
            self.failure_reporter(context, request.pool_id, event)
        except Exception:
            return
