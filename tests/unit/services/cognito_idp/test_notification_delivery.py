import copy
import json
from pathlib import Path
from types import SimpleNamespace

import botocore.session
import pytest
from botocore.stub import Stubber

from localstack import config
from localstack.aws.api import RequestContext
from localstack.services.cognito_idp import log_delivery, notification_delivery
from localstack.services.cognito_idp.notification_delivery import (
    InvalidEmailDeliveryConfiguration,
    InvalidSmsDeliveryConfiguration,
    NotificationCommitError,
    NotificationConfigurationError,
    NotificationDeliveryError,
    NotificationDispatcher,
    NotificationRequest,
    NotificationReservation,
    NotificationTemplates,
    validate_local_resources,
    validate_notification_configuration,
)


class FakeSes:
    def __init__(self):
        self.identities = ["mailer@example.test"]
        self.configuration_sets = {"cognito-events"}
        self.messages = []

    def list_identities(self, **_request):
        return {"Identities": list(self.identities)}

    def get_identity_verification_attributes(self, *, Identities):
        return {
            "VerificationAttributes": {
                identity: {"VerificationStatus": "Success"} for identity in Identities
            }
        }

    def describe_configuration_set(self, *, ConfigurationSetName):
        if ConfigurationSetName not in self.configuration_sets:
            raise KeyError(ConfigurationSetName)
        return {}

    def send_email(self, **request):
        self.messages.append(request)
        return {"MessageId": f"email-{len(self.messages)}"}


class FakeSns:
    def __init__(self):
        self.messages = []

    def publish(self, **request):
        self.messages.append(request)
        return {"MessageId": f"sms-{len(self.messages)}"}


class FakeIam:
    def __init__(self, context, external_id="external-id"):
        self.context = context
        self.external_id = external_id
        self.policy_document = {
            "Statement": [{"Action": "sns:Publish", "Effect": "Allow", "Resource": "*"}]
        }

    def get_role(self, *, RoleName):
        return {
            "Role": {
                "Arn": f"arn:aws:iam::{self.context.account_id}:role/{RoleName}",
                "RoleId": "AROAEXAMPLE",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Action": "sts:AssumeRole",
                            "Effect": "Allow",
                            "Principal": {"Service": "cognito-idp.amazonaws.com"},
                            "Condition": {"StringEquals": {"sts:ExternalId": self.external_id}},
                        }
                    ]
                },
            }
        }

    def list_role_policies(self, **_request):
        return {"IsTruncated": False, "PolicyNames": ["publish"]}

    def get_role_policy(self, **_request):
        return {"PolicyDocument": copy.deepcopy(self.policy_document)}

    def list_attached_role_policies(self, **_request):
        return {"AttachedPolicies": [], "IsTruncated": False}


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = "111122223333"
    value.region = "us-east-1"
    return value


@pytest.fixture
def clients(context, monkeypatch):
    value = SimpleNamespace(ses=FakeSes(), sns=FakeSns(), iam=FakeIam(context))
    monkeypatch.setattr(notification_delivery, "_client_factory", lambda _context, _region: value)
    return value


def configuration(context):
    return validate_notification_configuration(
        {
            "ConfigurationSet": "cognito-events",
            "EmailSendingAccount": "DEVELOPER",
            "From": "Cognito <mailer@example.test>",
            "ReplyToEmailAddress": "support@example.test",
            "SourceArn": (
                f"arn:aws:ses:{context.region}:{context.account_id}:identity/mailer@example.test"
            ),
        },
        {
            "ExternalId": "external-id",
            "SnsCallerArn": f"arn:aws:iam::{context.account_id}:role/cognito-sms",
            "SnsRegion": context.region,
        },
        context,
    )


def test_configuration_is_immutable_and_resources_are_validated(context, clients):
    raw_email = {
        "EmailSendingAccount": "DEVELOPER",
        "SourceArn": f"arn:aws:ses:{context.region}:{context.account_id}:identity/mailer@example.test",
    }
    original = copy.deepcopy(raw_email)
    result = validate_notification_configuration(
        raw_email,
        {"SnsCallerArn": f"arn:aws:iam::{context.account_id}:role/cognito-sms"},
        context,
    )
    raw_email["SourceArn"] = "changed"

    assert result.email.source_arn == original["SourceArn"]
    assert result.sms.region == context.region
    validate_local_resources(context, "us-east-1_pool", result)


@pytest.mark.parametrize(
    "statements",
    [
        [{"Action": "sns:*", "Effect": "Allow", "Resource": "*"}],
        [
            {"Action": "sns:Publish", "Effect": "Allow", "Resource": "*"},
            {"Action": "sns:*", "Effect": "Deny", "Resource": "*"},
        ],
        [{"Action": "sns:Publish", "Effect": "Allow", "Resource": "phone/*"}],
    ],
)
def test_sms_publish_policy_is_fail_closed(context, clients, statements):
    clients.iam.policy_document = {"Statement": statements}
    with pytest.raises(InvalidSmsDeliveryConfiguration):
        validate_local_resources(
            context,
            "us-east-1_pool",
            validate_notification_configuration(
                None,
                {"SnsCallerArn": f"arn:aws:iam::{context.account_id}:role/cognito-sms"},
                context,
            ),
        )


def test_sms_resource_snapshot_changes_with_role_trust_and_policy(context, clients):
    configured = validate_notification_configuration(
        None,
        {"SnsCallerArn": f"arn:aws:iam::{context.account_id}:role/cognito-sms"},
        context,
    )
    first = validate_local_resources(context, "us-east-1_pool", configured)
    clients.iam.policy_document["Statement"].append(
        {"Action": "s3:GetObject", "Effect": "Allow", "Resource": "*"}
    )
    second = validate_local_resources(context, "us-east-1_pool", configured)
    assert first != second


def test_sms_role_policy_aba_after_publish_rolls_back_before_commit(context, clients):
    configured = validate_notification_configuration(
        None,
        {"SnsCallerArn": f"arn:aws:iam::{context.account_id}:role/cognito-sms"},
        context,
    )
    snapshot = validate_local_resources(context, "us-east-1_pool", configured)
    original_publish = clients.sns.publish

    def publish(**request):
        result = original_publish(**request)
        clients.iam.policy_document["Statement"].append(
            {"Action": "s3:GetObject", "Effect": "Allow", "Resource": "*"}
        )
        return result

    clients.sns.publish = publish
    committed = []
    rolled_back = []
    with pytest.raises(NotificationConfigurationError):
        NotificationDispatcher(configured).deliver_reserved(
            context,
            NotificationRequest(
                pool_id="us-east-1_pool",
                purpose="signup_confirmation",
                medium="SMS",
                destination="+15551234567",
                secret="123456",
                username="alice",
            ),
            NotificationReservation("reservation-generation-0001"),
            commit=lambda value: committed.append(value) or True,
            rollback=rolled_back.append,
            pre_commit=lambda: (
                None
                if validate_local_resources(context, "us-east-1_pool", configured) == snapshot
                else (_ for _ in ()).throw(NotificationConfigurationError("IAM role changed"))
            ),
        )
    assert not committed
    assert rolled_back == ["reservation-generation-0001"]


def test_local_resource_validation_rejects_unverified_identity_and_wrong_sms_trust(
    context, clients
):
    result = configuration(context)
    clients.ses.identities.clear()
    with pytest.raises(InvalidEmailDeliveryConfiguration, match="not locally verified") as email:
        validate_local_resources(context, "us-east-1_pool", result)
    assert email.value.code == "InvalidEmailRoleAccessPolicyException"

    clients.ses.identities.append("mailer@example.test")
    clients.iam.external_id = "different-external-id"
    with pytest.raises(InvalidSmsDeliveryConfiguration, match="does not trust Cognito") as sms:
        validate_local_resources(context, "us-east-1_pool", result)
    assert sms.value.code == "InvalidSmsRoleAccessPolicyException"

    assert clients.ses.messages == []
    assert clients.sns.messages == []


def test_ses_identity_discovery_has_a_hard_pagination_bound(context, clients):
    pages = 0

    def endless(**_request):
        nonlocal pages
        pages += 1
        return {"Identities": [], "NextToken": f"page-{pages}"}

    clients.ses.list_identities = endless

    with pytest.raises(InvalidEmailDeliveryConfiguration, match="pagination"):
        validate_local_resources(context, "us-east-1_pool", configuration(context))

    assert pages == 10
    assert clients.ses.messages == []


@pytest.mark.parametrize(
    ("email", "sms"),
    [
        ({"EmailSendingAccount": "DEVELOPER"}, None),
        (
            {
                "EmailSendingAccount": "DEVELOPER",
                "SourceArn": "arn:aws:ses:eu-west-1:111122223333:identity/a@example.test",
            },
            None,
        ),
        (
            {"From": "sender@example.test\r\nBcc: secret@example.test"},
            None,
        ),
        (
            {
                "EmailSendingAccount": "DEVELOPER",
                "From": "attacker@example.test",
                "SourceArn": ("arn:aws:ses:us-east-1:111122223333:identity/mailer@example.test"),
            },
            None,
        ),
        (
            None,
            {"SnsCallerArn": "arn:aws:iam::999999999999:role/cognito-sms"},
        ),
        (
            None,
            {
                "SnsCallerArn": "arn:aws:iam::111122223333:role/cognito-sms",
                "SnsRegion": "eu-west-1",
            },
        ),
    ],
)
def test_configuration_fails_closed_for_unsupported_or_cross_boundary_values(context, email, sms):
    with pytest.raises(NotificationConfigurationError):
        validate_notification_configuration(email, sms, context)


@pytest.mark.parametrize(
    "purpose",
    [
        "signup_confirmation",
        "resend_confirmation",
        "forgot_password",
        "attribute_verification",
    ],
)
@pytest.mark.parametrize("medium", ["EMAIL", "SMS"])
def test_all_code_flows_are_recoverable_from_selected_local_channel(
    context, clients, purpose, medium
):
    dispatcher = NotificationDispatcher(
        configuration(context),
        NotificationTemplates(
            verification_email_message="Email code {####} for {username}",
            verification_sms_message="SMS code {####} for {username}",
        ),
    )
    destination = "member@example.test" if medium == "EMAIL" else "+12065550123"

    message_id = dispatcher.deliver(
        context,
        NotificationRequest(
            pool_id="us-east-1_pool",
            purpose=purpose,
            medium=medium,
            destination=destination,
            secret="246810",
            username="member",
        ),
    )

    if medium == "EMAIL":
        assert message_id.startswith("email-")
        delivered = clients.ses.messages[-1]
        assert delivered["Destination"] == {"ToAddresses": [destination]}
        assert delivered["Message"]["Body"]["Text"]["Data"] == "Email code 246810 for member"
        assert delivered["Source"] == "Cognito <mailer@example.test>"
        assert delivered["SourceArn"].endswith("identity/mailer@example.test")
        assert delivered["ConfigurationSetName"] == "cognito-events"
    else:
        assert message_id.startswith("sms-")
        delivered = clients.sns.messages[-1]
        assert delivered["PhoneNumber"] == destination
        assert delivered["Message"] == "SMS code 246810 for member"


@pytest.mark.parametrize(
    ("purpose", "medium", "destination"),
    [
        ("EMAIL_MFA", "EMAIL", "member@example.test"),
        ("EMAIL_OTP", "EMAIL", "member@example.test"),
        ("SMS_MFA", "SMS", "+12065550123"),
        ("SMS_OTP", "SMS", "+12065550123"),
    ],
)
def test_authentication_purposes_are_distinct_and_medium_bound(
    context, clients, purpose, medium, destination
):
    dispatcher = NotificationDispatcher(configuration(context))
    assert dispatcher.deliver(
        context,
        NotificationRequest(
            pool_id="us-east-1_pool",
            purpose=purpose,
            medium=medium,
            destination=destination,
            secret="246810",
            username="member",
        ),
    )
    with pytest.raises(NotificationConfigurationError, match="does not match"):
        dispatcher.deliver(
            context,
            NotificationRequest(
                pool_id="us-east-1_pool",
                purpose=purpose,
                medium="SMS" if medium == "EMAIL" else "EMAIL",
                destination="+12065550123" if medium == "EMAIL" else "member@example.test",
                secret="246810",
                username="member",
            ),
        )


@pytest.mark.parametrize("medium", ["EMAIL", "SMS"])
def test_admin_invitation_is_recoverable_from_selected_local_channel(context, clients, medium):
    dispatcher = NotificationDispatcher(
        configuration(context),
        NotificationTemplates(
            invitation_email_message="Invite {username} with {####}",
            invitation_sms_message="Invite {username} with {####}",
        ),
    )
    destination = "admin@example.test" if medium == "EMAIL" else "+12065550123"
    request = NotificationRequest(
        pool_id="us-east-1_pool",
        purpose="admin_invitation",
        medium=medium,
        destination=destination,
        secret="Temporary-99!",
        username="admin@example.test",
    )

    assert dispatcher.deliver(context, request) == ("email-1" if medium == "EMAIL" else "sms-1")
    if medium == "EMAIL":
        delivered = clients.ses.messages[0]
        message = delivered["Message"]["Body"]["Text"]["Data"]
    else:
        delivered = clients.sns.messages[0]
        message = delivered["Message"]
        assert delivered["MessageAttributes"]["AWS.SNS.SMS.SMSType"]["StringValue"] == (
            "Transactional"
        )
    assert request.username in message
    assert request.secret in message


def test_template_and_rendered_message_bounds_fail_before_service_call(context, clients):
    with pytest.raises(NotificationConfigurationError, match="missing"):
        NotificationDispatcher(
            configuration(context),
            NotificationTemplates(verification_sms_message="No placeholder here"),
        )
    dispatcher = NotificationDispatcher(
        configuration(context),
        NotificationTemplates(invitation_sms_message=("x" * 120) + "{username} {####}"),
    )
    with pytest.raises(NotificationConfigurationError, match="exceeds"):
        dispatcher.deliver(
            context,
            NotificationRequest(
                pool_id="us-east-1_pool",
                purpose="admin_invitation",
                medium="SMS",
                destination="+12065550123",
                secret="246810",
                username="member-with-a-long-name",
            ),
        )
    assert clients.sns.messages == []

    with pytest.raises(NotificationConfigurationError, match="header delimiter"):
        NotificationDispatcher(
            configuration(context),
            NotificationTemplates(verification_email_subject="Verify\r\nBcc: attacker"),
        )


def test_delivery_failure_is_sanitized_reported_once_and_never_retried(context, clients):
    reports = []
    attempts = 0

    def fail(**_request):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("provider included secret 246810 and member@example.test")

    clients.ses.send_email = fail
    dispatcher = NotificationDispatcher(
        configuration(context),
        failure_reporter=lambda *arguments: reports.append(arguments),
    )
    request = NotificationRequest(
        pool_id="us-east-1_pool",
        purpose="forgot_password",
        medium="EMAIL",
        destination="member@example.test",
        secret="246810",
        username="member",
    )

    with pytest.raises(NotificationDeliveryError) as error:
        dispatcher.deliver(context, request)

    assert attempts == 1
    assert str(error.value) == "EMAIL notification delivery failed for forgot_password"
    assert "246810" not in str(error.value)
    assert "member@example.test" not in str(error.value)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert len(reports) == 1
    assert reports[0][1:] == (
        "us-east-1_pool",
        {
            "deliveryMedium": "EMAIL",
            "failureType": "RuntimeError",
            "notificationPurpose": "forgot_password",
        },
    )


def test_failure_reporter_cannot_cascade_or_expose_delivery_error(context, clients):
    clients.sns.publish = lambda **_request: (_ for _ in ()).throw(RuntimeError("secret"))
    dispatcher = NotificationDispatcher(
        configuration(context),
        failure_reporter=lambda *_arguments: (_ for _ in ()).throw(RuntimeError("reporter")),
    )

    with pytest.raises(NotificationDeliveryError, match="SMS notification delivery failed"):
        dispatcher.deliver(
            context,
            NotificationRequest(
                pool_id="us-east-1_pool",
                purpose="resend_confirmation",
                medium="SMS",
                destination="+12065550123",
                secret="246810",
                username="member",
            ),
        )


def test_reserved_delivery_commits_after_service_and_never_holds_provider_state(context, clients):
    events = []
    dispatcher = NotificationDispatcher(configuration(context))
    request = NotificationRequest(
        pool_id="us-east-1_pool",
        purpose="signup_confirmation",
        medium="EMAIL",
        destination="member@example.test",
        secret="246810",
        username="member",
    )

    message_id = dispatcher.deliver_reserved(
        context,
        request,
        NotificationReservation("reservation-generation-1"),
        commit=lambda generation: (
            events.append(("commit", generation, len(clients.ses.messages))) or True
        ),
        rollback=lambda generation: events.append(("rollback", generation)),
    )

    assert message_id == "email-1"
    assert events == [("commit", "reservation-generation-1", 1)]


def test_reserved_delivery_rolls_back_exact_generation_on_delivery_or_aba_failure(context, clients):
    rolled_back = []
    dispatcher = NotificationDispatcher(configuration(context))
    request = NotificationRequest(
        pool_id="us-east-1_pool",
        purpose="forgot_password",
        medium="EMAIL",
        destination="member@example.test",
        secret="246810",
        username="member",
    )
    reservation = NotificationReservation("reservation-generation-1")
    clients.ses.send_email = lambda **_request: (_ for _ in ()).throw(RuntimeError("failed"))

    with pytest.raises(NotificationDeliveryError):
        dispatcher.deliver_reserved(
            context,
            request,
            reservation,
            commit=lambda _generation: pytest.fail("delivery failure must not commit"),
            rollback=rolled_back.append,
        )
    assert rolled_back == [reservation.reservation_id]

    clients.ses.send_email = lambda **_request: {"MessageId": "delivered-but-stale"}
    with pytest.raises(NotificationCommitError):
        dispatcher.deliver_reserved(
            context,
            request,
            reservation,
            commit=lambda _generation: False,
            rollback=rolled_back.append,
        )
    assert rolled_back == [reservation.reservation_id, reservation.reservation_id]


def test_reserved_delivery_rolls_back_when_render_or_destination_validation_fails(context, clients):
    rolled_back = []
    dispatcher = NotificationDispatcher(configuration(context))

    with pytest.raises(NotificationConfigurationError, match="E.164"):
        dispatcher.deliver_reserved(
            context,
            NotificationRequest(
                pool_id="us-east-1_pool",
                purpose="signup_confirmation",
                medium="SMS",
                destination="not-a-phone-number",
                secret="246810",
                username="member",
            ),
            NotificationReservation("reservation-generation-1"),
            commit=lambda _generation: pytest.fail("invalid delivery must not commit"),
            rollback=rolled_back.append,
        )

    assert rolled_back == ["reservation-generation-1"]
    assert clients.sns.messages == []


@pytest.mark.parametrize("race", ["delete", "replace"])
def test_reserved_delivery_delete_and_aba_races_never_remove_a_new_generation(
    context, clients, race
):
    dispatcher = NotificationDispatcher(configuration(context))
    request = NotificationRequest(
        pool_id="us-east-1_pool",
        purpose="signup_confirmation",
        medium="EMAIL",
        destination="member@example.test",
        secret="246810",
        username="member",
    )
    old_generation = "reservation-generation-old"
    new_generation = "reservation-generation-new"
    state = {"generation": old_generation}

    def deliver_and_race(**_request):
        if race == "delete":
            state.clear()
        else:
            state["generation"] = new_generation
        return {"MessageId": "delivered-before-race-was-observed"}

    def compare_and_rollback(generation):
        if state.get("generation") == generation:
            state.clear()

    clients.ses.send_email = deliver_and_race
    with pytest.raises(NotificationCommitError):
        dispatcher.deliver_reserved(
            context,
            request,
            NotificationReservation(old_generation),
            commit=lambda generation: state.get("generation") == generation,
            rollback=compare_and_rollback,
        )

    assert state == ({} if race == "delete" else {"generation": new_generation})


def test_local_client_adapter_binds_explicit_account_and_region(context, monkeypatch):
    calls = []
    sentinel = object()

    def local_connect(**kwargs):
        calls.append(kwargs)
        return sentinel

    monkeypatch.setattr(notification_delivery, "connect_to", local_connect)

    assert notification_delivery._client_factory(context, "us-east-1") is sentinel
    assert calls == [{"aws_access_key_id": context.account_id, "region_name": "us-east-1"}]


def test_official_botocore_shapes_accept_local_ses_and_sns_adapter_requests(context, monkeypatch):
    session = botocore.session.get_session()
    credentials = {
        "aws_access_key_id": context.account_id,
        "aws_secret_access_key": "test-secret-key",
    }
    ses = session.create_client(
        "ses",
        region_name=context.region,
        endpoint_url="http://127.0.0.1:1",
        **credentials,
    )
    sns = session.create_client(
        "sns",
        region_name=context.region,
        endpoint_url="http://127.0.0.1:1",
        **credentials,
    )
    local_clients = SimpleNamespace(ses=ses, sns=sns)
    monkeypatch.setattr(
        notification_delivery, "_client_factory", lambda _context, _region: local_clients
    )
    dispatcher = NotificationDispatcher(configuration(context))
    email_request = NotificationRequest(
        pool_id="us-east-1_pool",
        purpose="signup_confirmation",
        medium="EMAIL",
        destination="member@example.test",
        secret="246810",
        username="member",
    )
    sms_request = NotificationRequest(
        pool_id="us-east-1_pool",
        purpose="forgot_password",
        medium="SMS",
        destination="+12065550123",
        secret="135791",
        username="member",
    )
    with Stubber(ses) as ses_stub, Stubber(sns) as sns_stub:
        ses_stub.add_response(
            "send_email",
            {"MessageId": "ses-message-id"},
            {
                "ConfigurationSetName": "cognito-events",
                "Destination": {"ToAddresses": [email_request.destination]},
                "Message": {
                    "Body": {
                        "Text": {
                            "Charset": "UTF-8",
                            "Data": "Your verification code is 246810.",
                        }
                    },
                    "Subject": {"Charset": "UTF-8", "Data": "Your verification code"},
                },
                "ReplyToAddresses": ["support@example.test"],
                "Source": "Cognito <mailer@example.test>",
                "SourceArn": (
                    f"arn:aws:ses:{context.region}:{context.account_id}:"
                    "identity/mailer@example.test"
                ),
            },
        )
        sns_stub.add_response(
            "publish",
            {"MessageId": "sns-message-id"},
            {
                "Message": "Your verification code is 135791.",
                "MessageAttributes": {
                    "AWS.SNS.SMS.SMSType": {
                        "DataType": "String",
                        "StringValue": "Transactional",
                    }
                },
                "PhoneNumber": sms_request.destination,
            },
        )

        assert dispatcher.deliver(context, email_request) == "ses-message-id"
        assert dispatcher.deliver(context, sms_request) == "sns-message-id"

    ses.close()
    sns.close()


def test_cognito_default_email_uses_service_owned_ses_retrospection_without_identity_mutation(
    context, clients, monkeypatch
):
    from localstack.services.ses.provider import EMAILS

    default = validate_notification_configuration(None, None, context)
    dispatcher = NotificationDispatcher(default)
    identities_before = list(clients.ses.identities)
    monkeypatch.setattr(
        notification_delivery,
        "_client_factory",
        lambda *_arguments: pytest.fail("COGNITO_DEFAULT must not call public SES SendEmail"),
    )

    message_id = dispatcher.deliver(
        context,
        NotificationRequest(
            pool_id="us-east-1_pool",
            purpose="resend_confirmation",
            medium="EMAIL",
            destination="member@example.test",
            secret="246810",
            username="member",
        ),
    )
    stored = Path(config.dirs.data or config.dirs.tmp) / "ses" / f"{message_id}.json"
    try:
        message = EMAILS[message_id]
        assert message == {
            "AccountId": context.account_id,
            "Body": {"html_part": None, "text_part": "Your verification code is 246810."},
            "Destination": {"ToAddresses": ["member@example.test"]},
            "Id": message_id,
            "Region": context.region,
            "ServiceOwned": "cognito-idp",
            "Source": "no-reply@verificationemail.com",
            "Subject": "Your verification code",
            "Timestamp": message["Timestamp"],
        }
        assert json.loads(stored.read_text()) == message
        assert clients.ses.identities == identities_before
        assert clients.ses.messages == []
    finally:
        EMAILS.pop(message_id, None)
        stored.unlink(missing_ok=True)


def test_cognito_default_failure_and_aba_feed_log_delivery_without_public_ses(
    context, clients, monkeypatch
):
    events = []
    state = {"generation": "reservation-generation-old"}
    monkeypatch.setattr(
        notification_delivery,
        "_client_factory",
        lambda *_arguments: pytest.fail("COGNITO_DEFAULT must not call public SES SendEmail"),
    )
    monkeypatch.setattr(
        log_delivery,
        "_deliver",
        lambda actual_context, pool_id, source, event: events.append(
            (actual_context, pool_id, source, event)
        ),
    )
    dispatcher = NotificationDispatcher(
        validate_notification_configuration(None, None, context),
        failure_reporter=log_delivery.emit_notification_error,
    )
    request = NotificationRequest(
        pool_id="us-east-1_pool",
        purpose="resend_confirmation",
        medium="EMAIL",
        destination="member@example.test",
        secret="246810",
        username="member",
    )
    monkeypatch.setattr(
        notification_delivery,
        "_save_cognito_default_email",
        lambda *_arguments: (_ for _ in ()).throw(RuntimeError("secret 246810")),
    )

    with pytest.raises(NotificationDeliveryError):
        dispatcher.deliver_reserved(
            context,
            request,
            NotificationReservation("reservation-generation-old"),
            commit=lambda _generation: pytest.fail("failed delivery must not commit"),
            rollback=lambda generation: (
                state.clear() if state.get("generation") == generation else None
            ),
        )
    assert state == {}
    assert len(events) == 1
    assert events[0][1:] == (
        "us-east-1_pool",
        "userNotification",
        {
            "deliveryMedium": "EMAIL",
            "failureType": "RuntimeError",
            "notificationPurpose": "resend_confirmation",
        },
    )
    assert clients.ses.messages == []

    state["generation"] = "reservation-generation-old"

    def deliver_then_replace(*_arguments):
        state["generation"] = "reservation-generation-new"
        return {"MessageId": "service-owned-message"}

    monkeypatch.setattr(notification_delivery, "_save_cognito_default_email", deliver_then_replace)
    with pytest.raises(NotificationCommitError):
        dispatcher.deliver_reserved(
            context,
            request,
            NotificationReservation("reservation-generation-old"),
            commit=lambda generation: state.get("generation") == generation,
            rollback=lambda generation: (
                state.clear() if state.get("generation") == generation else None
            ),
        )
    assert state == {"generation": "reservation-generation-new"}
    assert len(events) == 1


def test_cognito_default_partial_retrospection_failure_is_rolled_back(context, monkeypatch):
    from localstack.services.ses import provider as ses_provider

    allocated = []

    def partial_write(message):
        message_id = message["Id"]
        allocated.append(message_id)
        ses_provider.EMAILS[message_id] = message
        path = Path(config.dirs.data or config.dirs.tmp) / "ses" / f"{message_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("partial secret 246810")
        raise OSError("disk full with secret 246810")

    monkeypatch.setattr(ses_provider, "save_for_retrospection", partial_write)

    with pytest.raises(OSError):
        notification_delivery._save_cognito_default_email(
            context,
            "member@example.test",
            "no-reply@verificationemail.com",
            "Your verification code",
            "Your verification code is 246810.",
        )

    assert len(allocated) == 1
    assert allocated[0] not in ses_provider.EMAILS
    path = Path(config.dirs.data or config.dirs.tmp) / "ses" / f"{allocated[0]}.json"
    assert not path.exists()
