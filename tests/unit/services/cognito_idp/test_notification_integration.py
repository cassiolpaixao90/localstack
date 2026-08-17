import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    yield value
    with cognito_idp_stores.lock:
        cognito_idp_stores.pop(value.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def _pool_and_client(provider, context):
    pool = provider.create_user_pool(
        context,
        {
            "EmailConfiguration": {"EmailSendingAccount": "COGNITO_DEFAULT"},
            "PoolName": "notifications",
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context, {"ClientName": "web", "UserPoolId": pool["Id"]}
    )["UserPoolClient"]
    return pool, client


def test_signup_delivers_outside_pool_lock_and_activates_exact_code(provider, context, monkeypatch):
    pool, client = _pool_and_client(provider, context)
    delivered = []

    def save(_context, destination, _source, _subject, message):
        assert pool["Id"] not in provider_module._POOL_LOCKS
        delivered.append((destination, message))
        return {"MessageId": "message-id"}

    monkeypatch.setattr(
        "localstack.services.cognito_idp.notification_delivery._save_cognito_default_email",
        save,
    )
    provider.sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "Password": "Password9!",
            "UserAttributes": [{"Name": "email", "Value": "user@example.test"}],
            "Username": "user",
        },
    )

    code = delivered[0][1].removeprefix("Your verification code is ").removesuffix(".")
    provider.confirm_sign_up(
        context,
        {
            "ClientId": client["ClientId"],
            "ConfirmationCode": code,
            "Username": "user",
        },
    )
    assert (
        provider.admin_get_user(context, {"UserPoolId": pool["Id"], "Username": "user"})[
            "UserStatus"
        ]
        == "CONFIRMED"
    )


def test_signup_delivery_failure_rolls_back_only_pending_generation(provider, context, monkeypatch):
    pool, client = _pool_and_client(provider, context)
    monkeypatch.setattr(
        "localstack.services.cognito_idp.notification_delivery._save_cognito_default_email",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("secret transport detail")),
    )

    with pytest.raises(CommonServiceException) as failure:
        provider.sign_up(
            context,
            {
                "ClientId": client["ClientId"],
                "Password": "Password9!",
                "UserAttributes": [{"Name": "email", "Value": "user@example.test"}],
                "Username": "user",
            },
        )
    assert failure.value.code == "CodeDeliveryFailureException"
    assert "secret transport detail" not in str(failure.value)
    assert not provider.get_store(context).user_codes
    assert (
        provider.admin_get_user(context, {"UserPoolId": pool["Id"], "Username": "user"})[
            "UserStatus"
        ]
        == "UNCONFIRMED"
    )


def test_notification_configuration_and_invitation_template_reset_on_update(provider, context):
    pool = provider.create_user_pool(
        context,
        {
            "AdminCreateUserConfig": {
                "AllowAdminCreateUserOnly": True,
                "InviteMessageTemplate": {
                    "EmailMessage": "Welcome {username}: {####}",
                    "EmailSubject": "Welcome",
                },
            },
            "EmailConfiguration": {"EmailSendingAccount": "COGNITO_DEFAULT"},
            "PoolName": "configured",
        },
    )["UserPool"]
    assert pool["EmailConfiguration"] == {"EmailSendingAccount": "COGNITO_DEFAULT"}
    assert pool["AdminCreateUserConfig"]["InviteMessageTemplate"]["EmailSubject"] == "Welcome"

    provider.update_user_pool(context, {"PoolName": "reset", "UserPoolId": pool["Id"]})
    described = provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"]
    assert "EmailConfiguration" not in described
    assert described["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": False}
