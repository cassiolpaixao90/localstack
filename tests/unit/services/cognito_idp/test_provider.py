import base64
import hashlib
import hmac
import json
import threading
import uuid

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import PasswordHash, cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import decode_jwt_segment, public_key_from_jwk
from localstack.services.plugins import Service


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    yield context
    with cognito_idp_stores.lock:
        region_bundle = cognito_idp_stores.get(context.account_id)
        if region_bundle is not None:
            for store in region_bundle.values():
                for pool_id in list(store.user_pools):
                    if store.POOL_LOCATIONS.get(pool_id) == (
                        context.account_id,
                        store._region_name,
                    ):
                        store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def provider():
    return CognitoIdpProvider()


def create_pool_and_client(provider, context, *, generate_secret=False):
    pool = provider.create_user_pool(context, {"PoolName": "web-mobile-users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "amplify-client",
            "GenerateSecret": generate_secret,
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        },
    )["UserPoolClient"]
    return pool, client


def secret_hash(username, client_id, client_secret):
    digest = hmac.new(
        client_secret.encode(), f"{username}{client_id}".encode(), hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode()


def test_provider_builds_native_service_dispatch_table(provider):
    service = Service.for_provider(provider)

    assert service.name() == "cognito-idp"
    assert {
        "AddCustomAttributes",
        "AddUserPoolClientSecret",
        "CreateUserPool",
        "CreateUserPoolClient",
        "CreateUserPoolDomain",
        "DeleteUserPoolDomain",
        "DeleteUserPoolClientSecret",
        "DescribeRiskConfiguration",
        "DescribeUserPoolDomain",
        "UpdateUserPool",
        "UpdateUserPoolDomain",
        "AdminCreateUser",
        "AdminAddUserToGroup",
        "AdminConfirmSignUp",
        "AdminForgetDevice",
        "AdminGetDevice",
        "AdminListDevices",
        "AdminDeleteUser",
        "AdminDeleteUserAttributes",
        "AdminDisableUser",
        "AdminEnableUser",
        "AdminGetUser",
        "AdminInitiateAuth",
        "AdminListUserAuthEvents",
        "AdminListGroupsForUser",
        "AdminRemoveUserFromGroup",
        "AdminResetUserPassword",
        "AdminRespondToAuthChallenge",
        "AdminSetUserMFAPreference",
        "AdminSetUserSettings",
        "AdminSetUserPassword",
        "AdminUpdateUserAttributes",
        "AdminUpdateAuthEventFeedback",
        "AdminUpdateDeviceStatus",
        "AdminUserGlobalSignOut",
        "AssociateSoftwareToken",
        "ChangePassword",
        "ConfirmForgotPassword",
        "ConfirmDevice",
        "ConfirmSignUp",
        "CompleteWebAuthnRegistration",
        "CreateGroup",
        "DeleteUser",
        "DeleteUserAttributes",
        "DeleteWebAuthnCredential",
        "DeleteGroup",
        "ForgotPassword",
        "ForgetDevice",
        "GetGroup",
        "GetDevice",
        "GetUser",
        "GetUserAuthFactors",
        "GetUserAttributeVerificationCode",
        "GetUserPoolMfaConfig",
        "GetTokensFromRefreshToken",
        "GlobalSignOut",
        "InitiateAuth",
        "ListGroups",
        "ListDevices",
        "ListUsers",
        "ListUsersInGroup",
        "ListUserPoolClientSecrets",
        "ListWebAuthnCredentials",
        "RespondToAuthChallenge",
        "ResendConfirmationCode",
        "RevokeToken",
        "SetUserMFAPreference",
        "SetUserSettings",
        "SetUserPoolMfaConfig",
        "SetRiskConfiguration",
        "SignUp",
        "StartWebAuthnRegistration",
        "UpdateUserAttributes",
        "UpdateAuthEventFeedback",
        "UpdateGroup",
        "UpdateDeviceStatus",
        "VerifyUserAttribute",
        "VerifySoftwareToken",
        "CreateResourceServer",
        "DeleteResourceServer",
        "DescribeResourceServer",
        "ListResourceServers",
        "ListTagsForResource",
        "TagResource",
        "UntagResource",
        "UpdateResourceServer",
    } <= service.skeleton.dispatch_table.keys()

    from localstack.services.providers import cognito_idp

    assert cognito_idp.name == "cognito-idp:default"
    assert cognito_idp.factory().create_service().name() == "cognito-idp"


def test_user_pool_and_client_crud(provider, context):
    pool, client = create_pool_and_client(provider, context)

    assert pool["Name"] == "web-mobile-users"
    assert pool["Arn"].startswith("arn:aws:cognito-idp:us-east-1:")
    assert (
        provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"]["Id"]
        == pool["Id"]
    )
    assert provider.list_user_pools(context, {"MaxResults": 10})["UserPools"][0]["Id"] == pool["Id"]
    assert (
        provider.describe_user_pool_client(
            context, {"UserPoolId": pool["Id"], "ClientId": client["ClientId"]}
        )["UserPoolClient"]["ClientName"]
        == "amplify-client"
    )

    updated = provider.update_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientId": client["ClientId"],
            "ClientName": "renamed",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH"],
        },
    )["UserPoolClient"]
    assert updated["ClientName"] == "renamed"

    provider.delete_user_pool_client(
        context, {"UserPoolId": pool["Id"], "ClientId": client["ClientId"]}
    )
    with pytest.raises(CommonServiceException, match="does not exist"):
        provider.describe_user_pool_client(
            context, {"UserPoolId": pool["Id"], "ClientId": client["ClientId"]}
        )

    provider.delete_user_pool(context, {"UserPoolId": pool["Id"]})
    with pytest.raises(CommonServiceException, match="does not exist"):
        provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})


def test_resource_quotas_fail_before_mutating_state(provider, context, monkeypatch):
    monkeypatch.setattr(provider_module, "_MAX_USER_POOLS_PER_ACCOUNT_REGION", 1)
    pool = provider.create_user_pool(context, {"PoolName": "first"})["UserPool"]
    with pytest.raises(CommonServiceException) as pool_quota:
        provider.create_user_pool(context, {"PoolName": "second"})
    assert pool_quota.value.code == "LimitExceededException"

    monkeypatch.setattr(provider_module, "_MAX_CLIENTS_PER_POOL", 1)
    first_client = provider.create_user_pool_client(
        context, {"ClientName": "first", "UserPoolId": pool["Id"]}
    )["UserPoolClient"]
    with pytest.raises(CommonServiceException) as client_quota:
        provider.create_user_pool_client(
            context, {"ClientName": "second", "UserPoolId": pool["Id"]}
        )
    assert client_quota.value.code == "LimitExceededException"

    monkeypatch.setattr(provider_module, "_MAX_CLIENTS_PER_POOL", 2)
    second_client = provider.create_user_pool_client(
        context, {"ClientName": "second", "UserPoolId": pool["Id"]}
    )["UserPoolClient"]
    monkeypatch.setattr(provider_module, "_MAX_MANAGED_LOGIN_BRANDING_PER_POOL", 1)
    provider.create_managed_login_branding(
        context,
        {
            "ClientId": first_client["ClientId"],
            "UseCognitoProvidedValues": True,
            "UserPoolId": pool["Id"],
        },
    )
    with pytest.raises(CommonServiceException) as branding_quota:
        provider.create_managed_login_branding(
            context,
            {
                "ClientId": second_client["ClientId"],
                "UseCognitoProvidedValues": True,
                "UserPoolId": pool["Id"],
            },
        )
    assert branding_quota.value.code == "LimitExceededException"

    monkeypatch.setattr(provider_module, "_MAX_TERMS_PER_POOL", 1)
    provider.create_terms(
        context,
        {
            "ClientId": first_client["ClientId"],
            "Enforcement": "NONE",
            "Links": {"cognito:default": "https://example.test/terms"},
            "TermsName": "terms-of-use",
            "TermsSource": "LINK",
            "UserPoolId": pool["Id"],
        },
    )
    with pytest.raises(CommonServiceException) as terms_quota:
        provider.create_terms(
            context,
            {
                "ClientId": first_client["ClientId"],
                "Enforcement": "NONE",
                "Links": {"cognito:default": "https://example.test/privacy"},
                "TermsName": "privacy-policy",
                "TermsSource": "LINK",
                "UserPoolId": pool["Id"],
            },
        )
    assert terms_quota.value.code == "LimitExceededException"


def test_update_user_pool_renames_without_replacement(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "before"})["UserPool"]

    assert provider.update_user_pool(context, {"UserPoolId": pool["Id"], "PoolName": "after"}) == {}

    updated = provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})["UserPool"]
    assert updated["Id"] == pool["Id"]
    assert updated["Name"] == "after"


def test_list_operations_return_reusable_bounded_page_tokens(provider, context):
    first_pool = provider.create_user_pool(context, {"PoolName": "first"})["UserPool"]
    second_pool = provider.create_user_pool(context, {"PoolName": "second"})["UserPool"]
    first_page = provider.list_user_pools(context, {"MaxResults": 1})
    second_page = provider.list_user_pools(
        context, {"MaxResults": 1, "NextToken": first_page["NextToken"]}
    )

    assert {first_page["UserPools"][0]["Id"], second_page["UserPools"][0]["Id"]} == {
        first_pool["Id"],
        second_pool["Id"],
    }
    assert "NextToken" not in second_page

    for index in range(61):
        provider.create_user_pool_client(
            context,
            {"UserPoolId": first_pool["Id"], "ClientName": f"client-{index:02d}"},
        )
    client_page = provider.list_user_pool_clients(
        context, {"UserPoolId": first_pool["Id"], "MaxResults": 60}
    )
    client_tail = provider.list_user_pool_clients(
        context,
        {
            "UserPoolId": first_pool["Id"],
            "MaxResults": 60,
            "NextToken": client_page["NextToken"],
        },
    )

    assert len(client_page["UserPoolClients"]) == 60
    assert len(client_tail["UserPoolClients"]) == 1
    assert "NextToken" not in client_tail


def test_pool_delete_and_client_create_are_linearized(provider, context, monkeypatch):
    from localstack.services.cognito_idp import provider as provider_module

    pool = provider.create_user_pool(context, {"PoolName": "users"})["UserPool"]
    create_entered = threading.Event()
    allow_create = threading.Event()
    delete_done = threading.Event()
    original_required_string = provider_module._required_string

    def controlled_required_string(request, key, **kwargs):
        if key == "ClientName":
            create_entered.set()
            assert allow_create.wait(timeout=2)
        return original_required_string(request, key, **kwargs)

    monkeypatch.setattr(provider_module, "_required_string", controlled_required_string)
    create_result = {}

    create_thread = threading.Thread(
        target=lambda: create_result.update(
            provider.create_user_pool_client(
                context, {"UserPoolId": pool["Id"], "ClientName": "client"}
            )
        )
    )
    delete_thread = threading.Thread(
        target=lambda: (
            provider.delete_user_pool(context, {"UserPoolId": pool["Id"]}),
            delete_done.set(),
        )
    )
    create_thread.start()
    assert create_entered.wait(timeout=2)
    delete_thread.start()
    assert not delete_done.wait(timeout=0.05)
    allow_create.set()
    create_thread.join(timeout=2)
    delete_thread.join(timeout=2)

    assert "UserPoolClient" in create_result
    assert delete_done.is_set()
    with pytest.raises(CommonServiceException):
        provider.describe_user_pool(context, {"UserPoolId": pool["Id"]})


def test_admin_create_user_supports_suppress_and_resend(provider, context, monkeypatch):
    delivered = []
    monkeypatch.setattr(
        "localstack.services.cognito_idp.notification_delivery._save_cognito_default_email",
        lambda _context, destination, _source, _subject, message: (
            delivered.append((destination, message)) or {"MessageId": "message-id"}
        ),
    )
    pool = provider.create_user_pool(context, {"PoolName": "suppressed-users"})["UserPool"]

    created = provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "Temporary9!",
            "UserPoolId": pool["Id"],
            "UserAttributes": [{"Name": "email", "Value": "suppressed@example.test"}],
            "Username": "suppressed",
        },
    )

    assert created["User"]["Username"] == "suppressed"
    assert "CodeDeliveryDetails" not in created
    resent = provider.admin_create_user(
        context,
        {
            "DesiredDeliveryMediums": ["EMAIL"],
            "MessageAction": "RESEND",
            "TemporaryPassword": "Replacement9!",
            "UserPoolId": pool["Id"],
            "Username": "suppressed",
        },
    )
    assert resent["User"]["Username"] == "suppressed"
    assert delivered == [
        (
            "suppressed@example.test",
            "Your username is suppressed and your temporary password is Replacement9!.",
        )
    ]
    with pytest.raises(CommonServiceException) as resend:
        provider.admin_create_user(
            context,
            {
                "MessageAction": "RESEND",
                "TemporaryPassword": "Temporary9!",
                "UserPoolId": pool["Id"],
                "Username": "must-not-exist",
            },
        )
    assert resend.value.code == "UserNotFoundException"
    with pytest.raises(CommonServiceException) as missing:
        provider.admin_get_user(context, {"UserPoolId": pool["Id"], "Username": "must-not-exist"})
    assert missing.value.code == "UserNotFoundException"


def test_password_auth_emits_verifiable_rs256_tokens_and_no_plaintext_password(provider, context):
    pool, client = create_pool_and_client(provider, context)
    provider.admin_create_user(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "person@example.test",
            "TemporaryPassword": "TempPass9!",
        },
    )

    with pytest.raises(CommonServiceException) as force_change:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": client["ClientId"],
                "AuthParameters": {
                    "USERNAME": "person@example.test",
                    "PASSWORD": "TempPass9!",
                },
            },
        )
    assert force_change.value.code == "NotAuthorizedException"

    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "person@example.test",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )
    auth = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {
                "USERNAME": "person@example.test",
                "PASSWORD": "PermanentPass9!",
            },
        },
    )["AuthenticationResult"]

    header = decode_jwt_segment(auth["IdToken"].split(".")[0])
    claims = decode_jwt_segment(auth["IdToken"].split(".")[1])
    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"
    assert claims["iss"] == f"https://cognito-idp.us-east-1.amazonaws.com/{pool['Id']}"
    assert claims["aud"] == client["ClientId"]
    assert claims["token_use"] == "id"
    assert claims["cognito:username"] == "person@example.test"

    jwk = next(
        key for key in provider.get_jwks(context, pool["Id"])["keys"] if key["kid"] == header["kid"]
    )
    assert header["kid"] == jwk["kid"]
    signing_input, encoded_signature = auth["IdToken"].rsplit(".", 1)
    signature = base64.urlsafe_b64decode(encoded_signature + "==")
    public_key_from_jwk(jwk).verify(
        signature, signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()
    )

    user = provider.get_store(context).user_pools[pool["Id"]].users["person@example.test"]
    assert "PermanentPass9!" not in json.dumps(user.password.to_dict())


def test_refresh_token_is_opaque_scoped_and_revocable(provider, context):
    pool, client = create_pool_and_client(provider, context)
    provider.admin_create_user(
        context,
        {"UserPoolId": pool["Id"], "Username": "alice", "TemporaryPassword": "TempPass9!"},
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "alice",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )
    initial = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {"USERNAME": "alice", "PASSWORD": "PermanentPass9!"},
        },
    )["AuthenticationResult"]
    refresh_token = initial["RefreshToken"]
    assert refresh_token.count(".") == 0

    refreshed = provider.initiate_auth(
        context,
        {
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {"REFRESH_TOKEN": refresh_token},
        },
    )["AuthenticationResult"]
    assert "IdToken" in refreshed
    assert "RefreshToken" not in refreshed

    provider.revoke_token(context, {"ClientId": client["ClientId"], "Token": refresh_token})
    with pytest.raises(CommonServiceException) as revoked:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "ClientId": client["ClientId"],
                "AuthParameters": {"REFRESH_TOKEN": refresh_token},
            },
        )
    assert revoked.value.code == "NotAuthorizedException"


def test_refresh_sessions_are_bounded_per_user_and_client(provider, context, monkeypatch):
    from localstack.services.cognito_idp import provider as provider_module

    pool, client = create_pool_and_client(provider, context)
    provider.admin_create_user(
        context,
        {"UserPoolId": pool["Id"], "Username": "alice", "TemporaryPassword": "TempPass9!"},
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "alice",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )
    monkeypatch.setattr(PasswordHash, "verify", lambda self, candidate: True)
    monkeypatch.setattr(provider_module, "sign_jwt", lambda *args, **kwargs: "signed-token")
    first_refresh = None
    for _ in range(65):
        result = provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": client["ClientId"],
                "AuthParameters": {"USERNAME": "alice", "PASSWORD": "PermanentPass9!"},
            },
        )["AuthenticationResult"]
        first_refresh = first_refresh or result["RefreshToken"]

    sessions = provider.get_store(context).refresh_sessions
    matching = [session for session in sessions.values() if session.client_id == client["ClientId"]]
    assert len(matching) == 64
    assert provider_module._token_hash(first_refresh) not in sessions


def test_refresh_store_capacity_never_evicts_another_pool(provider, context, monkeypatch):
    from localstack.services.cognito_idp import provider as provider_module

    monkeypatch.setattr(provider_module, "_MAX_REFRESH_SESSIONS_PER_POOL", 2)
    monkeypatch.setattr(provider_module, "_MAX_REFRESH_SESSIONS_PER_STORE", 2)
    monkeypatch.setattr(provider_module, "sign_jwt", lambda *args, **kwargs: "signed-token")
    created = []
    for index in range(2):
        pool, client = create_pool_and_client(provider, context)
        username = f"user-{index}"
        provider.admin_create_user(
            context,
            {
                "UserPoolId": pool["Id"],
                "Username": username,
                "TemporaryPassword": "TempPass9!",
            },
        )
        provider.admin_set_user_password(
            context,
            {
                "UserPoolId": pool["Id"],
                "Username": username,
                "Password": "PermanentPass9!",
                "Permanent": True,
            },
        )
        created.append((pool, client, username))

    def authenticate(item):
        pool, client, username = item
        return provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": client["ClientId"],
                "AuthParameters": {"USERNAME": username, "PASSWORD": "PermanentPass9!"},
            },
        )["AuthenticationResult"]["RefreshToken"]

    victim = authenticate(created[0])
    attacker = authenticate(created[1])
    with pytest.raises(CommonServiceException) as full:
        authenticate(created[1])

    assert full.value.code == "LimitExceededException"
    sessions = provider.get_store(context).refresh_sessions
    assert provider_module._token_hash(victim) in sessions
    assert provider_module._token_hash(attacker) in sessions


def test_client_secret_and_auth_flow_fail_closed(provider, context):
    pool, client = create_pool_and_client(provider, context, generate_secret=True)
    provider.admin_create_user(
        context,
        {"UserPoolId": pool["Id"], "Username": "alice", "TemporaryPassword": "TempPass9!"},
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "alice",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )

    request = {
        "AuthFlow": "USER_PASSWORD_AUTH",
        "ClientId": client["ClientId"],
        "AuthParameters": {"USERNAME": "alice", "PASSWORD": "PermanentPass9!"},
    }
    with pytest.raises(CommonServiceException) as missing_hash:
        provider.initiate_auth(context, request)
    assert missing_hash.value.code == "NotAuthorizedException"

    request["AuthParameters"]["SECRET_HASH"] = secret_hash(
        "alice", client["ClientId"], client["ClientSecret"]
    )
    assert "AuthenticationResult" in provider.initiate_auth(context, request)

    with pytest.raises(CommonServiceException) as unsupported:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_SRP_AUTH",
                "ClientId": client["ClientId"],
                "AuthParameters": {"USERNAME": "alice", "SRP_A": "not-implemented"},
            },
        )
    assert unsupported.value.code == "InvalidParameterException"


def test_custom_user_attributes_cannot_override_signed_security_claims(provider, context):
    pool, client = create_pool_and_client(provider, context)
    provider.admin_create_user(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "alice",
            "TemporaryPassword": "TempPass9!",
            "UserAttributes": [
                {"Name": "custom:iss", "Value": "https://attacker.invalid"},
                {"Name": "custom:aud", "Value": "wrong-client"},
                {"Name": "custom:exp", "Value": "never"},
                {"Name": "custom:iat", "Value": "never"},
                {"Name": "custom:token_use", "Value": "access"},
            ],
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "alice",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )

    token = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {"USERNAME": "alice", "PASSWORD": "PermanentPass9!"},
        },
    )["AuthenticationResult"]["IdToken"]
    claims = decode_jwt_segment(token.split(".")[1])

    assert claims["iss"].startswith("https://cognito-idp.us-east-1.amazonaws.com/")
    assert claims["aud"] == client["ClientId"]
    assert isinstance(claims["exp"], int)
    assert isinstance(claims["iat"], int)
    assert claims["token_use"] == "id"


@pytest.mark.parametrize(
    "operation,payload",
    [
        ("create_user_pool", {"PoolName": "users", "UnsupportedPoolField": "not-implemented"}),
        (
            "create_user_pool_client",
            {
                "UserPoolId": "placeholder",
                "ClientName": "client",
                "UnsupportedClientField": "not-implemented",
            },
        ),
    ],
)
def test_create_operations_reject_unsupported_fields(provider, context, operation, payload):
    if operation == "create_user_pool_client":
        payload["UserPoolId"] = provider.create_user_pool(context, {"PoolName": "users"})[
            "UserPool"
        ]["Id"]

    with pytest.raises(CommonServiceException) as unsupported:
        getattr(provider, operation)(context, payload)

    assert unsupported.value.code == "InvalidParameterException"
    assert "Unsupported" in unsupported.value.message


def test_client_accepts_custom_auth_flow_and_updates_validity(provider, context):
    pool, client = create_pool_and_client(provider, context)

    custom_client = provider.create_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "custom-auth-client",
            "ExplicitAuthFlows": ["ALLOW_CUSTOM_AUTH"],
        },
    )["UserPoolClient"]
    assert custom_client["ExplicitAuthFlows"] == ["ALLOW_CUSTOM_AUTH"]

    updated = provider.update_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientId": client["ClientId"],
            "AccessTokenValidity": 10,
        },
    )["UserPoolClient"]
    assert updated["AccessTokenValidity"] == 10


def test_access_and_id_tokens_use_distinct_signing_keys_and_access_expiry(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "client",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "AccessTokenValidity": 120,
            "IdTokenValidity": 5,
            "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes"},
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {"UserPoolId": pool["Id"], "Username": "alice", "TemporaryPassword": "TempPass9!"},
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "alice",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )

    auth = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {"USERNAME": "alice", "PASSWORD": "PermanentPass9!"},
        },
    )["AuthenticationResult"]
    access_header = decode_jwt_segment(auth["AccessToken"].split(".")[0])
    id_header = decode_jwt_segment(auth["IdToken"].split(".")[0])
    jwks = provider.get_jwks(context, pool["Id"])["keys"]

    assert access_header["kid"] != id_header["kid"]
    assert {key["kid"] for key in jwks} == {access_header["kid"], id_header["kid"]}
    assert auth["ExpiresIn"] == 120 * 60
    assert client["TokenValidityUnits"] == {
        "AccessToken": "minutes",
        "IdToken": "minutes",
        "RefreshToken": "days",
    }


def test_token_validity_defaults_and_duration_bounds(provider, context):
    pool = provider.create_user_pool(context, {"PoolName": "users"})["UserPool"]
    default_client = provider.create_user_pool_client(
        context,
        {"UserPoolId": pool["Id"], "ClientName": "default"},
    )["UserPoolClient"]

    assert default_client["AccessTokenValidity"] == 1
    assert default_client["IdTokenValidity"] == 1
    assert default_client["RefreshTokenValidity"] == 30
    assert default_client["TokenValidityUnits"] == {
        "AccessToken": "hours",
        "IdToken": "hours",
        "RefreshToken": "days",
    }

    with pytest.raises(CommonServiceException) as too_long:
        provider.create_user_pool_client(
            context,
            {
                "UserPoolId": pool["Id"],
                "ClientName": "invalid",
                "AccessTokenValidity": 25,
                "TokenValidityUnits": {"AccessToken": "hours"},
            },
        )
    assert too_long.value.code == "InvalidParameterException"


@pytest.mark.parametrize(
    "reserved_name",
    [
        "aud",
        "auth_time",
        "client_id",
        "cognito:groups",
        "cognito:preferred_role",
        "cognito:roles",
        "cognito:username",
        "device_key",
        "event_id",
        "exp",
        "iat",
        "identities",
        "iss",
        "jti",
        "nonce",
        "origin_jti",
        "scope",
        "sub",
        "token_use",
        "username",
    ],
)
def test_admin_create_user_rejects_reserved_token_claim_attributes(
    provider, context, reserved_name
):
    pool, _ = create_pool_and_client(provider, context)

    with pytest.raises(CommonServiceException) as reserved:
        provider.admin_create_user(
            context,
            {
                "UserPoolId": pool["Id"],
                "Username": "alice",
                "TemporaryPassword": "TempPass9!",
                "UserAttributes": [{"Name": reserved_name, "Value": "forged"}],
            },
        )

    assert reserved.value.code == "InvalidParameterException"
    assert "reserved" in reserved.value.message


def test_tokens_have_minimum_cognito_identity_and_revocation_claims(provider, context):
    pool, client = create_pool_and_client(provider, context)
    provider.admin_create_user(
        context,
        {"UserPoolId": pool["Id"], "Username": "alice", "TemporaryPassword": "TempPass9!"},
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "alice",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )

    auth = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {"USERNAME": "alice", "PASSWORD": "PermanentPass9!"},
        },
    )["AuthenticationResult"]
    access = decode_jwt_segment(auth["AccessToken"].split(".")[1])
    identity = decode_jwt_segment(auth["IdToken"].split(".")[1])

    for claims in (access, identity):
        assert isinstance(claims["auth_time"], int)
        assert uuid.UUID(claims["event_id"])
        assert uuid.UUID(claims["jti"])
        assert uuid.UUID(claims["origin_jti"])
    assert access["username"] == "alice"
    assert "cognito:username" not in access
    assert identity["cognito:username"] == "alice"
    assert "username" not in identity
    assert access["origin_jti"] == identity["origin_jti"]


def test_auth_and_admin_handlers_validate_modeled_inputs(provider, context):
    pool, client = create_pool_and_client(provider, context)

    created = provider.admin_create_user(
        context,
        {
            "ClientMetadata": {"source": "admin-api"},
            "TemporaryPassword": "TempPass9!",
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    assert created["User"]["Username"] == "alice"

    with pytest.raises(CommonServiceException) as auth_context:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {"USERNAME": "alice", "PASSWORD": "PermanentPass9!"},
                "ClientId": client["ClientId"],
                "UserContextData": {"UnsupportedContext": "fail-closed"},
            },
        )
    assert auth_context.value.code == "InvalidParameterException"

    with pytest.raises(CommonServiceException) as auth_parameter:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "DEVICE_KEY": "ignored-before-p1",
                    "PASSWORD": "PermanentPass9!",
                    "USERNAME": "alice",
                },
                "ClientId": client["ClientId"],
            },
        )
    assert auth_parameter.value.code == "InvalidParameterException"


@pytest.mark.parametrize(
    "attributes",
    [
        [{"Name": "x" * 33, "Value": "value"}],
        [{"Name": "custom:large", "Value": "x" * 2049}],
        [{"Name": f"custom:item{index}", "Value": "x"} for index in range(33)],
        [{"Name": "custom:invalid", "Value": "\ud800"}],
    ],
)
def test_admin_create_user_rejects_oversized_or_invalid_utf8_attributes(
    provider, context, attributes
):
    pool, _ = create_pool_and_client(provider, context)

    with pytest.raises(CommonServiceException) as invalid:
        provider.admin_create_user(
            context,
            {
                "TemporaryPassword": "TempPass9!",
                "UserAttributes": attributes,
                "UserPoolId": pool["Id"],
                "Username": "alice",
            },
        )

    assert invalid.value.code == "InvalidParameterException"


def test_admin_create_user_rejects_duplicate_attributes(provider, context):
    pool, _ = create_pool_and_client(provider, context)

    with pytest.raises(CommonServiceException) as duplicate:
        provider.admin_create_user(
            context,
            {
                "TemporaryPassword": "TempPass9!",
                "UserAttributes": [
                    {"Name": "email", "Value": "first@example.test"},
                    {"Name": "email", "Value": "second@example.test"},
                ],
                "UserPoolId": pool["Id"],
                "Username": "alice",
            },
        )

    assert duplicate.value.code == "InvalidParameterException"
    assert "Duplicate" in duplicate.value.message


def test_global_pool_location_index_isolated_and_cleaned_up(provider, context):
    from localstack.services.cognito_idp.models import resolve_pool_location

    other_context = RequestContext(None)
    other_context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    other_context.region = "eu-west-1"
    first = provider.create_user_pool(context, {"PoolName": "first"})["UserPool"]
    second = provider.create_user_pool(other_context, {"PoolName": "second"})["UserPool"]

    assert resolve_pool_location(first["Id"]) == (context.account_id, context.region)
    assert resolve_pool_location(second["Id"]) == (
        other_context.account_id,
        other_context.region,
    )
    assert len(provider.get_jwks_for_pool_id(first["Id"])["keys"]) == 2
    assert len(provider.get_jwks_for_pool_id(second["Id"])["keys"]) == 2

    provider.delete_user_pool(context, {"UserPoolId": first["Id"]})

    assert resolve_pool_location(first["Id"]) is None
    assert resolve_pool_location(second["Id"]) == (
        other_context.account_id,
        other_context.region,
    )
    provider.delete_user_pool(other_context, {"UserPoolId": second["Id"]})
    assert resolve_pool_location(second["Id"]) is None
    with pytest.raises(CommonServiceException) as deleted:
        provider.get_jwks_for_pool_id(second["Id"])
    assert deleted.value.code == "ResourceNotFoundException"


def test_refresh_auth_and_revoke_are_serialized_by_store_lock(provider, context, monkeypatch):
    pool, client = create_pool_and_client(provider, context)
    provider.admin_create_user(
        context,
        {"UserPoolId": pool["Id"], "Username": "alice", "TemporaryPassword": "TempPass9!"},
    )
    provider.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "alice",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )
    refresh_token = provider.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {"USERNAME": "alice", "PASSWORD": "PermanentPass9!"},
        },
    )["AuthenticationResult"]["RefreshToken"]

    from localstack.services.cognito_idp import provider as provider_module

    original_sign_jwt = provider_module.sign_jwt
    signing_started = threading.Event()
    allow_signing = threading.Event()
    refresh_done = threading.Event()
    revoke_done = threading.Event()

    def controlled_sign_jwt(*args, **kwargs):
        signing_started.set()
        assert allow_signing.wait(timeout=2)
        return original_sign_jwt(*args, **kwargs)

    monkeypatch.setattr(provider_module, "sign_jwt", controlled_sign_jwt)

    refresh_thread = threading.Thread(
        target=lambda: (
            provider.initiate_auth(
                context,
                {
                    "AuthFlow": "REFRESH_TOKEN_AUTH",
                    "ClientId": client["ClientId"],
                    "AuthParameters": {"REFRESH_TOKEN": refresh_token},
                },
            ),
            refresh_done.set(),
        )
    )
    revoke_thread = threading.Thread(
        target=lambda: (
            provider.revoke_token(
                context, {"ClientId": client["ClientId"], "Token": refresh_token}
            ),
            revoke_done.set(),
        )
    )
    refresh_thread.start()
    assert signing_started.wait(timeout=2)
    revoke_thread.start()
    assert not revoke_done.wait(timeout=0.1)

    allow_signing.set()
    refresh_thread.join(timeout=2)
    revoke_thread.join(timeout=2)
    assert refresh_done.is_set()
    assert revoke_done.is_set()
