import base64
import concurrent.futures
import json
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from moto.iam.models import iam_backends
from moto.sts.models import sts_backends

from localstack.aws.accounts import get_account_id_from_access_key_id
from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.forwarder import create_aws_request_context
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from localstack.services.cognito_idp.tokens import sign_jwt
from localstack.services.iam.iam_patches import apply_iam_patches
from localstack.services.sts.credentials import resolve_session
from localstack.services.sts.models import sts_stores
from localstack.services.sts.provider import StsProvider
from localstack.state import pickle
from localstack.utils.aws.request_context import mock_aws_request_headers


@pytest.fixture
def context():
    value = RequestContext(None)
    value.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    value.region = "us-east-1"
    value.partition = "aws"
    apply_iam_patches()
    yield value
    _remove_account(value)


@pytest.fixture
def provider():
    return CognitoIdentityProvider()


def _remove_account(context):
    with cognito_identity_stores.lock:
        bundle = cognito_identity_stores.get(context.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.identity_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
                for identity_id in list(store.identities):
                    store.IDENTITY_LOCATIONS.pop(identity_id, None)
            cognito_identity_stores.pop(context.account_id, None)
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(context.account_id)
        if bundle is not None:
            for store in bundle.values():
                for pool_id in list(store.user_pools):
                    store.POOL_LOCATIONS.pop(pool_id, None)
            cognito_idp_stores.pop(context.account_id, None)
    sts_stores.pop(context.account_id, None)
    iam_backends[context.account_id][context.partition].reset()
    sts_backends[context.account_id][context.partition].reset()


def _pool(provider, context, *, allow_guest=True, allow_classic=False, cognito_providers=None):
    return provider.create_identity_pool(
        context,
        {
            "IdentityPoolName": "credential-pool",
            "AllowUnauthenticatedIdentities": allow_guest,
            "AllowClassicFlow": allow_classic,
            "CognitoIdentityProviders": cognito_providers or [],
        },
    )


def _trust(pool_id, amr, **overrides):
    statement = {
        "Effect": "Allow",
        "Principal": {"Federated": "cognito-identity.amazonaws.com"},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
            "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
        },
    }
    statement.update(overrides)
    return {"Version": "2012-10-17", "Statement": [statement]}


def _role(context, name, policy):
    role = iam_backends[context.account_id][context.partition].create_role(
        role_name=name,
        assume_role_policy_document=json.dumps(policy),
        path="/",
        permissions_boundary=None,
        description="",
        tags=[],
        max_session_duration="3600",
    )
    return role.arn


def _configure_role(provider, context, pool_id, identity_type, policy=None):
    role_arn = _role(
        context,
        f"{identity_type}-{uuid.uuid4().hex[:8]}",
        policy or _trust(pool_id, identity_type),
    )
    provider.set_identity_pool_roles(
        context,
        {"IdentityPoolId": pool_id, "Roles": {identity_type: role_arn}},
    )
    return role_arn


def _native_login(context):
    idp = CognitoIdpProvider()
    pool = idp.create_user_pool(context, {"PoolName": "credential-users"})["UserPool"]
    client = idp.create_user_pool_client(
        context,
        {
            "UserPoolId": pool["Id"],
            "ClientName": "mobile",
            "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        },
    )["UserPoolClient"]
    idp.admin_create_user(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "credential-user@example.test",
            "TemporaryPassword": "TempPass9!",
        },
    )
    idp.admin_set_user_password(
        context,
        {
            "UserPoolId": pool["Id"],
            "Username": "credential-user@example.test",
            "Password": "PermanentPass9!",
            "Permanent": True,
        },
    )
    token = idp.initiate_auth(
        context,
        {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client["ClientId"],
            "AuthParameters": {
                "USERNAME": "credential-user@example.test",
                "PASSWORD": "PermanentPass9!",
            },
        },
    )["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{context.region}.amazonaws.com/{pool['Id']}"
    configuration = {
        "ClientId": client["ClientId"],
        "ProviderName": provider_name,
        "ServerSideTokenCheck": True,
    }
    return provider_name, token, configuration


def _token_with_role_claims(context, provider_name, token, **claims):
    encoded_claims = token.split(".")[1]
    payload = json.loads(
        base64.urlsafe_b64decode(encoded_claims + "=" * (-len(encoded_claims) % 4))
    )
    payload.update(claims)
    pool_id = provider_name.rsplit("/", 1)[1]
    with cognito_idp_stores.lock:
        pool = cognito_idp_stores[context.account_id][context.region].user_pools[pool_id]
        return sign_jwt(
            pool.id_signing_private_key_pem,
            pool.id_signing_key_id,
            payload,
            now=payload["iat"],
        )


def test_guest_enhanced_flow_issues_unique_registered_temporary_credentials(provider, context):
    pool = _pool(provider, context)
    role_arn = _configure_role(provider, context, pool["IdentityPoolId"], "unauthenticated")
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})

    first = provider.get_credentials_for_identity(context, identity)
    second = provider.get_credentials_for_identity(context, identity)

    assert first["IdentityId"] == identity["IdentityId"]
    assert second["IdentityId"] == identity["IdentityId"]
    assert first["Credentials"]["AccessKeyId"] != second["Credentials"]["AccessKeyId"]
    assert first["Credentials"]["SecretKey"]
    assert first["Credentials"]["SessionToken"]
    assert timedelta(minutes=55) <= first["Credentials"]["Expiration"] - datetime.now(UTC)
    assert first["Credentials"]["Expiration"] - datetime.now(UTC) <= timedelta(minutes=61)

    access_key = first["Credentials"]["AccessKeyId"]
    session = resolve_session(access_key, account_id=context.account_id)
    assert session is not None
    user_id, caller_arn, account_id = (
        session.assumed_role_id,
        session.assumed_role_arn,
        session.account_id,
    )
    assert account_id == context.account_id
    assert get_account_id_from_access_key_id(access_key) == context.account_id
    assert caller_arn.startswith(f"arn:{context.partition}:sts::{context.account_id}:assumed-role/")
    assert role_arn.rsplit("/", 1)[1] in caller_arn
    assert user_id.endswith(identity["IdentityId"].replace(":", "-")[-64:])

    sts_context = create_aws_request_context(
        service_name="sts",
        action="GetCallerIdentity",
        parameters={},
        region=context.region,
    )
    sts_context.account_id = context.account_id
    sts_context.partition = context.partition
    sts_context.request.headers.update(
        mock_aws_request_headers("sts", aws_access_key_id=access_key, region_name=context.region)
    )
    sts_context.request.headers["x-moto-account-id"] = context.account_id
    caller = StsProvider().get_caller_identity(sts_context)
    assert caller == {"Account": context.account_id, "Arn": caller_arn, "UserId": user_id}


@pytest.mark.parametrize(
    "policy_factory",
    [
        lambda pool_id: _trust(
            pool_id,
            "unauthenticated",
            Principal={"Federated": "accounts.example"},
        ),
        lambda pool_id: _trust(pool_id, "unauthenticated", Action="sts:*"),
        lambda pool_id: _trust(
            pool_id,
            "unauthenticated",
            Condition={
                "StringEquals": {"cognito-identity.amazonaws.com:aud": "wrong-pool"},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
            },
        ),
        lambda pool_id: _trust(pool_id, "authenticated"),
        lambda pool_id: _trust(
            pool_id,
            "unauthenticated",
            Condition={
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "*"},
            },
        ),
        lambda pool_id: _trust(
            pool_id,
            "unauthenticated",
            Condition={
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
                "StringLike": {"confusing.example:claim": "*"},
            },
        ),
    ],
)
def test_trust_policy_is_fail_closed_without_issuing_credentials(provider, context, policy_factory):
    pool = _pool(provider, context)
    _configure_role(
        provider,
        context,
        pool["IdentityPoolId"],
        "unauthenticated",
        policy_factory(pool["IdentityPoolId"]),
    )
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})

    with pytest.raises(CommonServiceException) as error:
        provider.get_credentials_for_identity(context, identity)

    assert error.value.code == "InvalidIdentityPoolConfigurationException"
    with cognito_identity_stores.lock:
        assert not cognito_identity_stores[context.account_id][context.region].credential_sessions


def test_authenticated_identity_requires_valid_linked_logins_and_authenticated_role(
    provider, context
):
    provider_name, token, configuration = _native_login(context)
    pool = _pool(
        provider,
        context,
        allow_guest=False,
        cognito_providers=[configuration],
    )
    role_arn = _configure_role(provider, context, pool["IdentityPoolId"], "authenticated")
    identity = provider.get_id(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "Logins": {provider_name: token},
        },
    )

    for request in (
        identity,
        {**identity, "Logins": {provider_name: "not-a-token"}},
    ):
        with pytest.raises(CommonServiceException) as error:
            provider.get_credentials_for_identity(context, request)
        assert error.value.code == "NotAuthorizedException"

    response = provider.get_credentials_for_identity(
        context,
        {**identity, "Logins": {provider_name: token}},
    )
    session = resolve_session(response["Credentials"]["AccessKeyId"], account_id=context.account_id)
    assert session is not None
    assert role_arn.rsplit("/", 1)[1] in session.assumed_role_arn


def test_principal_tag_map_derives_only_configured_verified_claims_for_sts(provider, context):
    provider_name, token, configuration = _native_login(context)
    pool = _pool(
        provider,
        context,
        allow_guest=False,
        cognito_providers=[configuration],
    )
    pool_id = pool["IdentityPoolId"]
    _configure_role(provider, context, pool_id, "authenticated")
    provider.set_principal_tag_attribute_map(
        context,
        {
            "IdentityPoolId": pool_id,
            "IdentityProviderName": provider_name,
            "PrincipalTags": {"tenant": "custom:tenantId"},
            "UseDefaults": False,
        },
    )
    tagged_token = _token_with_role_claims(
        context,
        provider_name,
        token,
        **{"custom:tenantId": "diagnostic", "unmapped": "must-not-propagate"},
    )
    identity = provider.get_id(
        context,
        {"IdentityPoolId": pool_id, "Logins": {provider_name: tagged_token}},
    )

    response = provider.get_credentials_for_identity(
        context,
        {**identity, "Logins": {provider_name: tagged_token}},
    )

    access_key_id = response["Credentials"]["AccessKeyId"]
    assert sts_stores[context.account_id][context.region].sessions[access_key_id] == {
        "iam_context": {},
        "tags": {"tenant": {"Key": "tenant", "Value": "diagnostic"}},
        "transitive_tags": [],
    }


@pytest.mark.parametrize("claim_value", ["", "x" * 257, ["diagnostic"], {"tenant": "x"}])
def test_principal_tag_map_rejects_unbounded_or_structured_claims_without_credentials(
    provider, context, claim_value
):
    provider_name, token, configuration = _native_login(context)
    pool = _pool(
        provider,
        context,
        allow_guest=False,
        cognito_providers=[configuration],
    )
    pool_id = pool["IdentityPoolId"]
    _configure_role(provider, context, pool_id, "authenticated")
    provider.set_principal_tag_attribute_map(
        context,
        {
            "IdentityPoolId": pool_id,
            "IdentityProviderName": provider_name,
            "PrincipalTags": {"tenant": "custom:tenantId"},
            "UseDefaults": False,
        },
    )
    malformed_token = _token_with_role_claims(
        context, provider_name, token, **{"custom:tenantId": claim_value}
    )
    identity = provider.get_id(
        context,
        {"IdentityPoolId": pool_id, "Logins": {provider_name: malformed_token}},
    )

    with pytest.raises(CommonServiceException) as error:
        provider.get_credentials_for_identity(
            context,
            {**identity, "Logins": {provider_name: malformed_token}},
        )

    assert error.value.code == "InvalidIdentityPoolConfigurationException"
    with cognito_identity_stores.lock:
        assert not cognito_identity_stores[context.account_id][context.region].credential_sessions


def test_token_role_mapping_preferred_and_custom_roles_reach_local_sts(provider, context):
    provider_name, token, configuration = _native_login(context)
    pool = _pool(
        provider,
        context,
        allow_guest=False,
        allow_classic=True,
        cognito_providers=[configuration],
    )
    pool_id = pool["IdentityPoolId"]
    default_role = _role(context, "default-auth", _trust(pool_id, "authenticated"))
    preferred_role = _role(context, "preferred-auth", _trust(pool_id, "authenticated"))
    alternate_role = _role(context, "alternate-auth", _trust(pool_id, "authenticated"))
    provider.set_identity_pool_roles(
        context,
        {
            "IdentityPoolId": pool_id,
            "Roles": {"authenticated": default_role},
            "RoleMappings": {
                f"{provider_name}:{configuration['ClientId']}": {
                    "Type": "Token",
                    "AmbiguousRoleResolution": "Deny",
                }
            },
        },
    )
    identity = provider.get_id(
        context, {"IdentityPoolId": pool_id, "Logins": {provider_name: token}}
    )
    mapped_token = _token_with_role_claims(
        context,
        provider_name,
        token,
        **{
            "cognito:roles": [alternate_role, preferred_role],
            "cognito:preferred_role": preferred_role,
        },
    )

    preferred = provider.get_credentials_for_identity(
        context, {**identity, "Logins": {provider_name: mapped_token}}
    )
    custom = provider.get_credentials_for_identity(
        context,
        {
            **identity,
            "Logins": {provider_name: mapped_token},
            "CustomRoleArn": alternate_role,
        },
    )
    for response, selected in ((preferred, preferred_role), (custom, alternate_role)):
        session = resolve_session(
            response["Credentials"]["AccessKeyId"], account_id=context.account_id
        )
        assert session is not None
        assert selected.rsplit("/", 1)[1] in session.assumed_role_arn

    with pytest.raises(CommonServiceException) as arbitrary:
        provider.get_credentials_for_identity(
            context,
            {
                **identity,
                "Logins": {provider_name: mapped_token},
                "CustomRoleArn": default_role,
            },
        )
    assert arbitrary.value.code == "NotAuthorizedException"

    ambiguous_token = _token_with_role_claims(
        context,
        provider_name,
        token,
        **{"cognito:roles": [alternate_role, preferred_role]},
    )
    with pytest.raises(CommonServiceException) as ambiguous:
        provider.get_credentials_for_identity(
            context, {**identity, "Logins": {provider_name: ambiguous_token}}
        )
    assert ambiguous.value.code == "NotAuthorizedException"

    invalid_preferred = _token_with_role_claims(
        context,
        provider_name,
        token,
        **{
            "cognito:roles": [alternate_role],
            "cognito:preferred_role": preferred_role,
        },
    )
    with pytest.raises(CommonServiceException) as invalid_claim:
        provider.get_credentials_for_identity(
            context, {**identity, "Logins": {provider_name: invalid_preferred}}
        )
    assert invalid_claim.value.code == "NotAuthorizedException"

    identity_token = provider.get_open_id_token(
        context, {**identity, "Logins": {provider_name: mapped_token}}
    )["Token"]
    with pytest.raises(CommonServiceException) as mapping_bypass:
        provider.get_credentials_for_identity(
            context,
            {
                **identity,
                "Logins": {"cognito-identity.amazonaws.com": identity_token},
            },
        )
    assert mapping_bypass.value.code == "NotAuthorizedException"


def test_rules_role_mapping_first_match_and_ambiguous_fallback(provider, context):
    provider_name, token, configuration = _native_login(context)
    pool = _pool(provider, context, allow_guest=False, cognito_providers=[configuration])
    pool_id = pool["IdentityPoolId"]
    default_role = _role(context, "rules-default", _trust(pool_id, "authenticated"))
    engineering_role = _role(context, "rules-engineering", _trust(pool_id, "authenticated"))
    provider.set_identity_pool_roles(
        context,
        {
            "IdentityPoolId": pool_id,
            "Roles": {"authenticated": default_role},
            "RoleMappings": {
                f"{provider_name}:{configuration['ClientId']}": {
                    "Type": "Rules",
                    "AmbiguousRoleResolution": "AuthenticatedRole",
                    "RulesConfiguration": {
                        "Rules": [
                            {
                                "Claim": "department",
                                "MatchType": "Equals",
                                "RoleARN": engineering_role,
                                "Value": "engineering",
                            }
                        ]
                    },
                }
            },
        },
    )
    identity = provider.get_id(
        context, {"IdentityPoolId": pool_id, "Logins": {provider_name: token}}
    )
    matching = _token_with_role_claims(context, provider_name, token, department="engineering")
    no_match = _token_with_role_claims(context, provider_name, token, department="finance")

    for mapped_token, selected in ((matching, engineering_role), (no_match, default_role)):
        response = provider.get_credentials_for_identity(
            context, {**identity, "Logins": {provider_name: mapped_token}}
        )
        session = resolve_session(
            response["Credentials"]["AccessKeyId"], account_id=context.account_id
        )
        assert session is not None
        assert selected.rsplit("/", 1)[1] in session.assumed_role_arn


def test_identity_ownership_state_and_guest_custom_role_fail_closed(provider, context):
    pool = _pool(provider, context)
    role_arn = _configure_role(provider, context, pool["IdentityPoolId"], "unauthenticated")
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})

    with pytest.raises(CommonServiceException) as custom:
        provider.get_credentials_for_identity(context, {**identity, "CustomRoleArn": role_arn})
    assert custom.value.code == "NotAuthorizedException"
    with pytest.raises(CommonServiceException) as arbitrary:
        provider.get_credentials_for_identity(
            context, {"IdentityId": f"{context.region}:{uuid.uuid4()}"}
        )
    assert arbitrary.value.code == "ResourceNotFoundException"
    other_context = RequestContext(None)
    other_context.account_id = f"{(int(context.account_id) + 1) % 10**12:012d}"
    other_context.region = context.region
    other_context.partition = context.partition
    with pytest.raises(CommonServiceException) as wrong_account:
        provider.get_credentials_for_identity(other_context, identity)
    assert wrong_account.value.code == "ResourceNotFoundException"

    provider.update_identity_pool(
        context,
        {
            "IdentityPoolId": pool["IdentityPoolId"],
            "IdentityPoolName": "credential-pool",
            "AllowUnauthenticatedIdentities": False,
        },
    )
    with pytest.raises(CommonServiceException) as guest_disabled:
        provider.get_credentials_for_identity(context, identity)
    assert guest_disabled.value.code == "NotAuthorizedException"

    with cognito_identity_stores.lock:
        cognito_identity_stores[context.account_id][context.region].identities[
            identity["IdentityId"]
        ].enabled = False
    with pytest.raises(CommonServiceException) as identity_disabled:
        provider.get_credentials_for_identity(context, identity)
    assert identity_disabled.value.code == "NotAuthorizedException"


def test_missing_and_cross_account_roles_never_issue_credentials(provider, context):
    pool = _pool(provider, context)
    role_arn = _configure_role(provider, context, pool["IdentityPoolId"], "unauthenticated")
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    role_name = role_arn.rsplit("/", 1)[1]
    iam_backends[context.account_id][context.partition].delete_role(role_name)

    with pytest.raises(CommonServiceException) as missing:
        provider.get_credentials_for_identity(context, identity)
    assert missing.value.code == "InvalidIdentityPoolConfigurationException"

    other_account = f"{(int(context.account_id) + 1) % 10**12:012d}"
    cross_account_role = f"arn:{context.partition}:iam::{other_account}:role/cross-account"
    with cognito_identity_stores.lock:
        cognito_identity_stores[context.account_id][context.region].identity_pools[
            pool["IdentityPoolId"]
        ].roles["unauthenticated"] = cross_account_role
    with pytest.raises(CommonServiceException) as cross_account:
        provider.get_credentials_for_identity(context, identity)
    assert cross_account.value.code == "InvalidIdentityPoolConfigurationException"

    with cognito_identity_stores.lock:
        assert not cognito_identity_stores[context.account_id][context.region].credential_sessions


def test_role_aba_is_detected_before_sts_issuance(provider, context, monkeypatch):
    pool = _pool(provider, context)
    role_arn = _configure_role(provider, context, pool["IdentityPoolId"], "unauthenticated")
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    from localstack.services.cognito_identity import credentials as credentials_module

    original_issue = credentials_module.issue_role_session
    backend = iam_backends[context.account_id][context.partition]
    original_role = backend.get_role_by_arn(role_arn)

    def replace_role(**kwargs):
        backend.delete_role(original_role.name)
        backend.create_role(
            role_name=original_role.name,
            assume_role_policy_document=original_role.assume_role_policy_document,
            path="/",
            permissions_boundary=None,
            description="",
            tags=[],
            max_session_duration="3600",
        )
        return original_issue(**kwargs)

    monkeypatch.setattr(credentials_module, "issue_role_session", replace_role)
    with pytest.raises(CommonServiceException) as error:
        provider.get_credentials_for_identity(context, identity)
    assert error.value.code == "InvalidIdentityPoolConfigurationException"
    assert not sts_backends[context.account_id][context.partition].assumed_roles
    assert not sts_stores[context.account_id][context.region].credential_sessions


def test_identity_pool_delete_waits_for_issuance_then_revokes_session(
    provider, context, monkeypatch
):
    pool = _pool(provider, context)
    _configure_role(provider, context, pool["IdentityPoolId"], "unauthenticated")
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    from localstack.services.cognito_identity import provider as provider_module

    original_issue = provider_module.issue_enhanced_flow_credentials
    entered = threading.Event()
    release = threading.Event()
    deleted = threading.Event()

    def paused_issue(**kwargs):
        issued = original_issue(**kwargs)
        entered.set()
        assert release.wait(timeout=5)
        return issued

    monkeypatch.setattr(provider_module, "issue_enhanced_flow_credentials", paused_issue)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        credential_future = executor.submit(
            provider.get_credentials_for_identity, context, identity
        )
        assert entered.wait(timeout=5)

        def delete_pool():
            result = provider.delete_identity_pool(
                context, {"IdentityPoolId": pool["IdentityPoolId"]}
            )
            deleted.set()
            return result

        delete_future = executor.submit(delete_pool)
        assert not deleted.wait(timeout=0.1)
        release.set()
        credentials = credential_future.result(timeout=5)
        assert delete_future.result(timeout=5) == {}

    access_key = credentials["Credentials"]["AccessKeyId"]
    assert deleted.is_set()
    assert access_key not in iam_backends[context.account_id][context.partition].access_keys
    assert resolve_session(access_key, account_id=context.account_id) is None
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        assert not store.credential_sessions
        assert identity["IdentityId"] not in store.identities


def test_session_cap_gc_revocation_and_raw_persistence(provider, context, monkeypatch):
    pool = _pool(provider, context)
    _configure_role(provider, context, pool["IdentityPoolId"], "unauthenticated")
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    monkeypatch.setattr(
        "localstack.services.cognito_identity.provider._MAX_CREDENTIAL_SESSIONS_PER_IDENTITY", 1
    )

    first = provider.get_credentials_for_identity(context, identity)
    with pytest.raises(CommonServiceException) as capped:
        provider.get_credentials_for_identity(context, identity)
    assert capped.value.code == "TooManyRequestsException"

    first_key = first["Credentials"]["AccessKeyId"]
    with cognito_identity_stores.lock:
        store = cognito_identity_stores[context.account_id][context.region]
        store.credential_sessions[first_key].expires_at = datetime.now(UTC) - timedelta(seconds=1)
    second = provider.get_credentials_for_identity(context, identity)
    assert second["Credentials"]["AccessKeyId"] != first_key
    assert first_key not in iam_backends[context.account_id][context.partition].access_keys
    assert resolve_session(first_key, account_id=context.account_id) is None

    with cognito_identity_stores.lock:
        restored = pickle.loads(pickle.dumps(cognito_identity_stores))
    restored_session = next(
        iter(restored[context.account_id][context.region].credential_sessions.values())
    )
    assert restored_session.identity_id == identity["IdentityId"]
    assert not hasattr(restored_session, "secret_key")
