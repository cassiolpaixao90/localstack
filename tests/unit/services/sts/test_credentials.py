import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from moto.iam.models import iam_backends
from moto.sts.models import sts_backends

from localstack.aws.accounts import get_account_id_from_access_key_id
from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.sts import InvalidIdentityTokenException
from localstack.aws.forwarder import create_aws_request_context
from localstack.services.cognito_identity.models import cognito_identity_stores
from localstack.services.cognito_identity.provider import CognitoIdentityProvider
from localstack.services.iam.iam_patches import apply_iam_patches
from localstack.services.sts.credentials import (
    CredentialIssueError,
    SessionAuthResult,
    authenticate_session,
    issue_role_session,
    resolve_session,
    revoke_role_session,
)
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
def other_context(context):
    value = RequestContext(None)
    value.account_id = f"{(int(context.account_id) + 1) % 10**12:012d}"
    value.region = context.region
    value.partition = context.partition
    yield value
    _remove_account(value)


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
    sts_stores.pop(context.account_id, None)
    iam_backends[context.account_id][context.partition].reset()
    sts_backends[context.account_id][context.partition].reset()


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


def _issue(context, role_arn, **overrides):
    parameters = {
        "account_id": context.account_id,
        "region": context.region,
        "partition": context.partition,
        "role_arn": role_arn,
        "role_session_name": "native-session",
        "provider_name": "cognito-identity.amazonaws.com",
        "subject": f"{context.region}:{uuid.uuid4()}",
    }
    parameters.update(overrides)
    return issue_role_session(**parameters)


def _pool_with_identity(context, *, allow_classic=True):
    provider = CognitoIdentityProvider()
    pool = provider.create_identity_pool(
        context,
        {
            "IdentityPoolName": "sts-pool",
            "AllowUnauthenticatedIdentities": True,
            "AllowClassicFlow": allow_classic,
        },
    )
    identity = provider.get_id(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    token = provider.get_open_id_token(context, {"IdentityId": identity["IdentityId"]})["Token"]
    return provider, pool, identity, token


def _sts_context(context, access_key_id):
    sts_context = create_aws_request_context(
        service_name="sts",
        action="GetCallerIdentity",
        parameters={},
        region=context.region,
    )
    sts_context.account_id = context.account_id
    sts_context.partition = context.partition
    sts_context.request.headers.update(
        mock_aws_request_headers("sts", aws_access_key_id=access_key_id, region_name=context.region)
    )
    return sts_context


def test_issued_session_shape_embeds_account_and_bounds_expiration(context):
    role_arn = _role(context, "native-role", _trust("pool", "unauthenticated"))

    issued = _issue(context, role_arn, principal_tags={"Tenant": "acme"})

    assert issued.access_key_id.startswith("LSIS")
    assert len(issued.access_key_id) == 20
    assert get_account_id_from_access_key_id(issued.access_key_id) == context.account_id
    assert len(issued.secret_access_key) == 40
    assert issued.session_token
    assert timedelta(minutes=55) <= issued.expiration - datetime.now(UTC)
    assert issued.expiration - datetime.now(UTC) <= timedelta(minutes=61)
    assert issued.assumed_role_arn == (
        f"arn:aws:sts::{context.account_id}:assumed-role/native-role/native-session"
    )
    assert issued.assumed_role_id.endswith(":native-session")

    store = sts_stores[context.account_id][context.region]
    session = store.credential_sessions[issued.access_key_id]
    assert session.role_arn == role_arn
    assert session.principal_tags == {"Tenant": "acme"}
    assert session.secret_access_key_hash != issued.secret_access_key
    assert session.session_token_hash != issued.session_token
    assert not hasattr(session, "secret_access_key")
    assert store.sessions[issued.access_key_id]["tags"] == {
        "tenant": {"Key": "Tenant", "Value": "acme"}
    }


def test_resolve_revoke_and_expiration(context):
    role_arn = _role(context, "native-role", _trust("pool", "unauthenticated"))
    issued = _issue(context, role_arn)

    session = resolve_session(issued.access_key_id)
    assert session is not None
    assert session.assumed_role_arn == issued.assumed_role_arn

    revoke_role_session(issued.access_key_id)
    assert resolve_session(issued.access_key_id) is None
    assert issued.access_key_id not in sts_stores[context.account_id][context.region].sessions

    expired = _issue(context, role_arn)
    store = sts_stores[context.account_id][context.region]
    store.credential_sessions[expired.access_key_id].expiration = datetime.now(UTC) - timedelta(
        seconds=1
    )
    assert resolve_session(expired.access_key_id) is None
    assert expired.access_key_id not in store.credential_sessions

    assert resolve_session("not-a-key") is None
    assert resolve_session("") is None
    revoke_role_session("not-a-key")


def test_authenticate_session_matrix(context, other_context):
    role_arn = _role(context, "native-role", _trust("pool", "unauthenticated"))
    issued = _issue(context, role_arn)

    assert (
        authenticate_session(
            issued.access_key_id,
            issued.session_token,
            account_id=context.account_id,
            region=context.region,
        )
        is SessionAuthResult.OK
    )
    # account and region resolve from the key and the store fallback
    assert authenticate_session(issued.access_key_id, issued.session_token) is SessionAuthResult.OK
    assert (
        authenticate_session(
            issued.access_key_id,
            issued.session_token,
            account_id=context.account_id,
            region="eu-west-1",
        )
        is SessionAuthResult.OK
    )

    assert (
        authenticate_session(issued.access_key_id, "tampered-token", account_id=context.account_id)
        is SessionAuthResult.TOKEN_MISMATCH
    )
    assert (
        authenticate_session(issued.access_key_id, None, account_id=context.account_id)
        is SessionAuthResult.TOKEN_MISMATCH
    )
    assert (
        authenticate_session(issued.access_key_id, "", account_id=context.account_id)
        is SessionAuthResult.TOKEN_MISMATCH
    )
    # a mismatch must not consume the session
    assert resolve_session(issued.access_key_id, account_id=context.account_id) is not None

    assert (
        authenticate_session("LSISAAAAAAAAAAAAAAAA", "token", account_id=context.account_id)
        is SessionAuthResult.NOT_REGISTERED
    )
    assert authenticate_session("not-a-key", "token") is SessionAuthResult.NOT_REGISTERED
    assert (
        authenticate_session(
            issued.access_key_id, issued.session_token, account_id=other_context.account_id
        )
        is SessionAuthResult.NOT_REGISTERED
    )

    # revocation turns a valid session into a plain unknown key
    revoked = _issue(context, role_arn)
    revoke_role_session(revoked.access_key_id)
    assert (
        authenticate_session(
            revoked.access_key_id, revoked.session_token, account_id=context.account_id
        )
        is SessionAuthResult.NOT_REGISTERED
    )

    # expiry prunes the session and reports EXPIRED instead of NOT_REGISTERED
    expired = _issue(context, role_arn)
    store = sts_stores[context.account_id][context.region]
    store.credential_sessions[expired.access_key_id].expiration = datetime.now(UTC) - timedelta(
        seconds=1
    )
    assert (
        authenticate_session(
            expired.access_key_id, expired.session_token, account_id=context.account_id
        )
        is SessionAuthResult.EXPIRED
    )
    assert expired.access_key_id not in store.credential_sessions
    assert expired.access_key_id not in store.sessions
    assert (
        authenticate_session(
            expired.access_key_id, expired.session_token, account_id=context.account_id
        )
        is SessionAuthResult.NOT_REGISTERED
    )

    # the store holds hashes only, never the presented token or secret
    session = store.credential_sessions[issued.access_key_id]
    assert session.session_token_hash != issued.session_token
    assert not hasattr(session, "session_token")


def test_issue_rejects_invalid_inputs_and_missing_role(context):
    role_arn = _role(context, "native-role", _trust("pool", "unauthenticated"))

    with pytest.raises(CredentialIssueError):
        _issue(context, role_arn, account_id="not-an-account")
    with pytest.raises(CredentialIssueError):
        _issue(context, role_arn, duration_seconds=899)
    with pytest.raises(CredentialIssueError):
        _issue(context, role_arn, duration_seconds=43201)
    with pytest.raises(CredentialIssueError):
        _issue(context, role_arn, role_session_name="x")
    with pytest.raises(CredentialIssueError):
        _issue(context, role_arn, principal_tags={"Tenant": "x" * 257})
    with pytest.raises(CredentialIssueError):
        _issue(
            context,
            f"arn:aws:iam::{context.account_id}:role/does-not-exist",
        )
    other_account = f"{(int(context.account_id) + 1) % 10**12:012d}"
    with pytest.raises(CredentialIssueError):
        _issue(context, f"arn:aws:iam::{other_account}:role/native-role")


def test_session_lookup_is_isolated_per_account(context, other_context):
    role_arn = _role(context, "native-role", _trust("pool", "unauthenticated"))
    issued = _issue(context, role_arn)

    assert resolve_session(issued.access_key_id, account_id=other_context.account_id) is None
    assert (
        resolve_session(
            issued.access_key_id,
            account_id=context.account_id,
            region="eu-west-1",
        )
        is not None
    )


def test_credential_sessions_survive_pickle_roundtrip_without_secrets(context):
    role_arn = _role(context, "native-role", _trust("pool", "unauthenticated"))
    issued = _issue(context, role_arn, principal_tags={"Tenant": "acme"})

    restored = pickle.loads(pickle.dumps(sts_stores))
    session = restored[context.account_id][context.region].credential_sessions[issued.access_key_id]

    assert session.assumed_role_arn == issued.assumed_role_arn
    assert session.principal_tags == {"Tenant": "acme"}
    assert session.secret_access_key_hash
    assert not hasattr(session, "secret_access_key")
    assert not hasattr(session, "session_token")


def test_assume_role_with_web_identity_full_local_flow(context):
    _, pool, identity, token = _pool_with_identity(context)
    role_arn = _role(
        context, "web-identity-role", _trust(pool["IdentityPoolId"], "unauthenticated")
    )
    sts = StsProvider()

    response = sts.assume_role_with_web_identity(
        context,
        role_arn=role_arn,
        role_session_name="web-session",
        web_identity_token=token,
    )

    credentials = response["Credentials"]
    assert credentials["AccessKeyId"].startswith("LSIS")
    assert get_account_id_from_access_key_id(credentials["AccessKeyId"]) == context.account_id
    expected_arn = f"arn:aws:sts::{context.account_id}:assumed-role/web-identity-role/web-session"
    assert response["AssumedRoleUser"]["Arn"] == expected_arn
    assert response["SubjectFromWebIdentityToken"] == identity["IdentityId"]
    assert response["Provider"] == "cognito-identity.amazonaws.com"
    assert response["Audience"] == pool["IdentityPoolId"]

    caller = sts.get_caller_identity(_sts_context(context, credentials["AccessKeyId"]))
    assert caller["Account"] == context.account_id
    assert caller["Arn"] == expected_arn
    assert caller["UserId"].endswith(":web-session")


def test_assume_role_with_web_identity_fails_closed(context):
    provider, pool, identity, token = _pool_with_identity(context)
    role_arn = _role(
        context, "web-identity-role", _trust(pool["IdentityPoolId"], "unauthenticated")
    )
    sts = StsProvider()

    with pytest.raises(InvalidIdentityTokenException):
        sts.assume_role_with_web_identity(
            context,
            role_arn=role_arn,
            role_session_name="web-session",
            web_identity_token="not-a-jwt",
        )
    with pytest.raises(InvalidIdentityTokenException):
        sts.assume_role_with_web_identity(
            context,
            role_arn=role_arn,
            role_session_name="web-session",
            web_identity_token=token,
            provider_id="https://accounts.example.com",
        )
    with pytest.raises(CommonServiceException) as invalid_arn:
        sts.assume_role_with_web_identity(
            context,
            role_arn="not-an-arn",
            role_session_name="web-session",
            web_identity_token=token,
        )
    assert invalid_arn.value.code == "ValidationError"
    with pytest.raises(CommonServiceException) as bad_duration:
        sts.assume_role_with_web_identity(
            context,
            role_arn=role_arn,
            role_session_name="web-session",
            web_identity_token=token,
            duration_seconds=60,
        )
    assert bad_duration.value.code == "ValidationError"

    # a token from an unknown/deleted pool must not be trusted
    provider.delete_identity_pool(context, {"IdentityPoolId": pool["IdentityPoolId"]})
    with pytest.raises(InvalidIdentityTokenException):
        sts.assume_role_with_web_identity(
            context,
            role_arn=role_arn,
            role_session_name="web-session",
            web_identity_token=token,
        )


def test_assume_role_with_web_identity_enforces_trust_policy(context):
    _, pool, identity, token = _pool_with_identity(context)
    sts = StsProvider()
    authenticated_only = _role(
        context, "authenticated-only", _trust(pool["IdentityPoolId"], "authenticated")
    )
    wrong_audience = _role(context, "wrong-audience", _trust("wrong-pool", "unauthenticated"))

    for arn in (authenticated_only, wrong_audience):
        with pytest.raises(CommonServiceException) as error:
            sts.assume_role_with_web_identity(
                context,
                role_arn=arn,
                role_session_name="web-session",
                web_identity_token=token,
            )
        assert error.value.code == "AccessDenied"

    with pytest.raises(CommonServiceException) as missing:
        sts.assume_role_with_web_identity(
            context,
            role_arn=f"arn:aws:iam::{context.account_id}:role/missing",
            role_session_name="web-session",
            web_identity_token=token,
        )
    assert missing.value.code == "AccessDenied"
    assert not sts_stores[context.account_id][context.region].credential_sessions
