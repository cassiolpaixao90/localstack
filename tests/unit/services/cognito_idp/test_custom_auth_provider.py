import uuid

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider
from tests.unit.services.cognito_idp.test_srp import G, N, _password_verifier_request


@pytest.fixture
def context(region_name):
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = region_name
    yield context
    with cognito_idp_stores.lock:
        bundle = cognito_idp_stores.get(context.account_id)
        if bundle is not None:
            for store in bundle.values():
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


def test_admin_challenge_response_is_charged_once_not_again_by_delegated_handler(
    context, custom_auth_topology, provider, monkeypatch
):
    pool = custom_auth_topology["pool"]
    client = custom_auth_topology["client"]
    started = provider.admin_initiate_auth(
        context,
        {
            "AuthFlow": "CUSTOM_AUTH",
            "AuthParameters": {"USERNAME": "alice"},
            "ClientId": client["ClientId"],
            "UserPoolId": pool["Id"],
        },
    )
    consumed = []
    monkeypatch.setattr(
        provider,
        "_consume_provisioned_rate",
        lambda _context, operation: consumed.append(operation),
    )
    monkeypatch.setattr(provider, "_authentication_result", lambda *args, **kwargs: {})

    provider.admin_respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "CUSTOM_CHALLENGE",
            "ChallengeResponses": {"ANSWER": "correct", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
            "Session": started["Session"],
            "UserPoolId": pool["Id"],
        },
    )

    assert consumed == ["AdminRespondToAuthChallenge"]


@pytest.fixture
def custom_auth_topology(context, monkeypatch, provider):
    events = []

    def invoke(trigger_context, pool, function_arn, event):
        assert pool.pool_id not in provider_module._POOL_LOCKS
        trigger = function_arn.rsplit(":", 1)[-1]
        events.append((trigger, event))
        if trigger == "define-custom":
            history = event["request"]["session"]
            event["response"] = (
                {"failAuthentication": False, "issueTokens": True}
                if history
                and history[-1]["challengeName"] == "CUSTOM_CHALLENGE"
                and history[-1]["challengeResult"]
                else {
                    "challengeName": "CUSTOM_CHALLENGE",
                    "failAuthentication": False,
                    "issueTokens": False,
                }
            )
        elif trigger == "create-custom":
            event["response"] = {
                "challengeMetadata": "captcha-v1",
                "privateChallengeParameters": {"answer": "correct"},
                "publicChallengeParameters": {"prompt": "captcha"},
            }
        elif trigger == "verify-custom":
            event["response"] = {
                "answerCorrect": event["request"]["challengeAnswer"]
                == event["request"]["privateChallengeParameters"]["answer"]
            }
        else:
            raise AssertionError(trigger)
        return event

    monkeypatch.setattr(provider_module, "_invoke_lambda_trigger", invoke)
    lambda_prefix = (
        f"arn:{context.partition}:lambda:{context.region}:{context.account_id}:function:"
    )
    pool = provider.create_user_pool(
        context,
        {
            "LambdaConfig": {
                "CreateAuthChallenge": f"{lambda_prefix}create-custom",
                "DefineAuthChallenge": f"{lambda_prefix}define-custom",
                "VerifyAuthChallengeResponse": f"{lambda_prefix}verify-custom",
            },
            "PoolName": "custom-auth-users",
        },
    )["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "custom-auth-client",
            "ExplicitAuthFlows": ["ALLOW_CUSTOM_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "PreventUserExistenceErrors": "ENABLED",
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "Username": "alice",
            "UserPoolId": pool["Id"],
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": "Permanent9!",
            "Permanent": True,
            "Username": "alice",
            "UserPoolId": pool["Id"],
        },
    )
    return {"client": client, "events": events, "pool": pool}


@pytest.mark.parametrize("admin", [False, True])
def test_custom_auth_dispatches_local_triggers_and_issues_tokens(
    admin, context, custom_auth_topology, provider
):
    client = custom_auth_topology["client"]
    pool = custom_auth_topology["pool"]
    events = custom_auth_topology["events"]
    initiate = provider.admin_initiate_auth if admin else provider.initiate_auth
    initiate_request = {
        "AuthFlow": "CUSTOM_AUTH",
        "AuthParameters": {"USERNAME": "alice"},
        "ClientId": client["ClientId"],
        "ClientMetadata": {"init-secret": "must-not-reach-custom-triggers"},
        **(
            {
                "ContextData": {
                    "EncodedData": "bounded-risk-context",
                    "HttpHeaders": [],
                    "IpAddress": "192.0.2.10",
                    "ServerName": "auth.example.test",
                    "ServerPath": "/login",
                },
                "UserPoolId": pool["Id"],
            }
            if admin
            else {"UserContextData": {"EncodedData": "bounded-risk-context"}}
        ),
    }

    challenge = initiate(context, initiate_request)

    assert challenge["ChallengeName"] == "CUSTOM_CHALLENGE"
    assert challenge["ChallengeParameters"] == {"prompt": "captcha"}
    assert [name for name, _ in events] == ["define-custom", "create-custom"]
    assert all(event["request"]["clientMetadata"] == {} for _, event in events)
    respond = (
        provider.admin_respond_to_auth_challenge if admin else provider.respond_to_auth_challenge
    )
    response = respond(
        context,
        {
            "ChallengeName": "CUSTOM_CHALLENGE",
            "ChallengeResponses": {"ANSWER": "correct", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
            "ClientMetadata": {"surface": "mobile"},
            "Session": challenge["Session"],
            **({"UserPoolId": pool["Id"]} if admin else {}),
        },
    )

    assert {"AccessToken", "IdToken", "RefreshToken"} <= set(response["AuthenticationResult"])
    assert [name for name, _ in events][-2:] == ["verify-custom", "define-custom"]
    assert all(
        event["request"]["clientMetadata"] == {"surface": "mobile"}
        for name, event in events[-2:]
        if name in {"verify-custom", "define-custom"}
    )
    with pytest.raises(CommonServiceException) as replay:
        respond(
            context,
            {
                "ChallengeName": "CUSTOM_CHALLENGE",
                "ChallengeResponses": {"ANSWER": "correct", "USERNAME": "alice"},
                "ClientId": client["ClientId"],
                "Session": challenge["Session"],
                **({"UserPoolId": pool["Id"]} if admin else {}),
            },
        )
    assert replay.value.code == "NotAuthorizedException"


def test_custom_auth_pue_runs_synthetic_triggers_but_never_issues_tokens(
    context, custom_auth_topology, provider
):
    client = custom_auth_topology["client"]
    events = custom_auth_topology["events"]
    challenge = provider.initiate_auth(
        context,
        {
            "AuthFlow": "CUSTOM_AUTH",
            "AuthParameters": {"USERNAME": "missing-user"},
            "ClientId": client["ClientId"],
        },
    )

    with pytest.raises(CommonServiceException) as denied:
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "CUSTOM_CHALLENGE",
                "ChallengeResponses": {"ANSWER": "correct", "USERNAME": "missing-user"},
                "ClientId": client["ClientId"],
                "Session": challenge["Session"],
            },
        )

    assert denied.value.code == "NotAuthorizedException"
    assert all(event["request"]["userNotFound"] is True for _, event in events)


def test_custom_auth_session_is_cleaned_with_user(context, custom_auth_topology, provider):
    client = custom_auth_topology["client"]
    pool = custom_auth_topology["pool"]
    challenge = provider.initiate_auth(
        context,
        {
            "AuthFlow": "CUSTOM_AUTH",
            "AuthParameters": {"USERNAME": "alice"},
            "ClientId": client["ClientId"],
        },
    )
    provider.admin_delete_user(context, {"Username": "alice", "UserPoolId": pool["Id"]})

    with pytest.raises(CommonServiceException) as deleted:
        provider.respond_to_auth_challenge(
            context,
            {
                "ChallengeName": "CUSTOM_CHALLENGE",
                "ChallengeResponses": {"ANSWER": "correct", "USERNAME": "alice"},
                "ClientId": client["ClientId"],
                "Session": challenge["Session"],
            },
        )

    assert deleted.value.code == "NotAuthorizedException"
    assert provider.get_store(context).custom_auth.sessions == {}


def test_custom_auth_optional_srp_a_continues_into_custom_challenge(
    context, custom_auth_topology, provider
):
    client = custom_auth_topology["client"]
    pool = custom_auth_topology["pool"]
    events = custom_auth_topology["events"]
    private_a = 0x123456789ABCDEF
    srp = provider.initiate_auth(
        context,
        {
            "AuthFlow": "CUSTOM_AUTH",
            "AuthParameters": {
                "CHALLENGE_NAME": "SRP_A",
                "SRP_A": format(pow(G, private_a, N), "x"),
                "USERNAME": "alice",
            },
            "ClientId": client["ClientId"],
        },
    )
    password_request = _password_verifier_request(pool, client, srp, private_a, "Permanent9!")
    password_request["ClientMetadata"] = {"surface": "web"}

    challenge = provider.respond_to_auth_challenge(context, password_request)

    assert challenge["ChallengeName"] == "CUSTOM_CHALLENGE"
    define = events[-2][1]
    assert define["request"]["clientMetadata"] == {"surface": "web"}
    assert define["request"]["session"] == [
        {"challengeName": "SRP_A", "challengeResult": True},
        {"challengeName": "PASSWORD_VERIFIER", "challengeResult": True},
    ]
    result = provider.respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "CUSTOM_CHALLENGE",
            "ChallengeResponses": {"ANSWER": "correct", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
            "Session": challenge["Session"],
        },
    )
    assert "AuthenticationResult" in result
