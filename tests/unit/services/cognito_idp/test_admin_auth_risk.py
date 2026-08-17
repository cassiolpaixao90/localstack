import pickle
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.services.cognito_idp import provider as provider_module
from localstack.services.cognito_idp.models import cognito_idp_stores
from localstack.services.cognito_idp.provider import CognitoIdpProvider


@pytest.fixture
def context():
    context = RequestContext(None)
    context.account_id = f"{uuid.uuid4().int % 10**12:012d}"
    context.region = "us-east-1"
    yield context
    with cognito_idp_stores.lock:
        cognito_idp_stores.pop(context.account_id, None)


@pytest.fixture
def admin_stack(context):
    provider = CognitoIdpProvider()
    pool = provider.create_user_pool(context, {"PoolName": "risk-users"})["UserPool"]
    client = provider.create_user_pool_client(
        context,
        {
            "ClientName": "server-client",
            "ExplicitAuthFlows": [
                "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH",
                "ALLOW_USER_PASSWORD_AUTH",
                "ALLOW_USER_SRP_AUTH",
            ],
            "UserPoolId": pool["Id"],
        },
    )["UserPoolClient"]
    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TempPass9!",
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    provider.admin_set_user_password(
        context,
        {
            "Password": "PermanentPass9!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    return provider, pool, client


def _admin_password_request(pool, client, password="PermanentPass9!"):
    return {
        "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
        "AuthParameters": {"PASSWORD": password, "USERNAME": "alice"},
        "ClientId": client["ClientId"],
        "ContextData": {
            "EncodedData": "must-not-be-persisted",
            "HttpHeaders": [{"headerName": "User-Agent", "headerValue": "test-browser"}],
            "IpAddress": "192.0.2.10",
            "ServerName": "app.example.test",
            "ServerPath": "/login",
        },
        "UserPoolId": pool["Id"],
    }


def test_admin_password_auth_records_bounded_events_and_feedback(admin_stack, context):
    provider, pool, client = admin_stack

    success = provider.admin_initiate_auth(context, _admin_password_request(pool, client))
    assert "AuthenticationResult" in success
    with pytest.raises(CommonServiceException) as denied:
        provider.admin_initiate_auth(
            context, _admin_password_request(pool, client, password="WrongPass9!")
        )
    assert denied.value.code == "NotAuthorizedException"

    first_page = provider.admin_list_user_auth_events(
        context,
        {"MaxResults": 1, "UserPoolId": pool["Id"], "Username": "alice"},
    )
    assert len(first_page["AuthEvents"]) == 1
    assert first_page["AuthEvents"][0]["EventResponse"] == "Fail"
    assert first_page["AuthEvents"][0]["EventContextData"] == {
        "DeviceName": "test-browser",
        "IpAddress": "192.0.2.10",
    }
    assert "NextToken" in first_page
    second_page = provider.admin_list_user_auth_events(
        context,
        {
            "MaxResults": 1,
            "NextToken": first_page["NextToken"],
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    assert second_page["AuthEvents"][0]["EventResponse"] == "Pass"
    with pytest.raises(CommonServiceException) as tampered:
        provider.admin_list_user_auth_events(
            context,
            {
                "MaxResults": 1,
                "NextToken": first_page["NextToken"] + "x",
                "UserPoolId": pool["Id"],
                "Username": "alice",
            },
        )
    assert tampered.value.code == "InvalidParameterException"

    event_id = second_page["AuthEvents"][0]["EventId"]
    provider.admin_update_auth_event_feedback(
        context,
        {
            "EventId": event_id,
            "FeedbackValue": "Valid",
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    updated = provider.admin_list_user_auth_events(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )["AuthEvents"]
    assert (
        next(item for item in updated if item["EventId"] == event_id)["EventFeedback"]["Provider"]
        == "Admin"
    )

    serialized = pickle.dumps(provider.get_store(context).auth_events)
    assert b"must-not-be-persisted" not in serialized
    assert len(pickle.loads(serialized)) == 2


def test_auth_event_cap_is_atomic_under_concurrency_and_survives_serialization(
    admin_stack, context, monkeypatch
):
    provider, pool, client = admin_stack
    store = provider.get_store(context)
    pool_model = store.user_pools[pool["Id"]]
    client_model = pool_model.clients[client["ClientId"]]
    monkeypatch.setattr(provider_module, "_MAX_AUTH_EVENTS_PER_USER", 7)

    def record(_):
        provider_module._record_auth_event(
            context,
            store,
            pool_model,
            client_model,
            "alice",
            True,
            {"IpAddress": "192.0.2.10"},
            "Low",
            "NoRisk",
            False,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(record, range(32)))

    events = [event for event in store.auth_events.values() if event.username == "alice"]
    assert len(events) == 7
    assert len({event.event_id for event in events}) == 7
    restored = pickle.loads(pickle.dumps(store.auth_events))
    assert len(restored) == 7


def test_user_feedback_token_is_bound_to_event_user_and_pool(admin_stack, context):
    provider, pool, client = admin_stack
    provider.admin_initiate_auth(context, _admin_password_request(pool, client))
    event = next(iter(provider.get_store(context).auth_events.values()))
    feedback_token = provider_module._auth_event_feedback_token(
        provider.get_store(context).user_pools[pool["Id"]], event
    )

    assert (
        provider.update_auth_event_feedback(
            context,
            {
                "EventId": event.event_id,
                "FeedbackToken": feedback_token,
                "FeedbackValue": "Invalid",
                "UserPoolId": pool["Id"],
                "Username": "alice",
            },
        )
        == {}
    )
    with pytest.raises(CommonServiceException) as replay_cross_user:
        provider.update_auth_event_feedback(
            context,
            {
                "EventId": event.event_id,
                "FeedbackToken": feedback_token,
                "FeedbackValue": "Valid",
                "UserPoolId": pool["Id"],
                "Username": "bob",
            },
        )
    assert replay_cross_user.value.code in {"NotAuthorizedException", "UserNotFoundException"}


def test_admin_srp_reuses_native_challenge_and_custom_fails_closed(admin_stack, context):
    provider, pool, client = admin_stack

    challenge = provider.admin_initiate_auth(
        context,
        {
            "AuthFlow": "USER_SRP_AUTH",
            "AuthParameters": {"SRP_A": "2", "USERNAME": "alice"},
            "ClientId": client["ClientId"],
            "UserPoolId": pool["Id"],
        },
    )
    assert challenge["ChallengeName"] == "PASSWORD_VERIFIER"
    assert len(challenge["Session"]) >= 20

    provider.admin_create_user(
        context,
        {
            "MessageAction": "SUPPRESS",
            "TemporaryPassword": "TempPass9!",
            "UserPoolId": pool["Id"],
            "Username": "bob",
        },
    )
    new_password = provider.admin_initiate_auth(
        context,
        {
            "AuthFlow": "ADMIN_USER_PASSWORD_AUTH",
            "AuthParameters": {"PASSWORD": "TempPass9!", "USERNAME": "bob"},
            "ClientId": client["ClientId"],
            "UserPoolId": pool["Id"],
        },
    )
    assert new_password["ChallengeName"] == "NEW_PASSWORD_REQUIRED"
    completed = provider.admin_respond_to_auth_challenge(
        context,
        {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "ChallengeResponses": {
                "NEW_PASSWORD": "PermanentPass10!",
                "USERNAME": "bob",
            },
            "ClientId": client["ClientId"],
            "Session": new_password["Session"],
            "UserPoolId": pool["Id"],
        },
    )
    assert "AuthenticationResult" in completed

    with pytest.raises(CommonServiceException) as unsupported:
        provider.admin_initiate_auth(
            context,
            {
                "AuthFlow": "CUSTOM_AUTH",
                "AuthParameters": {"USERNAME": "alice"},
                "ClientId": client["ClientId"],
                "UserPoolId": pool["Id"],
            },
        )
    assert unsupported.value.code == "InvalidParameterException"


def test_risk_configuration_pool_and_client_round_trip_is_atomic(admin_stack, context):
    provider, pool, client = admin_stack
    configuration = {
        "CompromisedCredentialsRiskConfiguration": {
            "Actions": {"EventAction": "BLOCK"},
            "EventFilter": ["SIGN_IN"],
        },
        "RiskExceptionConfiguration": {
            "BlockedIPRangeList": ["198.51.100.0/24"],
            "SkippedIPRangeList": ["192.0.2.10/32"],
        },
    }
    desired = {**configuration, "ClientId": "ALL", "UserPoolId": pool["Id"]}

    set_response = provider.set_risk_configuration(context, desired)["RiskConfiguration"]
    described = provider.describe_risk_configuration(
        context, {"ClientId": "ALL", "UserPoolId": pool["Id"]}
    )["RiskConfiguration"]

    assert {key: described[key] for key in configuration} == configuration
    assert set_response == described

    provider.admin_set_user_password(
        context,
        {
            "Password": "Password123!",
            "Permanent": True,
            "UserPoolId": pool["Id"],
            "Username": "alice",
        },
    )
    skipped = _admin_password_request(pool, client, password="Password123!")
    assert "AuthenticationResult" in provider.admin_initiate_auth(context, skipped)
    with pytest.raises(CommonServiceException) as user_flow_block:
        provider.initiate_auth(
            context,
            {
                "AuthFlow": "USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "PASSWORD": "Password123!",
                    "USERNAME": "alice",
                },
                "ClientId": client["ClientId"],
                "UserContextData": {
                    "EncodedData": "not-persisted",
                    "IpAddress": "203.0.113.11",
                },
            },
        )
    assert user_flow_block.value.code == "NotAuthorizedException"
    compromised = _admin_password_request(pool, client, password="Password123!")
    compromised["ContextData"]["IpAddress"] = "203.0.113.10"
    with pytest.raises(CommonServiceException) as compromised_block:
        provider.admin_initiate_auth(context, compromised)
    assert compromised_block.value.code == "NotAuthorizedException"
    blocked = _admin_password_request(pool, client, password="not-the-user-password")
    blocked["ContextData"]["IpAddress"] = "198.51.100.20"
    with pytest.raises(CommonServiceException) as cidr_block:
        provider.admin_initiate_auth(context, blocked)
    assert cidr_block.value.code == "NotAuthorizedException"
    risk_events = provider.admin_list_user_auth_events(
        context, {"UserPoolId": pool["Id"], "Username": "alice"}
    )["AuthEvents"]
    by_ip = {item["EventContextData"]["IpAddress"]: item for item in risk_events}
    assert by_ip["203.0.113.10"]["EventRisk"] == {
        "CompromisedCredentialsDetected": True,
        "RiskDecision": "Block",
        "RiskLevel": "High",
    }
    assert by_ip["198.51.100.20"]["EventRisk"]["CompromisedCredentialsDetected"] is False

    with pytest.raises(CommonServiceException) as proprietary:
        provider.set_risk_configuration(
            context,
            {
                **desired,
                "AccountTakeoverRiskConfiguration": {
                    "Actions": {"HighAction": {"EventAction": "BLOCK", "Notify": False}}
                },
            },
        )
    assert proprietary.value.code == "InvalidParameterException"
    with pytest.raises(CommonServiceException) as invalid:
        provider.set_risk_configuration(
            context,
            {
                **desired,
                "RiskExceptionConfiguration": {
                    "BlockedIPRangeList": ["not-a-cidr"],
                    "SkippedIPRangeList": [],
                },
            },
        )
    assert invalid.value.code == "InvalidParameterException"
    assert (
        provider.describe_risk_configuration(
            context, {"ClientId": "ALL", "UserPoolId": pool["Id"]}
        )["RiskConfiguration"]
        == described
    )
