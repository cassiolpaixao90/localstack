import base64
import hashlib
import json
import uuid
from datetime import UTC, datetime

import pytest

from localstack.services.cognito_idp.oauth_client_credentials import (
    ClientCredentialsConfig,
    ClientCredentialsError,
    build_machine_token_trigger_event,
    issue_client_credentials_token,
)
from localstack.services.cognito_idp.tokens import decode_jwt_segment, generate_signing_key


@pytest.fixture
def topology():
    account_id = f"{uuid.uuid4().int % 10**12:012d}"
    region_name = f"aa-{uuid.uuid4().hex[:4]}-1"
    return {
        "account_id": account_id,
        "region": region_name,
        "pool_id": f"{region_name}_pool123",
    }


def _issuer(topology):
    return f"https://cognito-idp.{topology['region']}.amazonaws.com/{topology['pool_id']}"


@pytest.fixture
def signing_key():
    return generate_signing_key()


@pytest.fixture
def client():
    return ClientCredentialsConfig(
        client_id="machine-client",
        secret_hashes=(hashlib.sha256(b"correct-secret").hexdigest(),),
        allowed_flows=("client_credentials",),
        allowed_scopes=frozenset({"orders/read", "orders/write"}),
        access_token_ttl_seconds=900,
    )


def _basic(client_id="machine-client", secret="correct-secret"):
    value = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return f"Basic {value}"


def test_confidential_client_gets_access_token_only(topology, signing_key, client):
    kid, private_key, _ = signing_key
    result = issue_client_credentials_token(
        config=client,
        authorization=_basic(),
        form={"grant_type": "client_credentials", "scope": "orders/read orders/write"},
        issuer=_issuer(topology),
        signing_key_id=kid,
        signing_private_key=private_key,
        now=datetime(2026, 8, 10, tzinfo=UTC),
    )
    assert set(result.token_response) == {"access_token", "expires_in", "token_type"}
    claims = decode_jwt_segment(result.token_response["access_token"].split(".")[1])
    assert claims["client_id"] == client.client_id
    assert claims["scope"] == "orders/read orders/write"
    assert claims["token_use"] == "access"
    assert claims["sub"] == client.client_id


@pytest.mark.parametrize(
    ("config_change", "form", "authorization", "message"),
    [
        ({"secret_hashes": ()}, {"grant_type": "client_credentials"}, _basic(), "confidential"),
        (
            {"allowed_flows": ("client_credentials", "code")},
            {"grant_type": "client_credentials"},
            _basic(),
            "exclusively",
        ),
        ({}, {"grant_type": "client_credentials", "scope": "openid"}, _basic(), "custom"),
        ({}, {"grant_type": "client_credentials", "scope": "unknown/read"}, _basic(), "scope"),
        (
            {},
            {
                "grant_type": "client_credentials",
                "client_id": "machine-client",
                "client_secret": "correct-secret",
            },
            _basic(),
            "one authentication method",
        ),
        ({}, {"grant_type": "authorization_code"}, _basic(), "grant_type"),
    ],
)
def test_client_credentials_rejects_public_mixed_oidc_unknown_and_ambiguous_auth(
    client, config_change, form, authorization, message, topology
):
    config = ClientCredentialsConfig(
        client_id=client.client_id,
        secret_hashes=config_change.get("secret_hashes", client.secret_hashes),
        allowed_flows=config_change.get("allowed_flows", client.allowed_flows),
        allowed_scopes=client.allowed_scopes,
        access_token_ttl_seconds=client.access_token_ttl_seconds,
    )
    kid, private_key, _ = generate_signing_key()
    with pytest.raises(ClientCredentialsError, match=message):
        issue_client_credentials_token(
            config=config,
            authorization=authorization,
            form=form,
            issuer=_issuer(topology),
            signing_key_id=kid,
            signing_private_key=private_key,
            now=datetime(2026, 8, 10, tzinfo=UTC),
        )


def test_post_secret_metadata_and_v3_machine_trigger_are_bounded(client, topology):
    kid, private_key, _ = generate_signing_key()
    metadata = json.dumps({"tenant": "acme", "trace": "trace-123"})
    result = issue_client_credentials_token(
        config=client,
        authorization=None,
        form={
            "grant_type": "client_credentials",
            "client_id": client.client_id,
            "client_secret": "correct-secret",
            "scope": "orders/read",
            "aws_client_metadata": metadata,
        },
        issuer=_issuer(topology),
        signing_key_id=kid,
        signing_private_key=private_key,
        now=datetime(2026, 8, 10, tzinfo=UTC),
    )
    event = build_machine_token_trigger_event(
        region=topology["region"],
        pool_id=topology["pool_id"],
        client_id=client.client_id,
        scopes=result.scopes,
        client_metadata=result.client_metadata,
    )
    assert event["version"] == "3"
    assert event["request"]["clientMetadata"] == {"tenant": "acme", "trace": "trace-123"}
    assert event["request"]["scopes"] == ["orders/read"]

    duplicate = '{"tenant":"one","tenant":"two"}'
    with pytest.raises(ClientCredentialsError, match="metadata"):
        issue_client_credentials_token(
            config=client,
            authorization=_basic(),
            form={"grant_type": "client_credentials", "aws_client_metadata": duplicate},
            issuer=_issuer(topology),
            signing_key_id=kid,
            signing_private_key=private_key,
        )
