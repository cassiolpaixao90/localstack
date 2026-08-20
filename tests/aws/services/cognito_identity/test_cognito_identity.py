import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@pytest.fixture
def identity_pool(aws_client):
    pool_ids = []

    def factory(**overrides):
        request = {
            "IdentityPoolName": f"pool-{short_uid()}",
            "AllowUnauthenticatedIdentities": True,
        }
        request.update(overrides)
        pool = aws_client.cognito_identity.create_identity_pool(**request)
        pool_ids.append(pool["IdentityPoolId"])
        return pool

    yield factory
    for pool_id in pool_ids:
        try:
            aws_client.cognito_identity.delete_identity_pool(IdentityPoolId=pool_id)
        except ClientError:
            pass


class TestCognitoIdentity:
    @markers.aws.only_localstack
    def test_pool_crud_pagination_and_tags(
        self, aws_client, identity_pool, region_name, account_id
    ):
        pool = identity_pool(IdentityPoolTags={"purpose": "integration"})
        pool_id = pool["IdentityPoolId"]

        described = aws_client.cognito_identity.describe_identity_pool(IdentityPoolId=pool_id)
        assert described["IdentityPoolId"] == pool_id
        assert described["IdentityPoolTags"] == {"purpose": "integration"}

        tags = aws_client.cognito_identity.list_tags_for_resource(
            ResourceArn=f"arn:aws:cognito-identity:{region_name}:{account_id}:identitypool/{pool_id}"
        )["Tags"]
        assert tags == {"purpose": "integration"}

        for index in range(2):
            identity_pool()
        page1 = aws_client.cognito_identity.list_identity_pools(MaxResults=2)
        assert len(page1["IdentityPools"]) == 2
        assert page1["NextToken"]
        page2 = aws_client.cognito_identity.list_identity_pools(
            MaxResults=2, NextToken=page1["NextToken"]
        )
        assert page2["IdentityPools"]
        names = {item["IdentityPoolId"] for item in page1["IdentityPools"]}
        assert not names & {item["IdentityPoolId"] for item in page2["IdentityPools"]}

        with pytest.raises(ClientError) as e:
            aws_client.cognito_identity.list_identity_pools(MaxResults=61)
        assert e.value.response["Error"]["Code"] in {
            "ValidationException",
            "InvalidParameterException",
        }

    @markers.aws.only_localstack
    def test_identity_lifecycle_through_gateway(self, aws_client, identity_pool, account_id):
        pool_id = identity_pool(AllowClassicFlow=True)["IdentityPoolId"]

        identity = aws_client.cognito_identity.get_id(AccountId=account_id, IdentityPoolId=pool_id)
        identity_id = identity["IdentityId"]

        described = aws_client.cognito_identity.describe_identity(IdentityId=identity_id)
        assert described["IdentityId"] == identity_id

        listed = aws_client.cognito_identity.list_identities(IdentityPoolId=pool_id, MaxResults=10)
        assert identity_id in [item["IdentityId"] for item in listed["Identities"]]

        token = aws_client.cognito_identity.get_open_id_token(IdentityId=identity_id)
        assert token["IdentityId"] == identity_id
        assert token["Token"].count(".") == 2

        deleted = aws_client.cognito_identity.delete_identities(IdentityIdsToDelete=[identity_id])
        assert deleted["UnprocessedIdentityIds"] == []
        listed = aws_client.cognito_identity.list_identities(IdentityPoolId=pool_id, MaxResults=10)
        remaining = listed.get("Identities") or []
        assert identity_id not in [item["IdentityId"] for item in remaining]

        with pytest.raises(ClientError) as e:
            aws_client.cognito_identity.describe_identity(IdentityId=identity_id)
        assert e.value.response["Error"]["Code"] == "ResourceNotFoundException"

    @markers.aws.only_localstack
    def test_identity_pool_roles_roundtrip(self, aws_client, identity_pool, account_id):
        pool_id = identity_pool()["IdentityPoolId"]
        role_arn = f"arn:aws:iam::{account_id}:role/unused-{short_uid()}"

        aws_client.cognito_identity.set_identity_pool_roles(
            IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn}
        )
        roles = aws_client.cognito_identity.get_identity_pool_roles(IdentityPoolId=pool_id)
        assert roles["IdentityPoolId"] == pool_id
        assert roles["Roles"] == {"unauthenticated": role_arn}

    @markers.aws.only_localstack
    def test_developer_identities_link_lookup_and_unlink(
        self, aws_client, identity_pool, account_id
    ):
        pool_id = identity_pool(
            AllowUnauthenticatedIdentities=False,
            DeveloperProviderName="login.localstack",
        )["IdentityPoolId"]
        developer_user = f"dev-{short_uid()}"

        created = aws_client.cognito_identity.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id,
            Logins={"login.localstack": developer_user},
            TokenDuration=900,
        )
        identity_id = created["IdentityId"]

        looked_up = aws_client.cognito_identity.lookup_developer_identity(
            IdentityPoolId=pool_id, DeveloperUserIdentifier=developer_user
        )
        assert looked_up["IdentityId"] == identity_id
        assert looked_up["DeveloperUserIdentifierList"] == [developer_user]

        aws_client.cognito_identity.unlink_developer_identity(
            IdentityId=identity_id,
            IdentityPoolId=pool_id,
            DeveloperProviderName="login.localstack",
            DeveloperUserIdentifier=developer_user,
        )
        with pytest.raises(ClientError) as e:
            aws_client.cognito_identity.lookup_developer_identity(
                IdentityPoolId=pool_id, DeveloperUserIdentifier=developer_user
            )
        assert e.value.response["Error"]["Code"] == "ResourceNotFoundException"

    @markers.aws.only_localstack
    def test_unknown_pool_and_identity_fail_closed(
        self, aws_client, identity_pool, account_id, region_name
    ):
        missing_pool = f"{region_name}:00000000-0000-0000-0000-000000000000"
        with pytest.raises(ClientError) as e:
            aws_client.cognito_identity.describe_identity_pool(IdentityPoolId=missing_pool)
        assert e.value.response["Error"]["Code"] == "ResourceNotFoundException"

        identity_pool()
        with pytest.raises(ClientError) as e:
            aws_client.cognito_identity.get_open_id_token(
                IdentityId=f"{region_name}:00000000-0000-0000-0000-000000000000"
            )
        assert e.value.response["Error"]["Code"] in {
            "ResourceNotFoundException",
            "ExternalServiceException",
        }

        # guest access disabled pools must reject guest GetId
        closed_pool = identity_pool(AllowUnauthenticatedIdentities=False)["IdentityPoolId"]
        with pytest.raises(ClientError) as e:
            aws_client.cognito_identity.get_id(AccountId=account_id, IdentityPoolId=closed_pool)
        assert e.value.response["Error"]["Code"] == "NotAuthorizedException"
