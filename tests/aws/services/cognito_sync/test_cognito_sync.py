import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@pytest.fixture
def sync_identity(aws_client, account_id):
    pool = aws_client.cognito_identity.create_identity_pool(
        IdentityPoolName=f"pool-{short_uid()}",
        AllowUnauthenticatedIdentities=True,
    )
    pool_id = pool["IdentityPoolId"]
    identity_id = aws_client.cognito_identity.get_id(AccountId=account_id, IdentityPoolId=pool_id)[
        "IdentityId"
    ]
    yield pool_id, identity_id
    aws_client.cognito_identity.delete_identity_pool(IdentityPoolId=pool_id)


def _create_dataset(aws_client, pool_id, identity_id, dataset, records):
    token = aws_client.cognito_sync.list_records(
        IdentityPoolId=pool_id, IdentityId=identity_id, DatasetName=dataset
    )["SyncSessionToken"]
    patches = [
        {"Op": "replace", "Key": key, "Value": value, "SyncCount": 0}
        for key, value in records.items()
    ]
    return aws_client.cognito_sync.update_records(
        IdentityPoolId=pool_id,
        IdentityId=identity_id,
        DatasetName=dataset,
        SyncSessionToken=token,
        RecordPatches=patches,
    )


class TestCognitoSync:
    @markers.aws.only_localstack
    def test_dataset_lifecycle_and_conflict_semantics(self, aws_client, sync_identity):
        pool_id, identity_id = sync_identity
        sync = aws_client.cognito_sync
        dataset = f"dataset-{short_uid()}"

        session = sync.list_records(
            IdentityPoolId=pool_id, IdentityId=identity_id, DatasetName=dataset
        )
        assert session["DatasetExists"] is False
        assert session["Records"] == []
        token = session["SyncSessionToken"]

        updated = sync.update_records(
            IdentityPoolId=pool_id,
            IdentityId=identity_id,
            DatasetName=dataset,
            SyncSessionToken=token,
            RecordPatches=[{"Op": "replace", "Key": "k1", "Value": "v1", "SyncCount": 0}],
        )
        assert updated["Records"][0]["SyncCount"] == 1

        described = sync.describe_dataset(
            IdentityPoolId=pool_id, IdentityId=identity_id, DatasetName=dataset
        )
        assert described["Dataset"]["NumRecords"] == 1

        with pytest.raises(ClientError) as e:
            sync.update_records(
                IdentityPoolId=pool_id,
                IdentityId=identity_id,
                DatasetName=dataset,
                SyncSessionToken=token,
                RecordPatches=[{"Op": "replace", "Key": "k2", "Value": "v2", "SyncCount": 0}],
            )
        assert e.value.response["Error"]["Code"] == "ResourceConflictException"

        fresh = sync.list_records(
            IdentityPoolId=pool_id, IdentityId=identity_id, DatasetName=dataset, LastSyncCount=0
        )
        assert fresh["DatasetSyncCount"] == 1
        assert fresh["Records"][0]["Key"] == "k1"
        assert fresh["Records"][0]["Value"] == "v1"

        # incremental listing only returns records changed after LastSyncCount
        incremental = sync.list_records(
            IdentityPoolId=pool_id, IdentityId=identity_id, DatasetName=dataset, LastSyncCount=1
        )
        assert incremental["Records"] == []

        with pytest.raises(ClientError) as e:
            sync.update_records(
                IdentityPoolId=pool_id,
                IdentityId=identity_id,
                DatasetName=dataset,
                SyncSessionToken=fresh["SyncSessionToken"],
                RecordPatches=[{"Op": "replace", "Key": "k1", "Value": "v2", "SyncCount": 0}],
            )
        assert e.value.response["Error"]["Code"] == "ResourceConflictException"

        updated = sync.update_records(
            IdentityPoolId=pool_id,
            IdentityId=identity_id,
            DatasetName=dataset,
            SyncSessionToken=fresh["SyncSessionToken"],
            RecordPatches=[{"Op": "replace", "Key": "k1", "Value": "v2", "SyncCount": 1}],
        )
        assert updated["Records"][0]["SyncCount"] == 2

        listed = sync.list_datasets(IdentityPoolId=pool_id, IdentityId=identity_id)
        assert [d["DatasetName"] for d in listed["Datasets"]] == [dataset]

        removed = sync.delete_dataset(
            IdentityPoolId=pool_id, IdentityId=identity_id, DatasetName=dataset
        )
        assert removed["Dataset"]["DatasetName"] == dataset

        with pytest.raises(ClientError) as e:
            sync.describe_dataset(
                IdentityPoolId=pool_id, IdentityId=identity_id, DatasetName=dataset
            )
        assert e.value.response["Error"]["Code"] == "ResourceNotFoundException"

        after_delete = sync.list_records(
            IdentityPoolId=pool_id, IdentityId=identity_id, DatasetName=dataset, LastSyncCount=2
        )
        assert after_delete["DatasetExists"] is False
        assert after_delete["DatasetDeletedAfterRequestedSyncCount"] is True

    @markers.aws.only_localstack
    def test_list_datasets_pagination_and_invalid_cursor(self, aws_client, sync_identity):
        pool_id, identity_id = sync_identity
        sync = aws_client.cognito_sync
        suffix = short_uid()
        names = sorted(f"dataset-{i}-{suffix}" for i in range(3))
        for name in names:
            _create_dataset(aws_client, pool_id, identity_id, name, {"k": "v"})

        page1 = sync.list_datasets(IdentityPoolId=pool_id, IdentityId=identity_id, MaxResults=2)
        assert page1["Count"] == 2
        assert "NextToken" in page1
        page2 = sync.list_datasets(
            IdentityPoolId=pool_id,
            IdentityId=identity_id,
            MaxResults=2,
            NextToken=page1["NextToken"],
        )
        assert page2["Count"] == 1
        assert "NextToken" not in page2
        collected = [d["DatasetName"] for d in page1["Datasets"] + page2["Datasets"]]
        assert collected == names

        with pytest.raises(ClientError) as e:
            sync.list_datasets(IdentityPoolId=pool_id, IdentityId=identity_id, NextToken="bogus")
        assert e.value.response["Error"]["Code"] == "InvalidParameterException"

        with pytest.raises(ClientError) as e:
            sync.list_datasets(IdentityPoolId=pool_id, IdentityId=identity_id, MaxResults=0)
        assert e.value.response["Error"]["Code"] == "InvalidParameterException"

    @markers.aws.only_localstack
    def test_identity_usage_reflects_datasets(self, aws_client, sync_identity):
        pool_id, identity_id = sync_identity
        sync = aws_client.cognito_sync
        _create_dataset(
            aws_client, pool_id, identity_id, f"dataset-{short_uid()}", {"k1": "v1", "k2": "v2"}
        )

        usage = sync.describe_identity_usage(IdentityPoolId=pool_id, IdentityId=identity_id)
        assert usage["IdentityUsage"]["DatasetCount"] == 1
        assert usage["IdentityUsage"]["DataStorage"] > 0

        pool_usage = sync.describe_identity_pool_usage(IdentityPoolId=pool_id)
        assert pool_usage["IdentityPoolUsage"]["DataStorage"] > 0
        assert pool_usage["IdentityPoolUsage"]["SyncSessionsCount"] >= 1

        listed = sync.list_identity_pool_usage()
        entry = next(u for u in listed["IdentityPoolUsages"] if u["IdentityPoolId"] == pool_id)
        assert entry["DataStorage"] > 0

    @markers.aws.only_localstack
    def test_cognito_events_roundtrip(self, aws_client, sync_identity):
        pool_id, _ = sync_identity
        sync = aws_client.cognito_sync

        assert sync.get_cognito_events(IdentityPoolId=pool_id)["Events"] == {}
        sync.set_cognito_events(IdentityPoolId=pool_id, Events={})
        assert sync.get_cognito_events(IdentityPoolId=pool_id)["Events"] == {}

    @markers.aws.only_localstack
    def test_sync_fails_closed_for_unknown_pool_and_identity(self, aws_client, sync_identity):
        pool_id, identity_id = sync_identity
        sync = aws_client.cognito_sync

        with pytest.raises(ClientError) as e:
            sync.list_datasets(
                IdentityPoolId=pool_id, IdentityId="us-east-1:00000000-0000-0000-0000-000000000000"
            )
        assert e.value.response["Error"]["Code"] == "ResourceNotFoundException"

        with pytest.raises(ClientError) as e:
            sync.list_records(
                IdentityPoolId=pool_id,
                IdentityId=identity_id,
                DatasetName="dataset",
                SyncSessionToken="bogus",
            )
        assert e.value.response["Error"]["Code"] == "InvalidParameterException"

        with pytest.raises(ClientError) as e:
            sync.update_records(
                IdentityPoolId=pool_id,
                IdentityId=identity_id,
                DatasetName="dataset",
                SyncSessionToken="bogus",
                RecordPatches=[],
            )
        assert e.value.response["Error"]["Code"] == "InvalidParameterException"
