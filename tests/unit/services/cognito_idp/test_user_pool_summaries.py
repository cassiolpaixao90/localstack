from datetime import UTC, datetime

import pytest

from localstack.services.cognito_idp.user_pool_summaries import (
    UserPoolSummaryError,
    user_pool_summary,
)


def test_list_user_pools_summary_includes_lambda_config_and_sorted_replica_regions():
    pool = {
        "pool_id": "us-east-1_example",
        "name": "enterprise",
        "created_at": datetime(2026, 8, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 8, 2, tzinfo=UTC),
        "lambda_config": {
            "PreSignUp": "arn:aws:lambda:us-east-1:123456789012:function:pre-signup",
            "CustomEmailSender": {
                "LambdaArn": "arn:aws:lambda:us-east-1:123456789012:function:sender",
                "LambdaVersion": "V1_0",
            },
        },
    }

    summary = user_pool_summary(pool, replica_regions=["eu-west-1", "us-west-2", "eu-west-1"])

    assert summary == {
        "Id": "us-east-1_example",
        "Name": "enterprise",
        "CreationDate": pool["created_at"],
        "LastModifiedDate": pool["updated_at"],
        "LambdaConfig": pool["lambda_config"],
        "ReplicaRegions": ["eu-west-1", "us-west-2"],
    }
    summary["LambdaConfig"]["PreSignUp"] = "mutated"
    assert pool["lambda_config"]["PreSignUp"].endswith("pre-signup")


def test_empty_optional_summary_fields_are_omitted():
    pool = {
        "pool_id": "us-east-1_example",
        "name": "minimal",
        "created_at": datetime(2026, 8, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 8, 1, tzinfo=UTC),
        "lambda_config": {},
    }
    summary = user_pool_summary(pool, replica_regions=[])
    assert "LambdaConfig" not in summary
    assert "ReplicaRegions" not in summary


@pytest.mark.parametrize("regions", [["bad region"], ["us-east-1", 1], ["x" * 65]])
def test_invalid_replica_summary_fails_closed(regions):
    pool = {
        "pool_id": "us-east-1_example",
        "name": "pool",
        "created_at": datetime(2026, 8, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 8, 1, tzinfo=UTC),
    }
    with pytest.raises(UserPoolSummaryError):
        user_pool_summary(pool, replica_regions=regions)
