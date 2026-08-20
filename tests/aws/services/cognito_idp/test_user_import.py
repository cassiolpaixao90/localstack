import json
from urllib.parse import urlsplit, urlunsplit

import pytest
import requests

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition


@pytest.fixture
def import_pool(aws_client):
    pool = aws_client.cognito_idp.create_user_pool(
        PoolName=f"pool-{short_uid()}",
        AutoVerifiedAttributes=["email"],
    )["UserPool"]
    yield pool
    aws_client.cognito_idp.delete_user_pool(UserPoolId=pool["Id"])


@pytest.fixture
def import_role(aws_client, create_role, region_name, account_id):
    role_name = f"role-{short_uid()}"
    role = create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cognito-idp.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    aws_client.iam.put_role_policy(
        RoleName=role_name,
        PolicyName="cognito-import-logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:DescribeLogStreams",
                            "logs:PutLogEvents",
                        ],
                        "Resource": (
                            f"arn:aws:logs:{region_name}:{account_id}:log-group:/aws/cognito/*"
                        ),
                    }
                ],
            }
        ),
    )
    return role["Role"]["Arn"]


def _local_url(presigned_url: str, endpoint_url: str) -> str:
    # the upload signature binds path and query only; target the test gateway host
    parsed = urlsplit(presigned_url)
    endpoint = urlsplit(endpoint_url)
    return urlunsplit((endpoint.scheme, endpoint.netloc, parsed.path, parsed.query, ""))


def _csv_body(header: list[str], usernames: list[str]) -> bytes:
    rows = []
    for username in usernames:
        values = dict.fromkeys(header, "")
        values.update(
            {
                "cognito:username": username,
                "email": f"{username}@example.test",
                "email_verified": "true",
            }
        )
        rows.append(",".join(values[name] for name in header))
    return (",".join(header) + "\n" + "\n".join(rows) + "\n").encode()


class TestUserImportGateway:
    @markers.aws.only_localstack
    def test_full_import_journey_with_log_delivery(
        self, aws_client, import_pool, import_role, region_name
    ):
        pool_id = import_pool["Id"]
        username = f"imported-{short_uid()}"
        header = aws_client.cognito_idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
        body = _csv_body(header, [username])

        job = aws_client.cognito_idp.create_user_import_job(
            JobName=f"job-{short_uid()}",
            UserPoolId=pool_id,
            CloudWatchLogsRoleArn=import_role,
        )["UserImportJob"]
        assert job["Status"] == "Created"

        upload = requests.put(
            _local_url(job["PreSignedUrl"], aws_client.cognito_idp.meta.endpoint_url),
            data=body,
            headers={"x-amz-server-side-encryption": "aws:kms"},
            timeout=10,
        )
        assert upload.status_code == 200

        aws_client.cognito_idp.start_user_import_job(UserPoolId=pool_id, JobId=job["JobId"])

        def _completed():
            described = aws_client.cognito_idp.describe_user_import_job(
                UserPoolId=pool_id, JobId=job["JobId"]
            )["UserImportJob"]
            return described["Status"] in {"Succeeded", "Failed", "Stopped"}

        assert poll_condition(_completed, timeout=15, interval=0.5), (
            "import job did not reach a terminal state"
        )
        job = aws_client.cognito_idp.describe_user_import_job(
            UserPoolId=pool_id, JobId=job["JobId"]
        )["UserImportJob"]
        assert job["Status"] == "Succeeded"
        assert job["ImportedUsers"] == 1
        assert job["FailedUsers"] == 0

        user = aws_client.cognito_idp.admin_get_user(UserPoolId=pool_id, Username=username)
        assert user["UserStatus"] == "RESET_REQUIRED"
        attributes = {item["Name"]: item["Value"] for item in user["UserAttributes"]}
        assert attributes["email"] == f"{username}@example.test"
        assert attributes["email_verified"] == "true"

        log_group = f"/aws/cognito/userpools/{pool_id}/{import_pool['Name']}"
        events = aws_client.logs.filter_log_events(logGroupName=log_group)["events"]
        assert any('"result":"Succeeded"' in event["message"] for event in events)
        aws_client.logs.delete_log_group(logGroupName=log_group)

    @markers.aws.only_localstack
    def test_upload_requires_signed_headers_through_gateway(
        self, aws_client, import_pool, import_role
    ):
        pool_id = import_pool["Id"]
        header = aws_client.cognito_idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
        body = _csv_body(header, [f"imported-{short_uid()}"])
        job = aws_client.cognito_idp.create_user_import_job(
            JobName=f"job-{short_uid()}",
            UserPoolId=pool_id,
            CloudWatchLogsRoleArn=import_role,
        )["UserImportJob"]
        url = _local_url(job["PreSignedUrl"], aws_client.cognito_idp.meta.endpoint_url)

        unsigned = requests.put(url, data=body, timeout=10)
        assert unsigned.status_code == 403

        tampered = requests.put(
            f"{url}&signature={'0' * 64}",
            data=body,
            headers={"x-amz-server-side-encryption": "aws:kms"},
            timeout=10,
        )
        assert tampered.status_code in {400, 403}
