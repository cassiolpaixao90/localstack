import base64
import csv
import hashlib
import io
import json
import re
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from localstack import config
from localstack.testing.pytest import markers
from localstack.utils.http import safe_requests
from localstack.utils.strings import short_uid

_CALLBACK_URL = "https://app.example.test/callback"
_PKCE_VERIFIER = "v" * 43
_IMPORT_TERMINAL_STATES = {"Failed", "Stopped", "Succeeded"}


def _decode_segment(value: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4)))


def _verify_jwt(token: str, keys: list[dict]) -> dict:
    encoded_header, encoded_payload, encoded_signature = token.split(".")
    header = _decode_segment(encoded_header)
    jwk = next(key for key in keys if key["kid"] == header["kid"])
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big"),
        int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=" * ((-len(jwk["n"])) % 4)), "big"),
    ).public_key()
    public_key.verify(
        base64.urlsafe_b64decode(encoded_signature + "=" * ((-len(encoded_signature)) % 4)),
        f"{encoded_header}.{encoded_payload}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return _decode_segment(encoded_payload)


def _hosted_ui_url(domain: str) -> str:
    endpoint = urlsplit(config.internal_service_url())
    assert endpoint.scheme in {"http", "https"}
    assert endpoint.port is not None
    return f"{endpoint.scheme}://{domain}.localhost.localstack.cloud:{endpoint.port}"


def _pkce_challenge() -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(_PKCE_VERIFIER.encode()).digest())
        .rstrip(b"=")
        .decode()
    )


def _authorize_and_redeem(
    session: requests.Session,
    base_url: str,
    client_id: str,
    username: str,
    password: str,
    state: str,
) -> dict:
    authorize = session.get(
        f"{base_url}/oauth2/authorize",
        params={
            "client_id": client_id,
            "code_challenge": _pkce_challenge(),
            "code_challenge_method": "S256",
            "redirect_uri": _CALLBACK_URL,
            "response_type": "code",
            "scope": "openid billgym-api/read",
            "state": state,
        },
        allow_redirects=False,
        timeout=5,
    )
    assert authorize.status_code == 302

    if urlsplit(authorize.headers["Location"]).path == "/login":
        assert session.cookies.get("cognito_oauth_transaction")
        login_form = session.get(f"{base_url}/login", timeout=5)
        assert login_form.status_code == 200
        csrf_match = re.search(rb'name="csrf_token" value="([A-Za-z0-9_-]+)"', login_form.content)
        assert csrf_match is not None
        authenticated = session.post(
            f"{base_url}/login",
            data={
                "csrf_token": csrf_match.group(1).decode(),
                "password": password,
                "username": username,
            },
            allow_redirects=False,
            timeout=5,
        )
        assert authenticated.status_code == 302
        assert session.cookies.get("cognito_oauth_session")
        callback = authenticated.headers["Location"]
    else:
        callback = authorize.headers["Location"]

    callback_parameters = parse_qs(urlsplit(callback).query)
    assert callback.startswith(_CALLBACK_URL)
    assert callback_parameters["state"] == [state]
    code = callback_parameters["code"][0]
    token = session.post(
        f"{base_url}/oauth2/token",
        data={
            "client_id": client_id,
            "code": code,
            "code_verifier": _PKCE_VERIFIER,
            "grant_type": "authorization_code",
            "redirect_uri": _CALLBACK_URL,
        },
        timeout=5,
    )
    assert token.status_code == 200
    return token.json()


@markers.aws.only_localstack
def test_password_auth_jwks_refresh_revoke_and_cleanup(
    aws_client, cognito_idp_resources, region_name
):
    pool = cognito_idp_resources.create_user_pool()["UserPool"]
    client = cognito_idp_resources.create_user_pool_client(
        pool["Id"],
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    username = f"user-{short_uid()}"
    password = "IntegrationPass9!"
    cognito_idp_resources.create_confirmed_user(pool["Id"], username, password)

    authentication = aws_client.cognito_idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client["ClientId"],
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    jwks_response = safe_requests.get(
        f"{config.internal_service_url()}/{pool['Id']}/.well-known/jwks.json",
        timeout=5,
    )
    jwks_response.raise_for_status()
    keys = jwks_response.json()["keys"]

    access_claims = _verify_jwt(authentication["AccessToken"], keys)
    id_claims = _verify_jwt(authentication["IdToken"], keys)
    assert access_claims["iss"] == (f"https://cognito-idp.{region_name}.amazonaws.com/{pool['Id']}")
    assert access_claims["client_id"] == client["ClientId"]
    assert access_claims["token_use"] == "access"
    assert id_claims["aud"] == client["ClientId"]
    assert id_claims["token_use"] == "id"

    refreshed = aws_client.cognito_idp.initiate_auth(
        AuthFlow="REFRESH_TOKEN_AUTH",
        ClientId=client["ClientId"],
        AuthParameters={"REFRESH_TOKEN": authentication["RefreshToken"]},
    )["AuthenticationResult"]
    assert "RefreshToken" not in refreshed
    _verify_jwt(refreshed["AccessToken"], keys)

    aws_client.cognito_idp.revoke_token(
        ClientId=client["ClientId"], Token=authentication["RefreshToken"]
    )
    with pytest.raises(ClientError) as revoked:
        aws_client.cognito_idp.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            ClientId=client["ClientId"],
            AuthParameters={"REFRESH_TOKEN": authentication["RefreshToken"]},
        )
    assert revoked.value.response["Error"]["Code"] == "NotAuthorizedException"


@markers.aws.only_localstack
def test_hosted_ui_custom_scope_tracks_resource_server_updates(
    account_id, cognito_idp_resources, region_name
):
    pool = cognito_idp_resources.create_user_pool()["UserPool"]
    assert pool["Arn"] == f"arn:aws:cognito-idp:{region_name}:{account_id}:userpool/{pool['Id']}"
    cognito_idp_resources.create_resource_server(
        pool["Id"],
        Identifier="billgym-api",
        Name="Billgym API",
        Scopes=[
            {"ScopeDescription": "Read Billgym data", "ScopeName": "read"},
            {"ScopeDescription": "Write Billgym data", "ScopeName": "write"},
        ],
    )
    client = cognito_idp_resources.create_user_pool_client(
        pool["Id"],
        AllowedOAuthFlows=["code"],
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthScopes=["openid", "billgym-api/read"],
        CallbackURLs=[_CALLBACK_URL],
        GenerateSecret=False,
        SupportedIdentityProviders=["COGNITO"],
    )["UserPoolClient"]
    domain = f"amplify-{short_uid()}"
    cognito_idp_resources.create_user_pool_domain(pool["Id"], Domain=domain)
    username = f"user-{short_uid()}"
    password = "IntegrationPass9!"
    cognito_idp_resources.create_confirmed_user(pool["Id"], username, password)

    session = requests.Session()
    session.trust_env = False
    base_url = _hosted_ui_url(domain)
    jwks = safe_requests.get(
        f"{config.internal_service_url()}/{pool['Id']}/.well-known/jwks.json",
        timeout=5,
    )
    jwks.raise_for_status()
    keys = jwks.json()["keys"]
    try:
        active = _authorize_and_redeem(
            session, base_url, client["ClientId"], username, password, "active-read"
        )
        active_claims = _verify_jwt(active["access_token"], keys)
        assert active_claims["client_id"] == client["ClientId"]
        assert active_claims["scope"] == "openid billgym-api/read"
        user_info = session.get(
            f"{base_url}/oauth2/userInfo",
            headers={"Authorization": f"Bearer {active['access_token']}"},
            timeout=5,
        )
        assert user_info.status_code == 200
        assert user_info.json()["username"] == username

        cognito_idp_resources.update_resource_server(
            pool["Id"],
            Identifier="billgym-api",
            Name="Billgym API",
            Scopes=[{"ScopeDescription": "Write Billgym data", "ScopeName": "write"}],
        )
        inactive = _authorize_and_redeem(
            session, base_url, client["ClientId"], username, password, "inactive-read"
        )
        assert _verify_jwt(inactive["access_token"], keys)["scope"] == "openid"

        cognito_idp_resources.update_resource_server(
            pool["Id"],
            Identifier="billgym-api",
            Name="Billgym API",
            Scopes=[
                {"ScopeDescription": "Read Billgym data", "ScopeName": "read"},
                {"ScopeDescription": "Write Billgym data", "ScopeName": "write"},
            ],
        )
        restored = _authorize_and_redeem(
            session, base_url, client["ClientId"], username, password, "restored-read"
        )
        assert _verify_jwt(restored["access_token"], keys)["scope"] == ("openid billgym-api/read")
    finally:
        session.close()


@markers.aws.only_localstack
def test_user_import_upload_endpoint_and_job_runtime(
    account_id,
    aws_client,
    cognito_idp_resources,
    create_role,
    region_name,
):
    pool = cognito_idp_resources.create_user_pool(AutoVerifiedAttributes=["email"])["UserPool"]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Principal": {"Service": "cognito-idp.amazonaws.com"},
            }
        ],
    }
    role = create_role(AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    log_group_arn = (
        f"arn:aws:logs:{region_name}:{account_id}:"
        f"log-group:/aws/cognito/userpools/{pool['Id']}/{pool['Name']}"
    )
    aws_client.iam.put_role_policy(
        RoleName=role["RoleName"],
        PolicyName="cognito-user-import-logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:DescribeLogStreams",
                            "logs:PutLogEvents",
                        ],
                        "Effect": "Allow",
                        "Resource": [log_group_arn, f"{log_group_arn}:*"],
                    }
                ],
            }
        ),
    )
    header = aws_client.cognito_idp.get_csv_header(UserPoolId=pool["Id"])["CSVHeader"]
    row = dict.fromkeys(header, "")
    row.update(
        {
            "cognito:mfa_enabled": "false",
            "cognito:username": f"imported-{short_uid()}",
            "email": f"imported-{short_uid()}@example.test",
            "email_verified": "true",
        }
    )
    csv_file = io.StringIO(newline="")
    writer = csv.DictWriter(csv_file, fieldnames=header, escapechar="\\", lineterminator="\n")
    writer.writeheader()
    writer.writerow(row)
    body = csv_file.getvalue().encode()
    job = aws_client.cognito_idp.create_user_import_job(
        CloudWatchLogsRoleArn=role["Arn"],
        JobName=f"job-{short_uid()}",
        UserPoolId=pool["Id"],
    )["UserImportJob"]
    session = requests.Session()
    session.trust_env = False
    try:
        upload = session.put(
            job["PreSignedUrl"],
            data=body,
            headers={"x-amz-server-side-encryption": "aws:kms"},
            timeout=5,
        )
        assert upload.status_code == 200
    finally:
        session.close()
    aws_client.cognito_idp.start_user_import_job(JobId=job["JobId"], UserPoolId=pool["Id"])
    deadline = time.monotonic() + 10
    while True:
        result = aws_client.cognito_idp.describe_user_import_job(
            JobId=job["JobId"], UserPoolId=pool["Id"]
        )["UserImportJob"]
        if result["Status"] in _IMPORT_TERMINAL_STATES:
            break
        assert time.monotonic() < deadline
        time.sleep(0.1)
    assert result["Status"] == "Succeeded"
    assert result["ImportedUsers"] == 1
    imported = aws_client.cognito_idp.admin_get_user(
        UserPoolId=pool["Id"], Username=row["cognito:username"]
    )
    assert imported["UserStatus"] == "RESET_REQUIRED"
    assert {item["Name"]: item["Value"] for item in imported["UserAttributes"]}["email"] == row[
        "email"
    ]


@markers.aws.only_localstack
def test_auth_event_log_delivery_reaches_local_s3(
    aws_client, cognito_idp_resources, s3_create_bucket
):
    bucket = s3_create_bucket()
    pool = cognito_idp_resources.create_user_pool()["UserPool"]
    client = cognito_idp_resources.create_user_pool_client(
        pool["Id"], ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"]
    )["UserPoolClient"]
    username = f"logged-{short_uid()}"
    password = "IntegrationPass9!"
    cognito_idp_resources.create_confirmed_user(pool["Id"], username, password)
    aws_client.cognito_idp.set_log_delivery_configuration(
        UserPoolId=pool["Id"],
        LogConfigurations=[
            {
                "EventSource": "userAuthEvents",
                "LogLevel": "INFO",
                "S3Configuration": {"BucketArn": f"arn:aws:s3:::{bucket}"},
            }
        ],
    )

    aws_client.cognito_idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client["ClientId"],
        AuthParameters={"PASSWORD": password, "USERNAME": username},
    )

    objects = aws_client.s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert len(objects) == 1
    body = json.loads(aws_client.s3.get_object(Bucket=bucket, Key=objects[0]["Key"])["Body"].read())
    assert body["eventSource"] == "userAuthEvents"
    assert body["event"]["username"] == username
