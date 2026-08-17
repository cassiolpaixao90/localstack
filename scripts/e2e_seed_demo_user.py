"""Seed the demo user into the deployed pool and smoke-test the browser paths.

Reads e2e-front/cdk-outputs.json, creates demo@example.test (group member), then
verifies the exact requests the browser makes: CORS preflight and InitiateAuth with
an Origin header.
"""

import json
from pathlib import Path

import boto3
import requests

ENDPOINT = "http://localhost.localstack.cloud:4566"
REGION = "us-east-1"
ORIGIN = "http://localhost:3100"
USERNAME = "demo@example.test"
PASSWORD = "EnterprisePass9!"
GROUP = "member"

outputs = json.loads(
    (Path(__file__).resolve().parent.parent / "e2e-front/cdk-outputs.json").read_text()
)
(stack_outputs,) = outputs.values()
pool_id = stack_outputs["UserPoolId"]
client_id = stack_outputs["UserPoolClientId"]
api_endpoint = stack_outputs["ApiEndpoint"]

idp = boto3.client(
    "cognito-idp",
    endpoint_url=ENDPOINT,
    region_name=REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
)
idp.admin_create_user(
    UserPoolId=pool_id,
    Username=USERNAME,
    TemporaryPassword="TempPass9!xx",
    UserAttributes=[
        {"Name": "email", "Value": USERNAME},
        {"Name": "email_verified", "Value": "true"},
    ],
    MessageAction="SUPPRESS",
)
idp.admin_set_user_password(
    UserPoolId=pool_id, Username=USERNAME, Password=PASSWORD, Permanent=True
)
idp.create_group(UserPoolId=pool_id, GroupName=GROUP)
idp.admin_add_user_to_group(UserPoolId=pool_id, Username=USERNAME, GroupName=GROUP)

preflight = requests.options(
    f"{ENDPOINT}/",
    headers={
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-amz-target",
    },
    timeout=5,
)
allow_origin = preflight.headers.get("Access-Control-Allow-Origin")
print(f"cognito preflight: {preflight.status_code} allow-origin={allow_origin!r}")

auth = idp.initiate_auth(
    AuthFlow="USER_PASSWORD_AUTH",
    ClientId=client_id,
    AuthParameters={"USERNAME": USERNAME, "PASSWORD": PASSWORD},
)
token = auth["AuthenticationResult"]["IdToken"]
print(f"initiate-auth ok, id token len={len(token)}")

api = requests.get(
    f"{api_endpoint}/private/exercise-1",
    headers={"Authorization": f"Bearer {token}", "Origin": ORIGIN},
    timeout=10,
)
print(
    f"api with jwt: {api.status_code} allow-origin={api.headers.get('Access-Control-Allow-Origin')!r}"
)
print(api.text)
