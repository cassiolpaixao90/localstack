"""Deploy the EnterpriseHttpApiJwt CDK fixture against the locally running fork.

Mirrors tests/aws/cli/test_cdk_cli_http_api_jwt_lambda.py: real pinned CDK CLI,
LocalStack-restricted environment via localstack.cli.cdk, LegacyStackSynthesizer
(no bootstrap required).
"""

import json
import os
import secrets
import shlex
import sys
import tempfile
from pathlib import Path

from localstack.cli.cdk import (
    CdkExecutableError,
    build_cdk_environment,
    launch_cdk,
    probe_cdk_cli_version,
)
from localstack.constants import AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_PATH = PROJECT_ROOT / "tests/aws/cli/fixtures/cdk_apps/python/enterprise_http_api_jwt.py"
CDK_EXECUTABLE = (PROJECT_ROOT / "tests/aws/cli/node_modules/aws-cdk/bin/cdk").resolve()
PYTHON = PROJECT_ROOT / ".venv/bin/python"
OUTPUT_PATH = PROJECT_ROOT / "e2e-front/cdk-outputs.json"


def main() -> None:
    owner_nonce = secrets.token_hex(12)
    deployment = f"d{owner_nonce[:23]}"
    stack_name = f"localstack-http-jwt-{deployment}"
    workspace = Path(tempfile.mkdtemp(prefix="cdk-e2e-workspace-"))

    environment = build_cdk_environment(
        dict(os.environ),
        region=AWS_REGION_US_EAST_1,
        account_id=DEFAULT_AWS_ACCOUNT_ID,
        endpoint_url="http://localhost.localstack.cloud:4566",
    )
    try:
        probe_cdk_cli_version(str(CDK_EXECUTABLE), environment=environment, cwd=workspace)
    except CdkExecutableError as error:
        result = error.result
        sys.stderr.write(result.stdout.decode(errors="replace"))
        sys.stderr.write(result.stderr.decode(errors="replace"))
        raise SystemExit(f"cdk probe failed: rc={result.returncode} timed_out={result.timed_out}")

    app_command = shlex.join((str(PYTHON), "-I", "-B", str(APP_PATH)))
    result = launch_cdk(
        [
            "deploy",
            "EnterpriseHttpApiJwt",
            "--app",
            app_command,
            "--context",
            f"deployment={deployment}",
            "--context",
            f"owner={owner_nonce}",
            "--outputs-file",
            str(OUTPUT_PATH),
            "--require-approval",
            "never",
            "--no-lookups",
            "--strict",
            "--no-version-reporting",
            "--no-path-metadata",
            "--no-asset-metadata",
            "--no-notices",
            "--no-color",
            "--ci",
            "--execute",
        ],
        executable=str(CDK_EXECUTABLE),
        environment=environment,
        cwd=workspace,
        timeout_seconds=300,
        max_output_bytes=256 * 1024,
    )
    sys.stdout.write(result.stdout.decode(errors="replace"))
    sys.stderr.write(result.stderr.decode(errors="replace"))
    if result.timed_out or result.returncode != 0:
        raise SystemExit(f"cdk deploy failed: rc={result.returncode} timed_out={result.timed_out}")
    outputs = json.loads(OUTPUT_PATH.read_text())
    print(json.dumps(outputs, indent=2))
    print(f"STACK_NAME={stack_name}")


if __name__ == "__main__":
    main()
