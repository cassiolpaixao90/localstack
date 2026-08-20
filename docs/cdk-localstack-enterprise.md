# CDK ↔ LocalStack enterprise support architecture

This document describes how this fork supports running the **real, unmodified AWS CDK CLI**
against LocalStack, the gates that keep that contract honest, and the backlog to widen
service coverage.

## Principles

- **Real CLI, pinned toolchain.** Gates run `aws-cdk` 2.1135.1 on Node 22.23.2
  (`tests/aws/cli/package.json`). No `cdklocal` wrapper, no patched SDK.
- **Fail-closed launcher.** `localstack.cli.cdk` (`python -m localstack.cli.cdk`) builds a
  scrubbed child environment (`build_cdk_environment`): fake `test/test` credentials, config
  files pointed at `/dev/null`, `AWS_ENDPOINT_URL` pinned to a loopback/LocalStack host, and
  `validate_local_endpoint` rejects public AWS domains — the CLI cannot escape to real AWS.
- **Objective gates over claims.** Each layer below is executable evidence; a layer is
  "supported" only while its gate is green.
- **Owned resources, zero residue.** Every gate deploys owner-tagged resources into an
  isolated runtime and asserts inventories return to baseline.

## Gate layers

| Layer | What it proves | Entry point | Runtime |
|---|---|---|---|
| L0 synth | Pinned CLI synthesizes templates (blackbox, no runtime) | `tests/aws/cli/test_cdk_cli_blackbox.py`, `test_cdk_cli_python_synth.py` | none |
| L1 in-process deploy | Real CLI deploys against the in-process runtime | `tests/aws/cli/test_cdk_cli_apigateway_deploy.py`, `test_cdk_cli_cognito_deploy.py`, `test_cdk_cli_http_api_jwt_lambda.py`, `test_cdk_cli_default_synth_deploy.py` | pytest in-memory |
| L2 Docker lifecycle | Real CLI deploy/no-op/update/destroy against the built Docker image, container restart, zero residue | `scripts/run_cdk_docker_gate.sh` → `tests/aws/cli/test_cdk_cli_docker_lifecycle.py` | throwaway container |
| L3 bootstrap | `cdk bootstrap` + `DefaultStackSynthesizer` with S3 file-asset publishing | `tests/aws/cli/test_cdk_cli_default_synth_deploy.py` | pytest in-memory |

### Running locally

```bash
make install-test
npm ci --prefix tests/aws/cli --ignore-scripts --engine-strict

# L1/L3 (in-process; runtime starts automatically)
pytest tests/aws/cli/test_cdk_cli_cognito_deploy.py
pytest tests/aws/cli/test_cdk_cli_default_synth_deploy.py

# L2 (Docker lifecycle; uses localstack/localstack:current by default)
bash scripts/run_cdk_docker_gate.sh

# L2 against a freshly built image from this checkout
make docker-build && CDK_DOCKER_GATE_IMAGE=localstack/localstack:latest bash scripts/run_cdk_docker_gate.sh
```

Notes:

- Node must match the pin; outside required CI lanes, `CDK_EXPECTED_NODE_VERSION=<ver>`
  relaxes the probe (skips become visible, not silent).
- The Docker gate picks a **fixed** host port for the container: ephemeral published ports
  change across `docker restart` and would break the restart phase.
- The Docker gate mounts the host Docker socket so the container can execute Lambda
  functions, and starts the container with `PERSISTENCE=1` for the restart phase.
- **S3 addressing with the CDK CLI:** the JS SDK bundled in the CLI ignores
  `AWS_S3_FORCE_PATH_STYLE` and uses virtual-hosted S3 addressing unless the endpoint
  host is an IP literal. Virtual-host addressing is only honored on
  `*.localhost.localstack.cloud` — a `bucket.localhost:4566` host is misrouted (the
  first path segment becomes the bucket). Any flow that publishes file assets
  (DefaultStackSynthesizer deploys) must therefore point the CLI at
  `http://127.0.0.1:<port>`, which makes the SDK fall back to path-style. The L3 gate
  (`_loopback_ip_runtime` in `test_cdk_cli_default_synth_deploy.py`) shows the pattern.
- Ad-hoc CDK usage: `python -m localstack.cli.cdk --endpoint-url http://localhost.localstack.cloud:4566 deploy ...`
  wraps any `cdk` invocation with the fail-closed environment.

### CI

`.github/workflows/cdk-cli-blackbox.yml` runs two lanes on push to `main`:

- `cdk-cli-blackbox` (amd64/arm64): hermetic `unshare --net --pid` sandbox running the L0
  synth gates, the bootstrap-upgrade gate (v28→v32), the API Gateway deploy gate, and the
  Cognito deploy/update/no-op/rollback/destroy lifecycle, with content-addressed execution
  receipts and Sigstore attestation.
- `cdk-docker-gate`: builds the image (`make docker-build`) and runs the L2 Docker
  lifecycle gate against it.

## Restart persistence boundary (measured)

With `PERSISTENCE=1`, the L2 gate's restart phase verifies this surface (container
stop/start with the full `enterprise_platform` topology deployed, followed by
`cdk destroy` against the restarted container):

| Survives container restart | Mechanism |
|---|---|
| CloudFormation stacks (incl. destroy-after-restart) | native store snapshot (`native-v1/`) |
| SQS queues (standard + FIFO), SNS topics/subscriptions | native store snapshot |
| Lambda functions (invoke after restart via version-manager repair) | native store snapshot + startup repair |
| Cognito user pools (encrypted at rest) | native store snapshot (AES-GCM) |
| DynamoDB tables | DynamoDB Local on-disk DB |
| API Gateway v2 APIs (routes re-registered at startup) | native store snapshot + startup repair |

The opt-in point for additional services is `NATIVE_SERVICE_STORES` in
`localstack-core/localstack/state/service_persistence.py`. Stacks left in a
`*_IN_PROGRESS` state at shutdown are swept to AWS-style rollback-failed terminals
on load; LocalStack cannot resume an interrupted rollback, matching the fail-closed
rollback semantics of the v2 engine.

## Coverage backlog (priority order)

Driven by `capabilities/report.md` and `capabilities/aws-feature-gap-report.md`:

- **B1 — restart persistence for CFN stacks, SQS, SNS, Lambda.** Unblocks
  destroy-after-restart and the roadmap's durability track.
- **B2 — CFN resource types:** 6 missing `AWS::ApiGatewayV2::*` (`IntegrationResponse`,
  `Model`, `RouteResponse`, `VpcLink`, `RoutingRule`, `ApiGatewayManagedOverrides`) and
  `AWS::Lambda::CapacityProvider`. Needed by arbitrary third-party CDK apps, not by current
  fixtures.
- **B3 — rollback parity:** rejected updates park in `UPDATE_ROLLBACK_FAILED` instead of
  AWS's `UPDATE_ROLLBACK_COMPLETE` (fail-closed, cross-resource compensation not
  implemented; see `test_cdk_cli_cognito_deploy.py`).
- **B4 — ECR image assets:** `cdk bootstrap` creates the container-assets repository, but
  Docker image asset publishing has no gate yet.
- **B5 — CDK lookups:** gates run with `--no-lookups`; context lookups (VPC, hosted zones,
  SSM) are unverified.
- **B6 — service coverage:** per-service operation status is tracked in
  `capabilities/report.md`; widen CFN/provider coverage per the gap report rather than by
  ad-hoc requests.

## Fixture stacks

- `enterprise_platform.py` — multi-service contract stack (SQS, SNS subscription, DynamoDB,
  Lambda, HTTP API v2, Cognito) used by the L2 Docker gate.
- `default_synth_app.py` — DefaultStackSynthesizer stack with a Lambda file asset, used by
  the L3 bootstrap gate.
- `enterprise_http_api_jwt.py`, `enterprise_cognito.py` — Cognito JWT / full Cognito
  lifecycle fixtures used by the L1 gates.
