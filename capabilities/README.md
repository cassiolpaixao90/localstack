# AWS capability inventory

This directory contains the machine-generated baseline used by the AWS feature
parity roadmap.

Generate it from the repository root in an environment with the project's pinned
Botocore version installed:

```bash
PYTHONPATH=localstack-core python -m localstack.capabilities
```

Verify that committed artifacts are current:

```bash
PYTHONPATH=localstack-core python -m localstack.capabilities --check
```

Artifacts:

- `catalog.lock.json`: pinned Botocore denominator and model digests;
- `generated/capabilities.json`: per-service and per-operation static inventory;
- `cdk/compatibility.json`: content-addressed CDK language, toolchain, and
  scenario planning baseline;
- `cdk/compatibility.schema.json`: closed contract for the CDK baseline;
- `report.md`: human-readable summary derived from the JSON inventory.

Do not edit generated files manually. Static analysis never promotes an operation
to `native` or `parity-pass`; those states require runtime dispatch evidence and
fresh differential validation against AWS.

Metrics mode now appends request dispatch origins to the local raw CSV. The
existing Tinybird `tests_raw__v0` uploader does not ingest that new column; a
versioned remote schema and evidence importer are explicit Wave 0 follow-up.

Convert one or more metric reports into a bounded, deterministic evidence
overlay:

```bash
PYTHONPATH=localstack-core python -m localstack.capabilities.evidence \
  --catalog capabilities/generated/capabilities.json \
  --metrics target/metric_reports \
  --observed-at 2026-08-08T18:00:00Z \
  --source-commit "$(git rev-parse HEAD)" \
  --output target/capability-evidence/evidence.json
```

The importer verifies the catalog's schema and inventory digest, streams CSV
rows, checks each operation against that catalog, and hashes the exact byte
stream being parsed. File count, input bytes, header, record, field, trace, and
diagnostic cardinality all have fail-closed ceilings. Output is written
atomically and conforms to `evidence.schema.json`. Raw metric CSVs can contain
request details and remain private CI artifacts under `target/`; do not commit
them.

This first overlay deliberately has `mode: informational` and marks every
promotion as ineligible. In the legacy CSV, `aws_validated` means that a test
has a marker and `snapshot` means that the fixture exists; neither proves a
successful AWS run or snapshot comparison. A future promotion pipeline must
join an isolated, no-rerun local run with JUnit outcome, explicit scenario
scope, provider selection, a fresh AWS validation, and zero critical snapshot
skips. Changing input order or repeating the same row does not change the
semantic digest, while the evidence ID still binds the exact files and row
counts used.

The CDK baseline follows the same conservative rule. It requires every stable
AWS binding and records current template-only or API-simulated coverage without
claiming that the real CLI works. Future execution evidence must be attached to
an exact language, Node, CLI, construct-library, Cloud Assembly, bootstrap,
platform, and scenario tuple; never replace that matrix with a global
`cdk_supported` boolean.

The launcher treats the standard CDK CLI as trusted code and supervises one
POSIX process group. It bounds retained capture and runtime but is not a
sandbox: a child that deliberately starts a detached session is outside this
boundary. Stronger containment requires a separately validated cgroup v2 or
Windows Job Object adapter.

The executable adapter is available as
`PYTHONPATH=localstack-core python -m localstack.cli.cdk [launcher options]
<cdk-command> [cdk-options]`. Launcher options must precede the CDK command;
all later arguments are forwarded literally. Explicit flags override
`LSTK_CDK_CMD`, `AWS_ENDPOINT_URL`, `AWS_ENDPOINT_URL_S3`, and `AWS_REGION`.
By default it verifies a bounded LocalStack health response and a stable CDK
CLI version of at least 2.177.0, inherits stdout/stderr directly, and inherits
stdin only when attached to a terminal. Capture memory is bounded for probes
and non-file test streams; bytes emitted by the child are intentionally not
bounded. `--unsafe-skip-version-check` is a diagnostic
escape hatch, not evidence of compatibility. The preflight and sentinel AWS
credentials reduce accidental AWS access but do not replace an external
network-egress policy for untrusted CDK applications.

The health request runs in a short-lived stdlib-only helper selected by
absolute path with isolated Python flags and a minimal environment. This keeps
the total deadline enforceable without inheriting AWS credentials, proxy
settings, Python import paths, or a persistent multiprocessing tracker.

The first real-CLI black-box gate is intentionally language-neutral and does
not create cloud resources. Its toolchain is locked under `tests/aws/cli/` to
Node 22.23.2 and `aws-cdk` 2.1135.1. The required CI lane must install it from
the committed lock before denying external egress, set
`CDK_REAL_CLI_REQUIRED=1`, and run:

```bash
npm ci --prefix tests/aws/cli --ignore-scripts --no-audit --no-fund --engine-strict
TEST_TARGET=LOCALSTACK CDK_REAL_CLI_REQUIRED=1 \
  pytest tests/aws/cli/test_cdk_cli_blackbox.py
```

The test uses the safe adapter primitives with bounded output and runtime,
requires the exact CLI version, and compares `bootstrap --show-template`
semantically with the pinned official v32 template. A local run with a
different Node version may set `CDK_EXPECTED_NODE_VERSION` for diagnostics,
but that execution is not promotion evidence. This gate alone does not prove
bootstrap deployment, Cloud Assembly generation, a language binding, or AWS
parity, so the aggregate manifest remains unchanged until the required
platform matrix produces attestable evidence.

The static provider inventory covers the providers declared by this checkout.
Static classifications use the provider registered as `default`; the JSON also
lists selectable alternatives without claiming they are active. External plugins
and runtime-selected alternatives must be added later through runtime evidence
rather than inferred as part of this deterministic baseline.
