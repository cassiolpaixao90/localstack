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
  --expected-inventory-sha256 "$CAPABILITY_INVENTORY_SHA256" \
  --output target/capability-evidence/evidence.json
```

The importer validates the catalog against the closed schema, verifies its
self-digest, and requires an inventory digest supplied independently by a
trusted CI configuration or attestation. Never derive
`CAPABILITY_INVENTORY_SHA256` from the catalog in the same untrusted step. It
then streams CSV rows, checks each operation against that catalog, and hashes
the exact byte stream being parsed. File count, input bytes, header, record,
field, trace, and diagnostic cardinality all have fail-closed ceilings. The
catalog JSON is capped at 4 MiB before decoding. Output is written atomically
and conforms to `evidence.schema.json`. Raw metric CSVs can contain request
details and remain private CI artifacts under `target/`; do not commit them.

`--source-commit` is a caller-supplied declaration in this informational
overlay, not an authenticated provenance claim. A promotion workflow must bind
the commit and expected inventory digest together in a trusted attestation.

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
Node 22.23.2 and `aws-cdk` 2.1135.1. The dedicated CI workflow runs natively on
Linux amd64 and arm64, installs from the committed lock, then executes pytest
inside a network namespace containing only loopback. A local diagnostic run
can install and invoke the same test with:

```bash
npm ci --prefix tests/aws/cli --ignore-scripts --no-audit --no-fund --engine-strict
TEST_TARGET=LOCALSTACK pytest tests/aws/cli/test_cdk_cli_blackbox.py
```

The test uses the safe adapter primitives with bounded output and runtime,
requires the exact native architecture and CLI version, and compares
`bootstrap --show-template` semantically with the pinned official v32
template. A local run with a different Node version may set
`CDK_EXPECTED_NODE_VERSION` for diagnostics, but that execution is not
promotion evidence. This gate alone does not prove bootstrap deployment,
Cloud Assembly generation, a language binding, or AWS parity. Promotion of its
narrow client-side scenario requires both post-merge platform runs to produce
attestable evidence. Each required lane emits a bounded,
content-addressed receipt only after the last assertion. The aggregator rejects
reruns, validates the exact amd64/arm64 pair and their JUnit reports, binds all
relevant harness inputs, and creates a candidate JSON conforming to
`cdk/execution-evidence.schema.json`. GitHub Actions attests that aggregate;
the receipt remains ineligible for broad promotion because this client-side
scenario performs no bootstrap deployment, produces no Cloud Assembly, tests
no language binding, and contains no AWS differential result.

Run `31288954038` supplied the first durable aggregate for commit
`1a23acd9b65fef0ef5a944bd4b412f9af9348665`. The repository preserves both
the content-addressed JSON and its Sigstore bundle under
`cdk/evidence/runs/31288954038/`. This promotes only the language-neutral
`bootstrap-show-template-v32` execution scenario to `cli-pass`; the aggregate
bootstrap capability remains `api-simulated`, with no supported language
inferred from this client-side command.

The separate `bootstrap-upgrade-v28-v32` gate seeds the pinned repository v28
fixture with a CloudFormation change set and upgrades that stack through the
real CDK CLI's built-in v32 template. The test writes only a bounded provisional
observation. A lane receipt is created after pytest has returned successfully,
the exact JUnit has proved that strict stack, bucket, role, and SSM cleanup also
completed, and the run/platform/toolchain contract has been validated. The
real argv is checked before emission and represented once by its normalized
dynamic fields plus a closed `argv_contract`, avoiding contradictory duplicate
values in the record. The two
native receipts are aggregated under
`cdk/bootstrap-upgrade-execution-evidence.schema.json` and attested as a subject
separate from the retained `bootstrap-show-template-v32` evidence. Candidate
run `31305122966` for commit
`c4a933343b6be315208edd68bb4827650275fcc6` passed both native platforms; its
content-addressed aggregate and Sigstore bundle are retained under
`cdk/evidence/runs/31305122966/`. This promotes only the language-neutral
`bootstrap-upgrade-v28-v32` scenario to `cli-pass`. The broad bootstrap
capability remains `api-simulated`; this transition does not prove a clean
bootstrap create, Cloud Assembly, any language binding, or AWS parity.
Promotion must pass both the closed JSON Schema and the scenario runtime
validator, which enforces cross-field run, platform, and command relationships
that JSON Schema cannot express by itself.

The Python `synth-python-minimal-sqs-v1` follow-up is deliberately diagnostic.
It uses the already pinned Python CDK packages and default stack synthesizer to
synthesize one L1 SQS resource through the real CLI, with no user-authored file
or Docker assets, lookups, deployment, or external egress. The default
synthesizer's stack-template asset manifest is closed explicitly. The emitted
assembly is bounded and structurally validated, but its standalone JUnit is
not compatibility evidence. A separate native
amd64/arm64 receipt, aggregate, attestation, and review are required before the
manifest can record Python or Cloud Assembly support.

Ingestion is allowed only after offline bundle verification pins every signer
boundary used by this record:

```bash
gh attestation verify capabilities/cdk/evidence/runs/31288954038/cdk-cli-execution-evidence.json \
  --bundle capabilities/cdk/evidence/runs/31288954038/cdk-cli-execution-evidence.sigstore.json \
  --repo cassiolpaixao90/localstack \
  --signer-workflow cassiolpaixao90/localstack/.github/workflows/cdk-cli-blackbox.yml \
  --source-digest 1a23acd9b65fef0ef5a944bd4b412f9af9348665 \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners

gh attestation verify capabilities/cdk/evidence/runs/31305122966/cdk-bootstrap-upgrade-execution-evidence.json \
  --bundle capabilities/cdk/evidence/runs/31305122966/cdk-bootstrap-upgrade-execution-evidence.sigstore.json \
  --repo cassiolpaixao90/localstack \
  --signer-workflow cassiolpaixao90/localstack/.github/workflows/cdk-cli-blackbox.yml \
  --source-digest c4a933343b6be315208edd68bb4827650275fcc6 \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```

The unit gate checks the retained bytes, DSSE subject and provenance fields;
the commands above are the cryptographic signature and certificate-chain gates.

The static provider inventory covers the providers declared by this checkout.
Static classifications use the provider registered as `default`; the JSON also
lists selectable alternatives without claiming they are active. External plugins
and runtime-selected alternatives must be added later through runtime evidence
rather than inferred as part of this deterministic baseline.
