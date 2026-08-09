# AWS Feature Parity Roadmap

Status: proposed
Created: 2026-08-08
Scope baseline: public archive checkout `8b9a79f05846835cf4dff63ab7eefdde9df83783`
dated 2026-03-23 and the public AWS/LocalStack catalog available on the creation
date. `v4.14.0` is a release reference, not a proven equivalent tag for this checkout.

## 1. Objective

Evolve the public LocalStack fork into a high-fidelity, high-performance local
AWS emulator, including capabilities currently distributed in paid LocalStack
plans, through an independent clean-room implementation.

The project should target a versioned AWS catalog with explicit fidelity levels.
"All AWS features" is not a fixed endpoint: AWS changes continuously, and some
managed or physical data planes cannot be reproduced locally with complete
fidelity. The defensible target is:

- broad protocol and control-plane coverage;
- high semantic fidelity for prioritized development journeys;
- delegated local engines where they provide useful data-plane behavior;
- explicit, machine-readable deviations rather than false success responses;
- predictable local performance guarded by regression tests.

## 2. Executive decision

1. Keep Python as the control plane, provider framework, plugin surface, and
   compatibility layer.
2. Build a common kernel for identity, IAM, state, persistence, scheduling,
   asynchronous delivery, and observability before expanding the service count.
3. Deliver complete vertical journeys, including IAM, CloudFormation,
   CloudControl, CDK, persistence, and performance, rather than isolated CRUD
   handlers.
4. Use Rust or Go only for measured hotspots or autonomous backends with a
   stable boundary. Do not perform a big-bang rewrite.
5. Treat documentation, API models, validation freshness, and capability status
   as versioned inputs to an automated catalog.

## 3. Clean-room policy

### Allowed sources

- Public AWS documentation.
- Public Botocore and Smithy models and traits.
- Public CloudFormation Resource Specifications.
- Public AWS CDK, Cloud Assembly, and bootstrap specifications.
- Black-box experiments run against an AWS account controlled by the project.
- Open-source projects with audited, distribution-compatible licenses.

### Prohibited sources and actions

- Extracting or decompiling paid LocalStack images.
- Copying proprietary implementation code, tests, snapshots, UI, or assets.
- Reproducing proprietary licensing or hosted SaaS mechanisms.
- Incorporating dependencies with incompatible licenses without legal and
  architectural approval.

The clean-room artifact is a neutral behavioral specification: inputs, outputs,
errors, state transitions, observable timing, and side effects. It must not
describe the internal implementation of a paid product.

Each clean-room requirement must eventually record:

```yaml
source:
version_or_tag:
commit_or_sha256:
license:
retrieved_at:
covered_features:
experiment_reference:
supersedes:
```

Legal review remains necessary and is not replaced by this engineering policy.
The first static inventory records the pinned Botocore version, license, URI,
model hashes, and inventory digest. Retrieval time, generator commit, dependency
digests, and experiment references remain explicit provenance gaps for the next
catalog iteration.

### Fork governance prerequisite

The [upstream notice](../README.md) declares the public repository archived and
read-only following consolidation into a unified LocalStack image. Before a
redistributable fork or feature release, record an explicit go/no-go decision
covering `LICENSE.txt` and referenced EULA terms, trademark and product naming,
attribution, contribution licensing, security reporting and embargo handling,
release signing/SBOM ownership, code owners/reviewers, and a policy for consuming
AWS model/documentation changes without an active public upstream. No capability
roadmap milestone implies permission to use LocalStack trademarks or proprietary
artifacts.

### Comparable projects and reuse posture

| Project | Useful lesson | Project posture |
|---|---|---|
| [Moto](https://github.com/getmoto/moto) (Apache-2.0) | Broad Python service models and fast in-process test doubles | Keep as a pinned, observable fallback; never equate delegation with parity |
| [ElasticMQ](https://github.com/softwaremill/elasticmq) (Apache-2.0) | Asynchronous SQS semantics, strict limits, persistence, and a dedicated performance suite | Evaluate as a replaceable SQS backend against the same conformance corpus |
| [Adobe S3Mock](https://github.com/adobe/S3Mock) (Apache-2.0) | Isolated container/Testcontainers distribution and an explicit supported-operation matrix | Reuse packaging and compatibility-matrix ideas; compare S3 behavior black-box |
| [kinesis-mock](https://github.com/etspaceman/kinesis-mock) (MIT) | Standalone Kinesis process, configurable lifecycle delays, account/region partitioning, and persistence | Candidate delegated data plane after differential, soak, and crash testing |
| [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html) | AWS-maintained local data plane distributed as JAR, Maven artifact, and container | Keep behind a process boundary; pin version and distribution terms |
| [MinIO](https://github.com/minio/minio) (AGPL-3.0, archived) | High-performance S3-compatible storage architecture and operational tooling | Architectural study only; do not incorporate or distribute its code without explicit legal approval |

The common lesson is to separate the AWS-facing protocol/control plane from
replaceable local data planes. Every delegated engine needs an adapter contract,
version and license record, health and shutdown lifecycle, resource limits,
capability declaration, and the same AWS differential suite. An engine may improve
throughput without raising the operation above `fallback` until semantics pass.

The implementations also span distinct boundaries: Moto is Python/in-process;
ElasticMQ is an actor-based Scala/JVM service that can run embedded or standalone;
S3Mock is Kotlin/Spring Boot in a process or container; kinesis-mock exposes an
http4s server for JVM and Node distributions; and MinIO is Go. This demonstrates
that isolated backends and HTTP contracts are viable, not that a language rewrite
will improve fidelity or speed. Only profiling plus differential tests can justify
moving a measured component.

## 4. Baseline assessment

The deterministic Botocore-denominator inventory currently finds:

- 415 Botocore services and 17,854 operations in the denominator;
- 37 generated API interfaces and 35 services with registered providers;
- 15,004 missing operations, 286 generated scaffolds, 1,939 fallback
  candidates, and 625 partial/native candidates;
- zero operations promoted to `native` or `parity-pass` without runtime proof;
- 102 CloudFormation resource types found by static source analysis;
- approximately 4,600 tests or validation entries;
- performance tests concentrated mainly on SQS and DynamoDB, without systematic
  CI regression gates.

The generated baseline is available in
[`capabilities/report.md`](../capabilities/report.md), with its pinned Botocore
denominator in [`capabilities/catalog.lock.json`](../capabilities/catalog.lock.json).

The existing generator in
[`localstack-core/localstack/aws/scaffold.py`](../localstack-core/localstack/aws/scaffold.py)
is a useful foundation. It should also generate or index IAM metadata, ARN
templates, endpoint rules, idempotency, pagination, checksums, streaming traits,
CloudFormation metadata, and capability manifests.

## 5. Capability catalog

The current commercial matrix is evidence of current packaging, not proof that
every capability belonged to the same tier at the fork date. The catalog must
therefore retain both `observed_at` and `source_version`.

Primary references:

- [Current LocalStack licensing matrix](https://docs.localstack.cloud/aws/licensing/)
- [Current LocalStack service catalog](https://docs.localstack.cloud/aws/services/)
- [LocalStack 4.14 release](https://blog.localstack.cloud/localstack-for-aws-release-v-4-14-0/)

### Base service backlog

- API Gateway HTTP, WebSocket, and Management APIs.
- Cognito User Pools and Identity Pools.
- ECR, ECS, and ElastiCache.
- RDS and RDS Data API.
- Elastic Load Balancing, ELBv2, and CloudFront.
- Amazon MQ and SES v2.
- CodeCommit, CodeArtifact, CodeBuild, and CodeConnections.
- IoT, AppConfig, Application Auto Scaling, and EC2 Auto Scaling.

### Ultimate service backlog

- EventBridge Pipes and MWAA.
- Athena, Glue, Lake Formation, MSK, Flink, EMR, and EMR Serverless.
- EKS, Batch, Elastic Beanstalk, and Serverless Application Repository.
- AppSync, Amplify, and Cloud Map.
- CodeDeploy, CodePipeline, FIS, and X-Ray.
- Organizations, Account Management, CloudTrail, RAM, WAF, Verified
  Permissions, Private CA, Identity Store, and Identity Center.
- DocumentDB, MemoryDB, Neptune, and Timestream.
- Transfer Family, DMS, EFS, Backup, and Glacier.
- Bedrock, SageMaker, Textract, MediaConvert, and Pinpoint.
- IoT Data and IoT Wireless.
- Managed Blockchain, Cost Explorer, Shield, and remaining catalog services.

### Cross-cutting and platform backlog

- Local persistence, export, import, and schema migration.
- IAM Policy Enforcement.
- IAM Policy Streams.
- AWS resource replication/import.
- Cloud Pods-compatible snapshot packaging, using a project-owned format.
- Stack diagnostics and a project-owned causal graph/inspector.
- Fault injection and resiliency testing.
- Air-gapped, reproducible images with SBOM and offline dependencies.
- Kubernetes operator/executor.
- Standard OIDC, SAML, and SCIM integration if a multi-user product is built.

Hosted sandbox, portal, billing, support, and other SaaS functionality are not
AWS parity and must not block the emulator roadmap.

## 6. Capability model

Every operation must have one unambiguous implementation state:

- `missing`;
- `scaffold`;
- `fallback`;
- `partial`;
- `native`;
- `parity-pass`.

Fidelity is tracked independently:

- `L0`: protocol parsing and serialization;
- `L1`: control-plane CRUD;
- `L2`: useful local data plane;
- `L3`: cross-service integrations;
- `L4`: IAM, lifecycle, errors, persistence, and IaC fidelity;
- `L5`: validated behavior and declared performance SLO.

Example:

```yaml
service: pipes
catalog:
  source: botocore
  version: 1.42.59
provider:
  name: native-v1
  state_schema: 1
operations:
  CreatePipe:
    status: native
    fidelity: L3
    authorization: pass
    scenarios:
      valid_create:
        parity: pass
        aws_validated_at: 2026-08-01
      invalid_role:
        parity: pass
      duplicate_name:
        parity: fail
    dependencies:
      - iam:PassRole
      - events:EventBus
      - lambda:InvokeFunction
    cfn_resources:
      - AWS::Pipes::Pipe
    known_deviations: []
```

## 7. Target architecture

```text
Versioned AWS/CDK catalog
        |
        v
Deterministic generator
  APIs | IAM | ARN | CFN | manifests
        |
        v
Common kernel
  identity and authorization
  versioned state and persistence
  clock and durable scheduler
  event bus and transactional outbox
  tagging, pagination, and idempotency
  bounded concurrency and backpressure
  capability registry and observability
        |
        v
Service providers
  native control plane
  native or delegated data plane
  typed integrations
  CloudFormation and CloudControl
```

### Provider rules

- Register implementation origin per operation.
- Treat Moto and HTTP fallback as temporary migration states.
- Do not access another provider's private store.
- Use a typed internal client for synchronous service calls.
- Use an event bus and durable scheduler for asynchronous work.
- Propagate the original or AWS-equivalent service principal explicitly.
- Keep alternate providers selectable to support canary migrations.

### State and persistence

Evolve `AccountRegionBundle` into a state contract with:

- schema version per service;
- persistent DTOs separate from runtime objects;
- explicit `N -> N+1` migrations;
- resource-level concurrency and optimistic revisions;
- injectable clock and deterministic test IDs;
- state machines for asynchronous resources;
- transactional outbox for state changes and event publication;
- atomic snapshot writes and verified restore;
- indexes by ARN, name, tag, and relationship.

Incremental snapshots or a WAL should be implemented only after cross-service
snapshot semantics are specified.

### IAM

IAM is a gateway/kernel concern, not duplicated provider logic. Implement in
this order:

1. principal and authentication context;
2. wildcard actions/resources and explicit deny;
3. identity and resource policies;
4. session policies and permission boundaries;
5. `NotAction`, `NotResource`, `Principal`, and `NotPrincipal`;
6. condition operators and global context keys;
7. principal, request, and resource tags;
8. `iam:PassRole`;
9. KMS key policies and grants;
10. cross-account policies and Organizations SCPs.

### Cross-service delivery

The event envelope must include identity, trace, causation, attempt, scheduling,
and deduplication information. Required semantics include idempotency, retry with
backoff and jitter, DLQ, ordering where applicable, deadlines, cancellation,
trace propagation, and delivery metrics.

Priority integration paths:

- S3 to SQS, SNS, Lambda, and EventBridge;
- DynamoDB Streams and Kinesis to Lambda, Pipes, and Firehose;
- EventBridge and Scheduler to common targets;
- Pipes source to enrichment to target;
- CloudWatch alarms to SNS and Lambda;
- Lambda to Logs, X-Ray, destinations, and DLQ;
- Step Functions AWS SDK integrations;
- CloudFormation through public service APIs.

### CloudFormation and CloudControl

CloudFormation must use the public internal service APIs, never provider stores.
Each resource type must define create, read, update, delete, list,
stabilization, import, drift, tagging, replacement, and rollback behavior.

CloudControl becomes a facade over the same resource-provider registry. A
resource is not complete if an unimplemented update is reported as success.

## 8. Implementation roadmap

### Wave 0: foundation and measurable truth, months 0-3

- Complete and publish the fork governance and redistribution go/no-go record.
- Lock Botocore, Smithy, CloudFormation, and CDK catalogs.
- Classify all operations by origin and fidelity.
- Build an AWS-versus-local differential harness.
- Introduce capability manifests and documentation provenance.
- Version metrics ingestion and import dispatch evidence into a separate,
  content-addressed overlay bound to the capability catalog.
- Establish state, clock, jobs, event bus, and backpressure contracts.
- Implement foundational IAM and account/region isolation.
- Add performance instrumentation and baselines.
- Deliver two pilot journeys:
  - API Gateway to Lambda to Logs;
  - S3 to SQS to Lambda.

### Wave 1: usable serverless and CDK, months 3-6

- API Gateway v2 HTTP and WebSocket APIs.
- Lambda ZIP and container-image lifecycle.
- Minimum ECR required for image assets.
- Cognito basics for prioritized journeys.
- EventBridge common targets, Scheduler, and basic Pipes.
- IAM, persistence, CloudFormation, and CloudControl for every delivered slice.
- Modern CDK bootstrap, file assets, Docker assets, deploy, update, and destroy.
- Six to eight complete journeys without fallback.

### Wave 2: integrations and platform, months 6-12

- DynamoDB and Kinesis Streams event source mappings.
- Filtering, batching, partial failures, retries, destinations, and DLQ.
- Priority Step Functions integrations.
- CDK custom resources, transforms, and nested stacks.
- ECR to ECS to ALB to Cloud Map.
- RDS/Data API, ElastiCache, Secrets, and KMS integration.
- Kinesis to Firehose to S3.
- CodeBuild and initial CodePipeline journeys.
- CDK and Terraform apply/destroy gates.

Expected result with 10-14 engineers: 15-25 useful control planes and 8-12
services at L3/L4.

### Wave 3: broad surface, months 12-24

- Athena and Glue Catalog.
- MSK and EKS/k3s.
- WAF, CloudTrail, X-Ray, Organizations, and Verified Permissions.
- AppSync with Cognito, Lambda, and DynamoDB.
- Backup, replication, and IAM Policy Streams.
- Control planes for specialized databases, analytics, media, and ML.

Expected result with 10-14 engineers: 40-60 declared control planes and 15-25
services at L3/L4. Covering nearly the full Base/Ultimate catalog within 24-36
months would require scaling toward 18-25 engineers, while retaining explicit
limitations for data planes that cannot be reproduced faithfully.

## 9. CDK local support

The project must make the real CDK toolkit work against local endpoints; it
must not reimplement client-side CDK behavior.

Use a thin, language-neutral launcher rather than a fork of CDK. For current
toolkits, prefer the standard `cdk` binary with `AWS_ENDPOINT_URL` and the
S3-specific endpoint configured; retain a `cdklocal`-compatible wrapper only
as an adapter for version compatibility and safe defaults. The launcher must
fail closed if configuration could target real AWS, isolate credentials and
profiles, allowlist only intentional region variables, handle container and
host networking, and emit its resolved endpoint/region/account in CI evidence.
The emulator contract remains the AWS APIs, CloudFormation, and Cloud
Assembly—not the implementation language of the CDK application.

| Capability | Local responsibility and dependencies |
|---|---|
| `cdk synth` | No special API; synthesis remains client-side |
| Modern bootstrap | CloudFormation, S3, ECR, SSM, IAM, STS, optional KMS |
| File assets | S3 multipart, checksums, and presigned URLs |
| Docker assets | ECR authentication, layers, manifests, push, and pull |
| Context lookups | EC2/VPC/AZ, Route53, SSM, STS, and queried services |
| Deploy/update/no-op | Change sets, events, outputs, waiters, and rollback |
| Diff | Correct templates and change-set behavior |
| Destroy | Dependencies, retain, and deletion policies |
| Hotswap | Direct service updates with correct CloudFormation fallback |
| Custom resources | Lambda/SNS invocation, callback, timeout, and rollback |
| Transforms | SAM, Include, LanguageExtensions, and Lambda macros |
| Nested stacks | Parent/child lifecycle, S3 templates, outputs, and rollback |
| CloudControl | CRUD over the shared resource-provider registry |

CDK custom resources execute AWS-authored Lambda code that does not know about
local endpoints. They require transparent endpoint injection/DNS inside the
Lambda runtime, including TLS handling, and must be tested as an end-to-end
network path. The S3 endpoint used for assets must preserve an S3-recognizable
hostname as well as path- and virtual-host addressing. These are runtime
compatibility features, not wrapper-only fixes.

The existing scenario harness uses a `BootstraplessSynthesizer` and documents
that CDK-generated assets are unsupported in
[`localstack-core/localstack/testing/scenario/provisioning.py`](../localstack-core/localstack/testing/scenario/provisioning.py).
Current tests exercise bootstrap templates but do not prove compatibility with
the real CLI. Add black-box tests that invoke the actual `cdk` binary.

The first executable adapter lives in
[`localstack-core/localstack/cli/cdk.py`](../localstack-core/localstack/cli/cdk.py).
It provides a hard-deadline health preflight, rejects redirects/proxies and
public AWS endpoints, sanitizes credentials, verifies the stable CLI version,
inherits stdout/stderr for native streaming, bounds fallback capture memory,
preserves interactive stdin on terminals, and supervises a POSIX process
group. This is launcher evidence only: it does not
promote any language or scenario until the real CLI matrix below passes.

The first bootstrap-update blocker is now covered at provider level:
`AWS::IAM::Role` reconciles mutable trust, managed and inline policies,
permissions boundaries, description, session duration, and owned tags without
changing `RoleId` or deleting external children. Its unit gate models the
critical bootstrap v28-to-v32 `DeploymentActionRole` delta and proves the
eight-call provider budget: one identity snapshot, one collision-safety read,
three just-in-time identity checks, and three mutations. The local CloudFormation v2 gate now deploys the pinned
official v28 template and updates the same stack to the byte-exact pinned v32
template. It verifies all five role identities and ARNs, external managed
policy ownership, the v32 trust/inline/managed policy deltas, the SSM version,
and strict cleanup of the retained bucket. This promotes only the bootstrap
engine/API scenario to `api-simulated`; real CLI and fresh AWS differential
evidence remain required.

The first real-CLI gate is now defined as the language-neutral
`bootstrap --show-template` scenario with Node 22.23.2 and `aws-cdk` 2.1135.1
locked under `tests/aws/cli/`. It compares the emitted template semantically
with the byte-pinned official v32 template while bounding runtime and captured
output. `.github/workflows/cdk-cli-blackbox.yml` defines native Linux amd64 and
arm64 jobs whose pytest process runs without external network interfaces,
inherited credentials, supplementary groups, or Linux capabilities. The gate
remains diagnostic until both post-merge jobs produce attestable evidence; a
test definition alone does not set `real_cli_exercised`, remove a deployment
gap, or promote any language.

The workflow's evidence contract is deliberately two-phase. A first-attempt
push to `main` must produce content-addressed lane receipts and exactly one
aggregate for native Linux amd64 and arm64. The aggregate binds the source
commit, workflow inputs, toolchain, semantic and byte template hashes, bounded
output metadata, JUnit outcomes, and the declared isolation profile; it is
then attested through the workflow's GitHub OIDC identity. This candidate does
not update the compatibility manifest automatically. A separate reviewed
commit must preserve and verify the aggregate and attestation before it may
promote only the narrow `bootstrap-show-template-v32` subscenario. Bootstrap
deployment, language bindings, Cloud Assembly, and AWS parity remain separate
gates.

The first cycle completed in GitHub Actions run `31288954038` for commit
`1a23acd9b65fef0ef5a944bd4b412f9af9348665`. Both native lanes and the
first-attempt aggregate passed, and the aggregate was verified against the
repository, signer workflow, source commit, and `refs/heads/main` before its
JSON and Sigstore bundle were retained in `capabilities/cdk/evidence/`. The
manifest therefore records `bootstrap-show-template-v32` as a language-neutral
`cli-pass` scenario with Node 22.23.2 and CDK CLI 2.1135.1. This does not change
the broad bootstrap status or satisfy the deploy, Cloud Assembly, language, or
AWS differential gates.

The next diagnostic gate seeds the pinned repository bootstrap v28 fixture
through the LocalStack CloudFormation API and then invokes the same pinned real
CDK CLI with its built-in v32 template. It uses a unique toolkit stack and
qualifier, verifies the in-place stack and IAM role identities, preserves an
externally attached policy, checks the v32 trust/inline/managed-policy deltas,
and requires strict stack, bucket, role, and SSM cleanup. This runs as a second
JUnit result in the isolated amd64/arm64 matrix without changing the retained
`bootstrap-show-template-v32` receipt or attestation. Until the deployment
transition had its own content-addressed two-platform evidence and reviewed
promotion commit, `bootstrap-deployment-cli-not-run` remained an active gap.

Run `31290258541` for commit
`ccaa955d086e56dc04caa521bf1ffe047292a1c0` passed that diagnostic in native
amd64 and arm64, but emitted only JUnit for the upgrade and therefore is not a
promotable evidence run. The follow-up contract keeps the original
show-template aggregate unchanged and gives the upgrade its own bounded
observation, post-cleanup lane receipt, two-platform aggregate, schema,
attestation subject, and artifact namespace. The first subsequent
first-attempt `main` run to produce that complete chain was required to remain
a candidate until a separate reviewed promotion commit. Ingestion and
promotion must run
both the closed schema and the scenario runtime validator; schema-only parsing
is not an evidence gate for cross-field invariants. The actual CLI argv is
validated before the observation is emitted and stored as one normalized
command plus a closed derivation contract rather than duplicated dynamic data.

Run `31305122966` for commit
`c4a933343b6be315208edd68bb4827650275fcc6` produced the first durable upgrade
aggregate after both native lanes and strict cleanup passed. Its aggregate and
Sigstore bundle are retained under `capabilities/cdk/evidence/runs/31305122966/`
and promote only `bootstrap-upgrade-v28-v32` to scenario-level `cli-pass` for
Node 22.23.2 and CDK CLI 2.1135.1. The broad `bootstrap` capability remains
`api-simulated`, language-neutral, and stale with respect to AWS differential
validation. The remaining bootstrap gap is `clean-bootstrap-create-cli-not-run`;
Cloud Assembly, application deployment, assets, language bindings, and parity
remain unproven.

The next diagnostic is the first real language-binding boundary. It invokes
the pinned CLI against a fixed Python app using `aws-cdk-lib` 2.241.0,
`constructs` 10.5.1, and the default stack synthesizer with one L1
`AWS::SQS::Queue` and no user-authored file or Docker assets. The gate closes
the default stack-template asset manifest and requires a bounded,
regular-file-only Cloud Assembly, validates its emitted schema version, and
closes the template and construct-tree shape. It runs without lookups,
user-authored file or Docker assets, CloudFormation resource path metadata,
external egress, or deployment. Its JUnit is archived separately from both
retained bootstrap evidence streams. Until a later two-platform receipt, attestation,
and reviewed promotion exists, this remains diagnostic and does not promote
Python, `synth`, Cloud Assembly, SQS deployment, or any other language binding.

The current LocalStack documentation is useful as a compatibility baseline:
it describes `cdklocal` as a thin wrapper, the newer `lstk cdk` path for CDK
2.177.0 or later, endpoint environment injection, and paid-plan asset
deployment. It also warns that stack updates can leave inconsistent state.
This fork's acceptance suite must therefore prove update/no-op/rollback and
file/Docker assets instead of inheriting those documented limitations.

Version matrix:

- supported Node LTS versions;
- CDK CLI minimum, pinned, and latest;
- `aws-cdk-lib` minimum, pinned, and latest independently;
- current bootstrap and upgrade from the preceding version;
- full `init`, `synth`, deploy, update, and destroy suites for every stable
  language binding supported by AWS CDK: TypeScript, JavaScript, Python, Java,
  C#/.NET, and Go;
- automatic matrix expansion when AWS promotes another language binding to
  stable, without changing the emulator protocol;
- Linux amd64 and arm64.

The CLI and Cloud Assembly are the language-neutral compatibility boundary.
Language suites must prove that equivalent applications produce deployable
assemblies and identical observable AWS API behavior; a passing TypeScript
suite cannot be used as evidence for another binding. Community or
experimental bindings can run as advisory jobs until AWS declares them stable.

Gates cover `init`, `list`, `synth`, bootstrap, assets, deploy, no-op, update,
rollback, diff, destroy, retain, transforms, custom resources, nested stacks,
hotswap, and uncached context lookups.

References:

- [AWS CDK bootstrapping](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html)
- [AWS CDK deployment](https://docs.aws.amazon.com/cdk/v2/guide/deploy.html)
- [AWS CDK language prerequisites](https://docs.aws.amazon.com/cdk/v2/guide/prerequisites.html)
- [AWS CDK language binding stability](https://docs.aws.amazon.com/cdk/v2/guide/versioning.html)
- [Cloud Assembly Schema](https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.cloud_assembly_schema/README.html)
- [LocalStack CDK integration documentation](https://docs.localstack.cloud/aws/connecting/infrastructure-as-code/aws-cdk/)
- [LocalStack `lstk cdk` launcher documentation](https://docs.localstack.cloud/aws/developer-tools/running-localstack/lstk/#cdk)
- [LocalStack transparent endpoint injection](https://docs.localstack.cloud/aws/configuration/networking/transparent-endpoint-injection/)

Client-side construct trees, jsii, synthesis, asset hashing, Docker builds,
`cdk.context.json`, CLI prompts, and the watch loop do not need emulation, but
the thin launcher must preserve their normal input/output behavior.

The first metrics importer is intentionally informational. Legacy metric CSVs
do not contain the final pytest/JUnit outcome, distinguish subject calls from
setup, polling, and cleanup, or attest that a snapshot comparison succeeded.
The `aws_validated` column records marker presence only. Consequently, an
observed native dispatch can identify a candidate for deeper validation but
cannot promote an operation to `native` or `parity-pass`.

Promotion requires a versioned scenario manifest and a versioned metrics
contract containing run ID, target, test outcome, snapshot outcome, evidence
scope, scenario ID, selected provider, source commit, catalog digests, and a
stable request sequence. The promotion gate must pair the local result with
JUnit and fresh AWS evidence, reject reruns, xfail/xpass, skipped snapshot
paths, teardown failures, missing scenarios, and conflicting provider traces.

For CDK, create that manifest before adding the CLI dependency. Pin Node, the
CDK CLI, `aws-cdk-lib`, the Cloud Assembly schema, and the emitted bootstrap
template independently. The first black-box gate is real `synth` and
`bootstrap --show-template`; bootstrap create/no-op/destroy follows once
CloudFormation, S3, IAM, STS, and SSM evidence is eligible. File assets follow
those gates, while Docker assets remain blocked until ECR exists. Adding the
CDK CLI or another project dependency still requires explicit approval.

## 10. Documentation ingestion and freshness

"Analyze all documentation" must be a repeatable pipeline rather than a
one-time reading exercise.

1. Pin versions and hashes of Botocore, Smithy, CDK, bootstrap templates,
   CloudFormation specifications, and public documentation inputs.
2. Generate an index by service, operation, shape, resource type, construct,
   integration, and error.
3. Produce a semantic diff for every upstream release.
4. Open or update capability-manifest entries automatically.
5. Identify new operations, properties, endpoint rules, and resource types.
6. Revalidate affected behavior against AWS.
7. Treat skipped snapshots, ignored paths, and stale validations as debt.
8. Use a default AWS-validation freshness window of 90 days for active scope.
9. Never manually modify generated API files, snapshots, or validation files.

Generated tests establish protocol and shape coverage. Human-authored tests
establish behavior, lifecycle, IAM, integrations, and side effects.

## 11. Performance program

Performance only counts when semantic invariants continue to pass: ordering,
isolation, retries, idempotency, and absence of loss or corruption.

### Baseline environments

- `perf-pr`: 4 vCPU, 8 GiB, amd64, persistence off.
- `perf-nightly`: amd64 and arm64, 8 vCPU, 16 GiB, bind mount and tmpfs,
  persistence on and off.

Record the image digest, commit, Python, Botocore, Moto, Java, Docker, kernel,
filesystem, CPU/memory/PID/FD limits, gateway mode, worker counts, cache state,
and Lambda image state.

### Workloads

- Gateway protocols: JSON, Query, EC2, REST-JSON, REST-XML, and CBOR.
- Concurrency: 1, 8, 32, 128, overload, and recovery.
- Payloads: empty, 1 KiB, 1 MiB, and large streaming payloads.
- S3: object, range, checksum, multipart, same-key contention.
- SQS: standard/FIFO, batch, long polling, visibility, redelivery, and DLQ.
- DynamoDB: CRUD, conditional writes, transactions, scans, queries, and streams.
- Lambda: cold/warm, ZIP/image, sync/async, versions, and concurrency.
- Cross-service journeys from the implementation roadmap.

Measure p50, p95, p99, p99.9, throughput, CPU/request, allocations, RSS/PSS,
GC, threads, FDs, context switches, event-loop lag, queue wait, lock wait, disk,
network, snapshot pauses, cold-start stages, backlog, and recovery.

### Initial gates

- throughput at least 95% of the accepted baseline;
- p95 and p99 no worse than baseline plus 10%;
- CPU/request and allocation/request no worse than plus 10%;
- startup and first request no worse than plus 10%;
- nominal errors below 0.1%;
- no data loss or corruption;
- no monotonic thread or FD growth;
- final soak RSS no worse than plus 5% or plus 50 MiB;
- queues return to normal after overload.

The current code suggests hypotheses requiring measurement, including a large
gateway worker ceiling, potentially unbounded queues, broad locks in SQS and
stores, SQS message copying, S3 reader position locking, DynamoDB process/HTTP
overhead, linear Lambda environment lookup, a global cold-start semaphore, and
full in-memory persistence snapshots.

Optimization order:

```text
instrumentation
  -> reproducible baseline
  -> bounded queues and backpressure
  -> service-level contention
  -> incremental persistence
  -> experimental gateway/storage changes
```

## 12. Language decision

### Recommendation

Keep Python for providers, Botocore/Moto compatibility, plugins, lifecycle,
state orchestration, and most tests.

- Use Rust/PyO3 only for proven CPU-bound kernels such as codecs, parsing,
  serialization, shape validation, or compact indexes.
- Use Go through a process or Unix-domain-socket boundary for autonomous
  networking, registry, queue, event-bus, or storage components.
- Do not use Go FFI as the first integration strategy.
- Do not rewrite the entire emulator in Go, Rust, or Java.

### Required 4-6 week experiment

1. Profile representative S3, SQS, DynamoDB, Lambda, routing, and CBOR paths.
2. Select a hotspot responsible for at least 25% of end-to-end CPU.
3. Define a narrow immutable boundary and a golden compatibility corpus.
4. Compare optimized Python with Rust/PyO3, or a Go sidecar if the hotspot is
   naturally network/process-bound.
5. Run validated behavior, concurrency, soak, cancellation, crash, shutdown,
   amd64, and arm64 tests.
6. Produce reproducible wheels/binaries, SBOM, symbols, fallback, and a
   maintenance estimate.

Approve a native component only if it achieves all of the following:

- at least 30% less CPU/request;
- at least 25% better end-to-end throughput or p99;
- FFI/RPC conversion below 15% of total time;
- no more than 10% regression in RSS or startup;
- all relevant golden and validated tests pass;
- no error, header, ordering, isolation, or streaming divergence;
- reproducible amd64 and arm64 releases;
- working Python fallback and compatible provider/plugin APIs.

Stop the experiment if the gain is only visible in a microbenchmark, if the
real bottleneck is a lock/backend/disk, if large payloads require extra copies,
or if Botocore models must be duplicated across languages.

## 13. Definition of Done

An operation is complete only when:

- its generated contract matches the pinned catalog;
- dispatch origin is native, with no hidden fallback;
- validation and service-specific errors match AWS;
- positive and negative paths have AWS-first snapshots;
- IAM allow and deny behavior works;
- account and region state is isolated;
- pagination, tags, and idempotency work;
- lifecycle and eventual consistency are tested;
- downstream integrations confirm side effects;
- persistence, reset, restore, and migration pass;
- a CloudFormation resource provider exists when applicable;
- CloudControl and real CDK pass when applicable;
- no critical path is skipped or ignored;
- AWS validation is within the configured freshness window;
- latency, throughput, CPU, memory, queues, and correctness satisfy the SLO;
- every remaining deviation is declared in the capability manifest.

A service is complete only when every operation in its versioned scope passes
and its prioritized journeys pass through direct API, CloudFormation, and at
least one real IaC client.

The program may claim complete coverage of a frozen catalog only when it has no
undeclared `missing`, `fallback`, or `partial` entries. It must not equate HTTP
success, generated method presence, or control-plane CRUD with full AWS parity.

## 14. Team shape and capacity

Suggested initial allocation for 10-14 engineers:

- 2 platform, catalog, protocol, and code generation;
- 2 IAM and security;
- 2 conformance, AWS validation, CloudFormation, and CDK;
- 4-6 services and integrations;
- 1 performance/runtime;
- 1 release, dependencies, supply chain, and multi-architecture delivery.

After the first year, reserve 25-40% of capacity for upstream model updates,
AWS behavior changes, flaky validation, migrations, dependency CVEs, and
compatibility maintenance.

## 15. First implementation artifacts

Wave 0 should materialize these durable artifacts before broad feature work:

1. machine-readable AWS/CDK capability matrix;
2. clean-room provenance policy and source registry;
3. architecture decision records for the kernel, IAM, state, events, and
   provider boundaries;
4. AWS differential conformance harness;
5. reproducible performance harness and accepted baseline;
6. CDK CLI compatibility matrix;
7. pilot specifications for API Gateway to Lambda to Logs and S3 to SQS to
   Lambda.
