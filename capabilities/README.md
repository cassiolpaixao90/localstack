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

The static provider inventory covers the providers declared by this checkout.
Static classifications use the provider registered as `default`; the JSON also
lists selectable alternatives without claiming they are active. External plugins
and runtime-selected alternatives must be added later through runtime evidence
rather than inferred as part of this deterministic baseline.
