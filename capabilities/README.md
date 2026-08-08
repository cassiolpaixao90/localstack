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
- `report.md`: human-readable summary derived from the JSON inventory.

Do not edit generated files manually. Static analysis never promotes an operation
to `native` or `parity-pass`; those states require runtime dispatch evidence and
fresh differential validation against AWS.

Metrics mode now appends request dispatch origins to the local raw CSV. The
existing Tinybird `tests_raw__v0` uploader does not ingest that new column; a
versioned remote schema and evidence importer are explicit Wave 0 follow-up.

The static provider inventory covers the providers declared by this checkout.
Static classifications use the provider registered as `default`; the JSON also
lists selectable alternatives without claiming they are active. External plugins
and runtime-selected alternatives must be added later through runtime evidence
rather than inferred as part of this deterministic baseline.
