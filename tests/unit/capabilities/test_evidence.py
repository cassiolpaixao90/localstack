import csv
import hashlib
import json
from pathlib import Path

import pytest

from localstack.capabilities.evidence import (
    EvidenceError,
    EvidenceLimits,
    classify_dispatch_trace,
    main,
    render_evidence,
)
from localstack.capabilities.evidence import (
    build_evidence_bundle as _build_evidence_bundle,
)


def _sha256(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _catalog():
    catalog = {
        "schema_version": 1,
        "model_catalog_sha256": "sha256:" + "1" * 64,
        "source": {
            "type": "botocore-service-model",
            "version": "test",
            "license": "Apache-2.0",
            "uri": "https://example.invalid/botocore",
        },
        "classification": {
            "method": "conservative-static-analysis",
            "native_and_parity_require_runtime_evidence": True,
            "statuses": [
                "missing",
                "scaffold",
                "fallback",
                "partial",
                "native",
                "parity-pass",
            ],
        },
        "summary": {
            "services": 1,
            "operations": 1,
            "generated_interfaces": 0,
            "services_with_providers": 0,
            "cloudformation_resources": 0,
            "by_status": {
                "missing": 0,
                "scaffold": 0,
                "fallback": 0,
                "partial": 1,
                "native": 0,
                "parity-pass": 0,
            },
        },
        "cloudformation": {"resources": []},
        "services": {
            "sample": {
                "api_version": "2026-08-08",
                "protocol": "json",
                "model_sha256": "sha256:" + "2" * 64,
                "generated_interface": None,
                "providers": [],
                "default_provider": None,
                "cloudformation_resources": [],
                "operation_statuses": {
                    "missing": [],
                    "scaffold": [],
                    "fallback": [],
                    "partial": ["DoThing"],
                    "native": [],
                    "parity-pass": [],
                },
                "implementations": {
                    "DoThing": {
                        "origin": "native-candidate",
                        "reasons": ["test-fixture"],
                        "validation": {"status": "unverified", "evidence": []},
                        "performance": {"profiles": []},
                    }
                },
            }
        },
    }
    catalog["inventory_sha256"] = _sha256(catalog)
    return catalog


def build_evidence_bundle(catalog, metric_inputs, **kwargs):
    return _build_evidence_bundle(
        catalog,
        metric_inputs,
        expected_inventory_sha256=catalog["inventory_sha256"],
        **kwargs,
    )


def _trace(origin="native", outcome="returned"):
    return [{"origin": origin, "handler": "provider.do_thing", "outcome": outcome}]


def _row(**overrides):
    row = {
        "service": "sample",
        "operation": "DoThing",
        "test_node_id": "tests/test_sample.py::test_do_thing",
        "xfail": "False",
        "aws_validated": "True",
        "snapshot": "True",
        "snapshot_skipped_paths": "",
        "dispatch_trace": json.dumps(_trace(), separators=(",", ":")),
    }
    row.update(overrides)
    return row


def _write_metrics(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(_row()))
        writer.writeheader()
        writer.writerows(rows)


@pytest.mark.parametrize(
    ("trace", "expected"),
    [
        (_trace(), "native-observed"),
        (_trace("native", "service-exception"), "native-observed"),
        (_trace("delegated:moto"), "fallback-observed"),
        (_trace("generated-mock"), "mock-observed"),
        (_trace("none", "missing"), "missing-observed"),
        (_trace("native", "error"), "error-observed"),
        (_trace("generated-stub", "not-implemented"), "unsupported-observed"),
        (_trace("plugin:custom"), "unknown-observed"),
        ([], "invalid-observed"),
    ],
)
def test_classifies_dispatch_trace_conservatively(trace, expected):
    assert classify_dispatch_trace(trace) == expected


def test_builds_deterministic_informational_bundle(tmp_path: Path):
    first = tmp_path / "a.csv"
    second = tmp_path / "b.csv"
    _write_metrics(first, [_row()])
    _write_metrics(second, [_row(dispatch_trace=json.dumps(_trace("delegated:moto")))])

    forward = build_evidence_bundle(
        _catalog(),
        [first, second],
        observed_at="2026-08-08T18:00:00Z",
        source_commit="a" * 40,
    )
    reverse = build_evidence_bundle(
        _catalog(),
        [second, first],
        observed_at="2026-08-08T18:00:00Z",
        source_commit="a" * 40,
    )

    assert render_evidence(forward) == render_evidence(reverse)
    assert forward["mode"] == "informational"
    assert forward["summary"] == {
        "by_trace_class": {"fallback-observed": 1, "native-observed": 1},
        "invalid_rows": 0,
        "operations_observed": 1,
        "rows_seen": 2,
        "valid_rows": 2,
    }
    operation = forward["operations"][0]
    assert operation["promotion"]["eligible"] is False
    assert operation["trace_classes"] == ["fallback-observed", "native-observed"]


def test_semantic_digest_ignores_duplicate_rows(tmp_path: Path):
    single = tmp_path / "single.csv"
    duplicate = tmp_path / "duplicate.csv"
    _write_metrics(single, [_row()])
    _write_metrics(duplicate, [_row(), _row()])

    one = build_evidence_bundle(
        _catalog(), [single], observed_at="2026-08-08T18:00:00Z", source_commit="b" * 40
    )
    two = build_evidence_bundle(
        _catalog(),
        [duplicate],
        observed_at="2026-08-08T18:00:00Z",
        source_commit="b" * 40,
    )

    assert one["semantic_sha256"] == two["semantic_sha256"]
    assert one["evidence_id"] != two["evidence_id"]


def test_rejects_malformed_trace_in_strict_mode(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row(dispatch_trace="not-json")])

    with pytest.raises(EvidenceError, match="metrics.csv:2: invalid dispatch_trace JSON"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="c" * 40,
        )


def test_allow_invalid_records_bounded_diagnostics(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row(dispatch_trace="not-json") for _ in range(20)])

    bundle = build_evidence_bundle(
        _catalog(),
        [metrics],
        observed_at="2026-08-08T18:00:00Z",
        source_commit="d" * 40,
        allow_invalid=True,
    )

    assert bundle["summary"]["invalid_rows"] == 20
    assert len(bundle["invalid_samples"]) == EvidenceLimits().max_invalid_samples


def test_rejects_unknown_catalog_operation(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row(operation="Unknown")])

    with pytest.raises(EvidenceError, match="operation is not in the capability catalog"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="e" * 40,
        )


def test_rejects_catalog_content_that_does_not_match_inventory_digest(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row()])
    catalog = _catalog()
    catalog["services"]["sample"]["operation_statuses"]["partial"].append("Tampered")

    with pytest.raises(EvidenceError, match="inventory digest does not match its content"):
        build_evidence_bundle(
            catalog,
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="5" * 40,
        )


def test_rejects_catalog_that_does_not_match_external_inventory_anchor(tmp_path: Path, monkeypatch):
    from localstack.capabilities import evidence as evidence_module

    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row()])
    catalog = _catalog()
    expected_inventory_sha256 = catalog["inventory_sha256"]
    implementation = catalog["services"]["sample"]["implementations"].pop("DoThing")
    catalog["services"]["sample"]["implementations"]["Invented"] = implementation
    catalog["services"]["sample"]["operation_statuses"]["partial"] = ["Invented"]
    catalog["inventory_sha256"] = _sha256(
        {key: value for key, value in catalog.items() if key != "inventory_sha256"}
    )
    monkeypatch.setattr(
        evidence_module,
        "_catalog_validator",
        lambda: pytest.fail("schema validation must not run before the trusted anchor matches"),
    )

    with pytest.raises(EvidenceError, match="does not match the expected inventory digest"):
        _build_evidence_bundle(
            catalog,
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="5" * 40,
            expected_inventory_sha256=expected_inventory_sha256,
        )


def test_rejects_catalog_that_violates_closed_schema(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row()])
    catalog = _catalog()
    catalog["unexpected"] = True
    catalog["inventory_sha256"] = _sha256(
        {key: value for key, value in catalog.items() if key != "inventory_sha256"}
    )

    with pytest.raises(EvidenceError, match="does not match the closed schema") as error:
        _build_evidence_bundle(
            catalog,
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="5" * 40,
            expected_inventory_sha256=catalog["inventory_sha256"],
        )
    assert len(str(error.value)) < 100


def test_rejects_trace_over_limit(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    trace = _trace() * (EvidenceLimits().max_trace_entries + 1)
    _write_metrics(metrics, [_row(dispatch_trace=json.dumps(trace))])

    with pytest.raises(EvidenceError, match="dispatch_trace has too many entries"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="f" * 40,
        )


def test_ingestion_does_not_use_path_read_text(tmp_path: Path, monkeypatch):
    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row() for _ in range(1000)])
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: pytest.fail("not streaming"))

    bundle = build_evidence_bundle(
        _catalog(),
        [metrics],
        observed_at="2026-08-08T18:00:00Z",
        source_commit="1" * 40,
    )

    assert bundle["summary"]["rows_seen"] == 1000
    assert len(bundle["operations"][0]["samples"]) == 1


def test_hashes_metrics_during_the_single_parse_open(tmp_path: Path, monkeypatch):
    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row()])
    expected_digest = f"sha256:{hashlib.sha256(metrics.read_bytes()).hexdigest()}"
    real_open = Path.open
    metric_opens = 0

    def counted_open(path, *args, **kwargs):
        nonlocal metric_opens
        if path == metrics:
            metric_opens += 1
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counted_open)
    bundle = build_evidence_bundle(
        _catalog(),
        [metrics],
        observed_at="2026-08-08T18:00:00Z",
        source_commit="6" * 40,
    )

    assert metric_opens == 1
    assert bundle["inputs"][0]["sha256"] == expected_digest


def test_bundle_matches_committed_schema(tmp_path: Path):
    from jsonschema.validators import validator_for

    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row()])
    bundle = build_evidence_bundle(
        _catalog(),
        [metrics],
        observed_at="2026-08-08T18:00:00Z",
        source_commit="2" * 40,
    )
    project_root = Path(__file__).parents[3]
    schema = json.loads((project_root / "capabilities/evidence.schema.json").read_text())
    validator = validator_for(schema)

    validator.check_schema(schema)
    validator(schema, format_checker=validator.FORMAT_CHECKER).validate(bundle)


def test_cli_writes_overlay_atomically(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    catalog = tmp_path / "catalog.json"
    output = tmp_path / "nested" / "evidence.json"
    _write_metrics(metrics, [_row()])
    catalog.write_text(json.dumps(_catalog()))

    exit_code = main(
        [
            "--catalog",
            str(catalog),
            "--metrics",
            str(metrics),
            "--observed-at",
            "2026-08-08T18:00:00Z",
            "--source-commit",
            "3" * 40,
            "--expected-inventory-sha256",
            _catalog()["inventory_sha256"],
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert json.loads(output.read_text())["mode"] == "informational"
    assert not list(output.parent.glob(f".{output.name}.*.tmp"))


def test_cli_preserves_previous_output_when_atomic_replace_fails(tmp_path: Path, monkeypatch):
    from localstack.capabilities import evidence as evidence_module

    metrics = tmp_path / "metrics.csv"
    catalog = tmp_path / "catalog.json"
    output = tmp_path / "evidence.json"
    _write_metrics(metrics, [_row()])
    catalog.write_text(json.dumps(_catalog()))
    output.write_text("previous\n")
    monkeypatch.setattr(
        evidence_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("replace failed")),
    )

    exit_code = main(
        [
            "--catalog",
            str(catalog),
            "--metrics",
            str(metrics),
            "--observed-at",
            "2026-08-08T18:00:00Z",
            "--source-commit",
            "7" * 40,
            "--expected-inventory-sha256",
            _catalog()["inventory_sha256"],
            "--output",
            str(output),
        ]
    )

    assert exit_code == 1
    assert output.read_text() == "previous\n"
    assert not list(tmp_path.glob(f".{output.name}.*.tmp"))


def test_rejects_legacy_header_without_dispatch_trace(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    row = _row()
    row.pop("dispatch_trace")
    with metrics.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)

    with pytest.raises(EvidenceError, match="missing metric fields: dispatch_trace"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="4" * 40,
        )


def test_limits_can_only_tighten_the_schema_contract():
    with pytest.raises(ValueError, match="max_trace_entries must be between 1 and 32"):
        EvidenceLimits(max_trace_entries=33)


def test_rejects_more_metric_files_than_the_configured_limit(tmp_path: Path):
    for index in range(3):
        _write_metrics(tmp_path / f"metric-report-raw-data-{index}.csv", [_row()])

    with pytest.raises(EvidenceError, match="metric inputs exceed the 2 file limit"):
        build_evidence_bundle(
            _catalog(),
            [tmp_path],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="8" * 40,
            limits=EvidenceLimits(max_input_files=2),
        )


def test_rejects_more_columns_than_the_configured_limit(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    row = _row(extra="value")
    with metrics.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)

    with pytest.raises(EvidenceError, match="metric header exceeds the 8 column limit"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="9" * 40,
            limits=EvidenceLimits(max_columns=8),
        )


def test_rejects_oversized_snapshot_skip_field(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row(snapshot_skipped_paths="12345")])

    with pytest.raises(EvidenceError, match="snapshot_skipped_paths exceeds the size limit"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="0" * 40,
            limits=EvidenceLimits(max_snapshot_skip_chars=4),
        )


def test_header_and_record_byte_limits_accept_boundary_and_reject_overflow(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    _write_metrics(metrics, [_row()])
    header, record = metrics.read_bytes().splitlines(keepends=True)

    bundle = build_evidence_bundle(
        _catalog(),
        [metrics],
        observed_at="2026-08-08T18:00:00Z",
        source_commit="a" * 40,
        limits=EvidenceLimits(
            max_header_bytes=len(header),
            max_record_bytes=len(record),
        ),
    )
    assert bundle["summary"]["valid_rows"] == 1

    with pytest.raises(EvidenceError, match="metric header exceeds the byte limit"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="0" * 40,
            limits=EvidenceLimits(max_header_bytes=len(header) - 1),
        )

    with pytest.raises(EvidenceError, match="metric record exceeds the byte limit"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="b" * 40,
            limits=EvidenceLimits(max_record_bytes=len(record) - 1),
        )


def test_rejects_input_file_and_total_byte_overflow(tmp_path: Path):
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    _write_metrics(first, [_row()])
    _write_metrics(second, [_row(dispatch_trace=json.dumps(_trace("delegated:moto")))])

    with pytest.raises(EvidenceError, match="input file exceeds the byte limit"):
        build_evidence_bundle(
            _catalog(),
            [first],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="c" * 40,
            limits=EvidenceLimits(max_input_file_bytes=first.stat().st_size - 1),
        )

    with pytest.raises(EvidenceError, match="metric inputs exceed the total byte limit"):
        build_evidence_bundle(
            _catalog(),
            [first, second],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="d" * 40,
            limits=EvidenceLimits(
                max_total_input_bytes=first.stat().st_size + second.stat().st_size - 1
            ),
        )


def test_rejects_field_and_decoded_row_overflow(tmp_path: Path):
    metrics = tmp_path / "metrics.csv"
    row = _row(snapshot_skipped_paths="x" * 100)
    _write_metrics(metrics, [row])

    with pytest.raises(EvidenceError, match="snapshot_skipped_paths exceeds the field size limit"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="e" * 40,
            limits=EvidenceLimits(max_field_chars=99),
        )

    row_chars = sum(len(field_name) + len(value) for field_name, value in row.items())
    with pytest.raises(EvidenceError, match="metric row exceeds the size limit"):
        build_evidence_bundle(
            _catalog(),
            [metrics],
            observed_at="2026-08-08T18:00:00Z",
            source_commit="f" * 40,
            limits=EvidenceLimits(max_row_chars=row_chars - 1),
        )
