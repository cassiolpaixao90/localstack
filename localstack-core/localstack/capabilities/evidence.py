from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

EVIDENCE_SCHEMA_VERSION = 1
TRACE_CLASSES = (
    "native-observed",
    "fallback-observed",
    "mock-observed",
    "missing-observed",
    "error-observed",
    "unsupported-observed",
    "unknown-observed",
    "invalid-observed",
)
REQUIRED_METRIC_FIELDS = frozenset(
    {
        "service",
        "operation",
        "test_node_id",
        "xfail",
        "aws_validated",
        "snapshot",
        "snapshot_skipped_paths",
        "dispatch_trace",
    }
)
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class EvidenceLimits:
    max_input_files: int = 256
    max_input_file_bytes: int = 512 * 1024 * 1024
    max_total_input_bytes: int = 2 * 1024 * 1024 * 1024
    max_columns: int = 64
    max_header_bytes: int = 16 * 1024
    max_header_chars: int = 16 * 1024
    max_field_chars: int = 128 * 1024
    max_record_bytes: int = 1024 * 1024
    max_row_chars: int = 1024 * 1024
    max_snapshot_skip_chars: int = 16 * 1024
    max_trace_json_chars: int = 16 * 1024
    max_trace_entries: int = 32
    max_handler_chars: int = 512
    max_token_chars: int = 64
    max_test_node_chars: int = 2 * 1024
    max_samples_per_operation: int = 8
    max_distinct_tokens_per_operation: int = 32
    max_invalid_samples: int = 8

    def __post_init__(self) -> None:
        ceilings = {
            "max_input_files": 256,
            "max_input_file_bytes": 512 * 1024 * 1024,
            "max_total_input_bytes": 2 * 1024 * 1024 * 1024,
            "max_columns": 64,
            "max_header_bytes": 16 * 1024,
            "max_header_chars": 16 * 1024,
            "max_field_chars": 128 * 1024,
            "max_record_bytes": 1024 * 1024,
            "max_row_chars": 1024 * 1024,
            "max_snapshot_skip_chars": 16 * 1024,
            "max_trace_json_chars": 16 * 1024,
            "max_trace_entries": 32,
            "max_handler_chars": 512,
            "max_token_chars": 64,
            "max_test_node_chars": 2 * 1024,
            "max_samples_per_operation": 8,
            "max_distinct_tokens_per_operation": 32,
            "max_invalid_samples": 8,
        }
        for field_name, ceiling in ceilings.items():
            value = getattr(self, field_name)
            if not 0 < value <= ceiling:
                raise ValueError(f"{field_name} must be between 1 and {ceiling}")


@dataclass
class _OperationState:
    service: str
    operation: str
    observations: int = 0
    trace_class_counts: Counter[str] = field(default_factory=Counter)
    origins: set[str] = field(default_factory=set)
    outcomes: set[str] = field(default_factory=set)
    samples: set[tuple[str, str]] = field(default_factory=set)
    max_trace_depth: int = 0
    aws_validated_observed: bool = False
    snapshot_observed: bool = False
    snapshot_skip_observed: bool = False
    xfail_observed: bool = False


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(value).encode()).hexdigest()}"


def _add_bounded(values: set[Any], value: Any, maximum: int) -> None:
    values.add(value)
    if len(values) > maximum:
        values.remove(max(values))


def classify_dispatch_trace(trace: Sequence[Mapping[str, str]]) -> str:
    """Classify an observed trace without making a capability promotion claim."""

    if not trace:
        return "invalid-observed"

    origins = {entry.get("origin", "") for entry in trace}
    outcomes = {entry.get("outcome", "") for entry in trace}
    if outcomes.intersection({"error", "started"}):
        return "error-observed"
    if "none" in origins or "missing" in outcomes:
        return "missing-observed"
    if any(origin.startswith("delegated:") for origin in origins):
        return "fallback-observed"
    if "generated-mock" in origins:
        return "mock-observed"
    if "generated-stub" in origins or "not-implemented" in outcomes:
        return "unsupported-observed"
    if origins == {"native"} and outcomes.issubset({"returned", "service-exception"}):
        return "native-observed"
    return "unknown-observed"


def _parse_bool(value: str, field_name: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise EvidenceError(f"{field_name} must be True or False")


def _row_text(row: Mapping[str, Any], field_name: str) -> str:
    value = row.get(field_name)
    if not isinstance(value, str):
        raise EvidenceError(f"{field_name} must be a string")
    return value


def _parse_trace(raw: str, limits: EvidenceLimits) -> list[dict[str, str]]:
    if len(raw) > limits.max_trace_json_chars:
        raise EvidenceError("dispatch_trace exceeds the size limit")
    try:
        trace = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EvidenceError("invalid dispatch_trace JSON") from error
    if not isinstance(trace, list):
        raise EvidenceError("dispatch_trace must be a JSON array")
    if len(trace) > limits.max_trace_entries:
        raise EvidenceError("dispatch_trace has too many entries")

    result: list[dict[str, str]] = []
    for entry in trace:
        if not isinstance(entry, dict) or set(entry) != {"origin", "handler", "outcome"}:
            raise EvidenceError("dispatch_trace entry must contain origin, handler, and outcome")
        origin = entry["origin"]
        handler = entry["handler"]
        outcome = entry["outcome"]
        if not all(isinstance(value, str) for value in (origin, handler, outcome)):
            raise EvidenceError("dispatch_trace entry values must be strings")
        if len(origin) > limits.max_token_chars or len(outcome) > limits.max_token_chars:
            raise EvidenceError("dispatch_trace origin or outcome exceeds the size limit")
        if len(handler) > limits.max_handler_chars:
            raise EvidenceError("dispatch_trace handler exceeds the size limit")
        result.append({"origin": origin, "handler": handler, "outcome": outcome})
    return result


def _catalog_operations(catalog: Mapping[str, Any]) -> set[tuple[str, str]]:
    if not isinstance(catalog, Mapping):
        raise EvidenceError("catalog must be a JSON object")
    if catalog.get("schema_version") != 1:
        raise EvidenceError("unsupported capability catalog schema version")
    for key in ("model_catalog_sha256", "inventory_sha256"):
        if not _SHA256_PATTERN.fullmatch(str(catalog.get(key, ""))):
            raise EvidenceError(f"catalog has an invalid {key}")
    inventory_payload = dict(catalog)
    inventory_sha256 = inventory_payload.pop("inventory_sha256")
    if inventory_sha256 != _sha256(inventory_payload):
        raise EvidenceError("capability catalog inventory digest does not match its content")

    result: set[tuple[str, str]] = set()
    services = catalog.get("services", {})
    if not isinstance(services, Mapping):
        raise EvidenceError("catalog services must be an object")
    for service_name, service in services.items():
        if not isinstance(service, Mapping):
            raise EvidenceError(f"invalid catalog service: {service_name}")
        status_groups = service.get("operation_statuses", {})
        if not isinstance(status_groups, Mapping):
            raise EvidenceError(f"invalid operation statuses for {service_name}")
        for operations in status_groups.values():
            if not isinstance(operations, list) or not all(
                isinstance(operation, str) for operation in operations
            ):
                raise EvidenceError(f"invalid operation list for {service_name}")
            result.update((str(service_name), operation) for operation in operations)
    if not result:
        raise EvidenceError("catalog contains no operations")
    return result


def _normalize_observed_at(value: str) -> str:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise EvidenceError("observed_at must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise EvidenceError("observed_at must include a timezone")
    return parsed.isoformat().replace("+00:00", "Z")


def _discover_metric_paths(inputs: Iterable[str | Path], limits: EvidenceLimits) -> list[Path]:
    discovered: list[Path] = []
    seen: set[Path] = set()

    def add(candidate: Path) -> None:
        if not candidate.is_file():
            raise EvidenceError(f"metric input does not exist: {candidate}")
        resolved = candidate.resolve()
        if resolved in seen:
            raise EvidenceError(f"duplicate metric input: {resolved.name}")
        if len(discovered) >= limits.max_input_files:
            raise EvidenceError(f"metric inputs exceed the {limits.max_input_files} file limit")
        seen.add(resolved)
        discovered.append(resolved)

    for raw_path in inputs:
        path = Path(raw_path).resolve()
        if path.is_dir():
            found = False
            for candidate in path.rglob("metric-report-raw-data-*.csv"):
                found = True
                add(candidate)
            if not found:
                raise EvidenceError(f"no metric CSV files found in: {path}")
        else:
            add(path)
    if not discovered:
        raise EvidenceError("no metric CSV files found")
    return sorted(discovered, key=lambda item: item.as_posix())


def _input_descriptors(paths: Sequence[Path]) -> list[dict[str, Any]]:
    descriptors: list[dict[str, Any]] = []
    names: set[str] = set()
    for path in paths:
        name = path.name
        if name in names:
            raise EvidenceError(f"duplicate metric input name: {name}")
        names.add(name)
        descriptors.append(
            {
                "csv_schema": "legacy-v1-informational",
                "invalid_rows": 0,
                "name": name,
                "rows_seen": 0,
                "sha256": None,
                "valid_rows": 0,
            }
        )
    return sorted(descriptors, key=lambda item: item["name"])


def _validate_header(fieldnames: Sequence[str | None], limits: EvidenceLimits) -> None:
    if len(fieldnames) > limits.max_columns:
        raise EvidenceError(f"metric header exceeds the {limits.max_columns} column limit")
    if any(not isinstance(field, str) or not field for field in fieldnames):
        raise EvidenceError("metric header contains an empty column name")
    if len(set(fieldnames)) != len(fieldnames):
        raise EvidenceError("metric header contains duplicate columns")
    if sum(len(field) for field in fieldnames if field is not None) > limits.max_header_chars:
        raise EvidenceError("metric header exceeds the size limit")


def _validate_row_limits(row: Mapping[str | None, Any], limits: EvidenceLimits) -> None:
    if None in row:
        raise EvidenceError("metric row contains more values than the header")
    row_chars = 0
    for field_name, value in row.items():
        if not isinstance(field_name, str) or not isinstance(value, str):
            raise EvidenceError("metric row fields must be strings")
        if len(value) > limits.max_field_chars:
            raise EvidenceError(f"{field_name} exceeds the field size limit")
        row_chars += len(field_name) + len(value)
    if row_chars > limits.max_row_chars:
        raise EvidenceError("metric row exceeds the size limit")


def _operation_payload(state: _OperationState) -> dict[str, Any]:
    return {
        "aws_validated_marker_observed": state.aws_validated_observed,
        "max_trace_depth": state.max_trace_depth,
        "observations": state.observations,
        "operation": state.operation,
        "origins": sorted(state.origins),
        "outcomes": sorted(state.outcomes),
        "promotion": {
            "eligible": False,
            "reason": "legacy metrics lack attested test outcome, evidence scope, and scenario manifest",
        },
        "samples": [
            {"test_node_id": test_node_id, "trace_sha256": trace_sha256}
            for trace_sha256, test_node_id in sorted(state.samples)
        ],
        "service": state.service,
        "snapshot_marker_observed": state.snapshot_observed,
        "snapshot_skip_observed": state.snapshot_skip_observed,
        "trace_class_counts": dict(sorted(state.trace_class_counts.items())),
        "trace_classes": sorted(state.trace_class_counts),
        "xfail_marker_observed": state.xfail_observed,
    }


def _semantic_payload(base: Mapping[str, str], operations: Sequence[Mapping[str, Any]]) -> dict:
    return {
        "base": dict(base),
        "mode": "informational",
        "operations": [
            {
                "aws_validated_marker_observed": operation["aws_validated_marker_observed"],
                "max_trace_depth": operation["max_trace_depth"],
                "operation": operation["operation"],
                "origins": operation["origins"],
                "outcomes": operation["outcomes"],
                "samples": operation["samples"],
                "service": operation["service"],
                "snapshot_marker_observed": operation["snapshot_marker_observed"],
                "snapshot_skip_observed": operation["snapshot_skip_observed"],
                "trace_classes": operation["trace_classes"],
                "xfail_marker_observed": operation["xfail_marker_observed"],
            }
            for operation in operations
        ],
    }


def build_evidence_bundle(
    catalog: Mapping[str, Any],
    metric_inputs: Iterable[str | Path],
    *,
    observed_at: str,
    source_commit: str,
    allow_invalid: bool = False,
    limits: EvidenceLimits | None = None,
) -> dict[str, Any]:
    """Stream legacy metric CSVs into a deterministic, informational evidence overlay."""

    limits = limits or EvidenceLimits()
    if not _COMMIT_PATTERN.fullmatch(source_commit):
        raise EvidenceError("source_commit must be a full lowercase Git SHA")
    normalized_observed_at = _normalize_observed_at(observed_at)
    known_operations = _catalog_operations(catalog)
    paths = _discover_metric_paths(metric_inputs, limits)
    inputs = _input_descriptors(paths)
    descriptor_by_name = {descriptor["name"]: descriptor for descriptor in inputs}
    operations: dict[tuple[str, str], _OperationState] = {}
    invalid_samples: set[tuple[str, int, str]] = set()
    trace_class_counts: Counter[str] = Counter()
    input_digests: set[str] = set()
    total_input_bytes = 0

    def reject(path: Path, line: int, message: str) -> None:
        descriptor_by_name[path.name]["invalid_rows"] += 1
        _add_bounded(
            invalid_samples,
            (path.name, line, message),
            limits.max_invalid_samples,
        )
        if not allow_invalid:
            raise EvidenceError(f"{path.name}:{line}: {message}")

    for path in paths:
        descriptor = descriptor_by_name[path.name]
        input_digest = hashlib.sha256()
        input_bytes = 0
        record_bytes_remaining = limits.max_header_bytes
        record_kind = "header"

        def decoded_lines() -> Iterable[str]:
            nonlocal input_bytes, record_bytes_remaining, total_input_bytes
            while True:
                read_limit = (
                    min(
                        record_bytes_remaining,
                        limits.max_input_file_bytes - input_bytes,
                        limits.max_total_input_bytes - total_input_bytes,
                    )
                    + 1
                )
                raw_line = stream.readline(max(1, read_limit))
                if not raw_line:
                    return
                input_bytes += len(raw_line)
                total_input_bytes += len(raw_line)
                record_bytes_remaining -= len(raw_line)
                if input_bytes > limits.max_input_file_bytes:
                    raise EvidenceError(f"{path.name}: input file exceeds the byte limit")
                if total_input_bytes > limits.max_total_input_bytes:
                    raise EvidenceError("metric inputs exceed the total byte limit")
                if record_bytes_remaining < 0:
                    raise EvidenceError(f"{path.name}: metric {record_kind} exceeds the byte limit")
                input_digest.update(raw_line)
                try:
                    yield raw_line.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise EvidenceError(f"{path.name}: metric input is not UTF-8") from error

        try:
            with path.open("rb") as stream:
                reader = csv.reader(decoded_lines())
                try:
                    fieldnames = next(reader)
                except StopIteration as error:
                    raise EvidenceError(f"{path.name}: metric input is empty") from error
                _validate_header(fieldnames, limits)
                missing_fields = REQUIRED_METRIC_FIELDS - set(fieldnames)
                if missing_fields:
                    raise EvidenceError(
                        f"{path.name}: missing metric fields: {', '.join(sorted(missing_fields))}"
                    )
                record_kind = "record"
                while True:
                    record_bytes_remaining = limits.max_record_bytes
                    try:
                        values = next(reader)
                    except StopIteration:
                        break
                    descriptor["rows_seen"] += 1
                    line = reader.line_num
                    if len(values) != len(fieldnames):
                        reject(path, line, "metric row does not match the header")
                        continue
                    row = dict(zip(fieldnames, values, strict=True))
                    try:
                        _validate_row_limits(row, limits)
                        service = _row_text(row, "service").strip()
                        operation = _row_text(row, "operation").strip()
                        test_node_id = _row_text(row, "test_node_id").strip()
                        if (service, operation) not in known_operations:
                            raise EvidenceError("operation is not in the capability catalog")
                        if not test_node_id:
                            raise EvidenceError("test_node_id is required")
                        if len(test_node_id) > limits.max_test_node_chars:
                            raise EvidenceError("test_node_id exceeds the size limit")
                        xfail = _parse_bool(_row_text(row, "xfail"), "xfail")
                        aws_validated = _parse_bool(
                            _row_text(row, "aws_validated"), "aws_validated"
                        )
                        snapshot = _parse_bool(_row_text(row, "snapshot"), "snapshot")
                        snapshot_skipped_paths = _row_text(row, "snapshot_skipped_paths").strip()
                        if len(snapshot_skipped_paths) > limits.max_snapshot_skip_chars:
                            raise EvidenceError("snapshot_skipped_paths exceeds the size limit")
                        trace = _parse_trace(_row_text(row, "dispatch_trace"), limits)
                    except EvidenceError as error:
                        reject(path, line, str(error))
                        continue

                    trace_class = classify_dispatch_trace(trace)
                    state = operations.setdefault(
                        (service, operation), _OperationState(service, operation)
                    )
                    state.observations += 1
                    state.trace_class_counts[trace_class] += 1
                    trace_class_counts[trace_class] += 1
                    state.max_trace_depth = max(state.max_trace_depth, len(trace))
                    state.aws_validated_observed |= aws_validated
                    state.snapshot_observed |= snapshot
                    state.snapshot_skip_observed |= bool(snapshot_skipped_paths)
                    state.xfail_observed |= xfail
                    for entry in trace:
                        _add_bounded(
                            state.origins,
                            entry["origin"],
                            limits.max_distinct_tokens_per_operation,
                        )
                        _add_bounded(
                            state.outcomes,
                            entry["outcome"],
                            limits.max_distinct_tokens_per_operation,
                        )
                    _add_bounded(
                        state.samples,
                        (_sha256(trace), test_node_id),
                        limits.max_samples_per_operation,
                    )
                    descriptor["valid_rows"] += 1
        except csv.Error as error:
            raise EvidenceError(f"{path.name}: invalid CSV: {error}") from error
        digest = f"sha256:{input_digest.hexdigest()}"
        if digest in input_digests:
            raise EvidenceError(f"duplicate metric input content: {path.name}")
        input_digests.add(digest)
        descriptor["sha256"] = digest

    operation_payloads = [_operation_payload(operations[key]) for key in sorted(operations)]
    base = {
        "inventory_sha256": catalog["inventory_sha256"],
        "model_catalog_sha256": catalog["model_catalog_sha256"],
        "source_commit": source_commit,
    }
    summary = {
        "by_trace_class": dict(sorted(trace_class_counts.items())),
        "invalid_rows": sum(descriptor["invalid_rows"] for descriptor in inputs),
        "operations_observed": len(operation_payloads),
        "rows_seen": sum(descriptor["rows_seen"] for descriptor in inputs),
        "valid_rows": sum(descriptor["valid_rows"] for descriptor in inputs),
    }
    bundle: dict[str, Any] = {
        "base": base,
        "inputs": inputs,
        "invalid_samples": [
            {"error": error, "input": name, "line": line}
            for name, line, error in sorted(invalid_samples)
        ],
        "mode": "informational",
        "observed_at": normalized_observed_at,
        "operations": operation_payloads,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "semantic_sha256": _sha256(_semantic_payload(base, operation_payloads)),
        "summary": summary,
    }
    bundle["evidence_id"] = _sha256(bundle)
    return bundle


def render_evidence(bundle: Mapping[str, Any]) -> str:
    return json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _write_atomic(output: Path, content: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            dir=output.parent,
            encoding="utf-8",
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, output)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build an informational AWS dispatch evidence overlay"
    )
    parser.add_argument("--catalog", required=True, help="generated capabilities.json")
    parser.add_argument("--metrics", required=True, nargs="+", help="metric CSV files/directories")
    parser.add_argument("--observed-at", required=True, help="explicit ISO-8601 observation time")
    parser.add_argument("--source-commit", required=True, help="full Git commit SHA")
    parser.add_argument("--output", required=True, help="output evidence JSON")
    parser.add_argument(
        "--allow-invalid",
        action="store_true",
        help="record bounded invalid-row diagnostics instead of failing closed",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        with Path(args.catalog).open(encoding="utf-8") as stream:
            catalog = json.load(stream)
        bundle = build_evidence_bundle(
            catalog,
            args.metrics,
            observed_at=args.observed_at,
            source_commit=args.source_commit,
            allow_invalid=args.allow_invalid,
        )
        output = Path(args.output)
        _write_atomic(output, render_evidence(bundle))
    except (EvidenceError, json.JSONDecodeError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"wrote informational evidence overlay to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
