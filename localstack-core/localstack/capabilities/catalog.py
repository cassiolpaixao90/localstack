from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
SUPPORT_STATUSES = ("missing", "scaffold", "fallback", "partial", "native", "parity-pass")


@dataclass(frozen=True)
class ServiceModelRecord:
    name: str
    api_version: str
    protocol: str
    model_sha256: str
    operations: tuple[str, ...]


@dataclass(frozen=True)
class HandlerRecord:
    operation: str
    function: str
    module: str
    class_name: str
    source: str
    line: int
    unconditional_notimplemented: bool
    conditional_notimplemented: bool
    direct_fallback: str | None


@dataclass(frozen=True)
class ProviderRecord:
    service: str
    name: str
    module: str | None
    class_name: str | None
    fallback: str | None
    handlers: Mapping[str, HandlerRecord]


@dataclass(frozen=True)
class GeneratedApiRecord:
    service: str
    version: str
    source: str
    operations: Mapping[str, str]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(value).encode()).hexdigest()}"


def _evict_botocore_service_cache(loader: Any, service_name: str, raw_model: Any) -> None:
    cache = getattr(loader, "_cache", None)
    if not isinstance(cache, dict):
        raise RuntimeError("Botocore loader cache contract changed")
    for key in tuple(cache):
        if not isinstance(key, tuple):
            continue
        if any(
            isinstance(part, str) and (part == service_name or part.startswith(f"{service_name}/"))
            for part in key[1:]
        ):
            cache.pop(key)
    if any(value is raw_model for value in cache.values()):
        raise RuntimeError(f"Botocore loader retained the {service_name} service model")


def load_botocore_models() -> tuple[str, dict[str, ServiceModelRecord]]:
    """Load the pinned Botocore catalog without importing LocalStack providers."""

    import botocore
    from botocore.session import Session

    session = Session()
    loader = session.get_component("data_loader")
    result: dict[str, ServiceModelRecord] = {}

    for service_name in sorted(session.get_available_services()):
        raw_model = loader.load_service_model(service_name, "service-2")
        metadata = raw_model.get("metadata", {})
        operations = tuple(sorted(raw_model.get("operations", {})))
        result[service_name] = ServiceModelRecord(
            name=service_name,
            api_version=str(metadata.get("apiVersion", "unknown")),
            protocol=str(metadata.get("protocol", "unknown")),
            model_sha256=_sha256(raw_model),
            operations=operations,
        )
        _evict_botocore_service_cache(loader, service_name, raw_model)
        del raw_model, metadata

    return botocore.__version__, result


def _string_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _symbol_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _handler_operation(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or _symbol_name(decorator.func) != "handler":
            continue
        if decorator.args and (operation := _string_constant(decorator.args[0])):
            return operation
    return None


def scan_generated_apis(project_root: Path) -> dict[str, GeneratedApiRecord]:
    api_root = project_root / "localstack-core" / "localstack" / "aws" / "api"
    result: dict[str, GeneratedApiRecord] = {}

    for source_path in sorted(api_root.glob("*/__init__.py")):
        tree = ast.parse(source_path.read_text(), filename=str(source_path))
        for class_node in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            if not class_node.name.endswith("Api"):
                continue

            service = None
            version = "unknown"
            operations: dict[str, str] = {}
            for node in class_node.body:
                if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    if node.target.id == "service":
                        service = _string_constant(node.value)
                    elif node.target.id == "version":
                        version = _string_constant(node.value) or version
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if operation := _handler_operation(node):
                        operations[operation] = node.name

            if service:
                result[service] = GeneratedApiRecord(
                    service=service,
                    version=version,
                    source=source_path.relative_to(project_root).as_posix(),
                    operations=dict(sorted(operations.items())),
                )

    return result


def _provider_decorator(node: ast.FunctionDef) -> tuple[str, str] | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or _symbol_name(decorator.func) != "aws_provider":
            continue
        keywords = {item.arg: _string_constant(item.value) for item in decorator.keywords}
        return keywords.get("api") or node.name, keywords.get("name") or "default"
    return None


def _module_source_path(project_root: Path, module: str) -> Path:
    module_path = project_root / "localstack-core" / Path(*module.split("."))
    source_path = module_path.with_suffix(".py")
    if source_path.exists():
        return source_path
    return module_path / "__init__.py"


def _imported_symbols(tree: ast.Module, module: str) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    current_package = module.split(".")[:-1]
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            package = current_package[: len(current_package) - node.level + 1]
            imported_module = ".".join([*package, *(node.module or "").split(".")]).rstrip(".")
        elif node.module:
            imported_module = node.module
        else:
            continue
        for imported in node.names:
            result[imported.asname or imported.name] = (imported_module, imported.name)
    return result


def _raises_notimplemented(node: ast.Raise) -> bool:
    exception = node.exc
    if isinstance(exception, ast.Call):
        exception = exception.func
    return _symbol_name(exception) == "NotImplementedError" if exception else False


def _is_unconditional_notimplemented(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr) and _string_constant(body[0].value):
        body = body[1:]
    return len(body) == 1 and isinstance(body[0], ast.Raise) and _raises_notimplemented(body[0])


def _direct_fallback(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    calls = {_symbol_name(item.func) for item in ast.walk(node) if isinstance(item, ast.Call)}
    if calls.intersection({"call_moto", "call_moto_with_request"}):
        return "moto"
    return None


def _scan_provider_handlers(
    project_root: Path,
    module: str | None,
    class_name: str | None,
    generated_api: GeneratedApiRecord | None,
    parse_source: Callable[[Path], ast.Module],
) -> dict[str, HandlerRecord]:
    if not module or not class_name:
        return {}

    operation_by_function = {
        function: operation
        for operation, function in (generated_api.operations.items() if generated_api else ())
    }
    visited: set[tuple[str, str]] = set()

    def has_generated_api_base(
        current_module: str,
        current_class_name: str,
        seen: set[tuple[str, str]],
    ) -> bool:
        identity = (current_module, current_class_name)
        if identity in seen:
            return False
        seen.add(identity)
        if current_module.startswith("localstack.aws.api"):
            return True

        source_path = _module_source_path(project_root, current_module)
        if not source_path.exists():
            return False
        tree = parse_source(source_path)
        class_node = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == current_class_name
            ),
            None,
        )
        if class_node is None:
            return False
        imports = _imported_symbols(tree, current_module)
        for base in class_node.bases:
            if not (base_name := _symbol_name(base)):
                continue
            base_module, resolved_name = imports.get(base_name, (current_module, base_name))
            if has_generated_api_base(base_module, resolved_name, seen):
                return True
        return False

    uses_generated_api = has_generated_api_base(module, class_name, set())

    def scan_class(current_module: str, current_class_name: str) -> dict[str, HandlerRecord]:
        identity = (current_module, current_class_name)
        if identity in visited or current_module.startswith("localstack.aws.api."):
            return {}
        visited.add(identity)

        source_path = _module_source_path(project_root, current_module)
        if not source_path.exists():
            return {}
        tree = parse_source(source_path)
        provider_class = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == current_class_name
            ),
            None,
        )
        if provider_class is None:
            return {}

        imports = _imported_symbols(tree, current_module)
        result: dict[str, HandlerRecord] = {}
        for base in reversed(provider_class.bases):
            base_name = _symbol_name(base)
            if not base_name:
                continue
            base_module, resolved_name = imports.get(base_name, (current_module, base_name))
            result.update(scan_class(base_module, resolved_name))

        for node in provider_class.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            operation = _handler_operation(node)
            if operation is None and uses_generated_api:
                operation = operation_by_function.get(node.name)
            if not operation:
                continue

            unconditional = _is_unconditional_notimplemented(node)
            has_notimplemented = any(
                isinstance(item, ast.Raise) and _raises_notimplemented(item)
                for item in ast.walk(node)
            )
            result[operation] = HandlerRecord(
                operation=operation,
                function=node.name,
                module=current_module,
                class_name=current_class_name,
                source=source_path.relative_to(project_root).as_posix(),
                line=node.lineno,
                unconditional_notimplemented=unconditional,
                conditional_notimplemented=has_notimplemented and not unconditional,
                direct_fallback=_direct_fallback(node),
            )
        return result

    return dict(sorted(scan_class(module, class_name).items()))


def scan_providers(
    project_root: Path, generated_apis: Mapping[str, GeneratedApiRecord]
) -> dict[str, tuple[ProviderRecord, ...]]:
    registry_path = project_root / "localstack-core" / "localstack" / "services" / "providers.py"
    parsed_sources: dict[Path, ast.Module] = {}

    def parse_source(source_path: Path) -> ast.Module:
        if source_path not in parsed_sources:
            parsed_sources[source_path] = ast.parse(
                source_path.read_text(), filename=str(source_path)
            )
        return parsed_sources[source_path]

    tree = parse_source(registry_path)
    providers: dict[str, list[ProviderRecord]] = {}

    for function in (node for node in tree.body if isinstance(node, ast.FunctionDef)):
        registration = _provider_decorator(function)
        if not registration:
            continue
        service, provider_name = registration

        imports: dict[str, tuple[str, str]] = {}
        for node in ast.walk(function):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            for imported in node.names:
                imports[imported.asname or imported.name] = (node.module, imported.name)

        module = None
        class_name = None
        for node in ast.walk(function):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            if not any(
                isinstance(target, ast.Name) and target.id == "provider" for target in node.targets
            ):
                continue
            called_name = _symbol_name(node.value.func)
            if called_name and called_name in imports:
                module, class_name = imports[called_name]
                break

        names = {_symbol_name(node) for node in ast.walk(function)}
        if "MotoFallbackDispatcher" in names:
            fallback = "moto"
        elif "HttpFallbackDispatcher" in names:
            fallback = "http"
        else:
            fallback = None

        handlers = _scan_provider_handlers(
            project_root,
            module,
            class_name,
            generated_apis.get(service),
            parse_source,
        )
        providers.setdefault(service, []).append(
            ProviderRecord(
                service=service,
                name=provider_name,
                module=module,
                class_name=class_name,
                fallback=fallback,
                handlers=handlers,
            )
        )

    return {
        service: tuple(sorted(records, key=lambda item: item.name))
        for service, records in sorted(providers.items())
    }


_SERVICE_DIRECTORY_ALIASES = {
    "certificatemanager": "acm",
    "configservice": "config",
    "kinesisfirehose": "firehose",
    "lambda_": "lambda",
    "resource_groups": "resource-groups",
}


def scan_cloudformation_resources(
    project_root: Path,
) -> tuple[dict[str, tuple[str, ...]], list[dict[str, str]]]:
    services_root = project_root / "localstack-core" / "localstack" / "services"
    by_service: dict[str, set[str]] = {}
    records: dict[str, dict[str, str]] = {}

    for source_path in sorted(services_root.glob("*/resource_providers/**/*.py")):
        tree = ast.parse(source_path.read_text(), filename=str(source_path))
        types = {
            value
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for value_node in ([node.value] if getattr(node, "value", None) is not None else [])
            if (value := _string_constant(value_node)) and value.startswith("AWS::")
        }
        if not types:
            continue
        source_service = source_path.relative_to(services_root).parts[0]
        service = _SERVICE_DIRECTORY_ALIASES.get(source_service, source_service)
        for resource_type in types:
            by_service.setdefault(service, set()).add(resource_type)
            records.setdefault(
                resource_type,
                {
                    "type": resource_type,
                    "source_service": service,
                    "source": source_path.relative_to(project_root).as_posix(),
                },
            )

    normalized = {
        service: tuple(sorted(resource_types))
        for service, resource_types in sorted(by_service.items())
    }
    return normalized, [records[key] for key in sorted(records)]


def _default_provider(records: Iterable[ProviderRecord]) -> ProviderRecord | None:
    return next((record for record in records if record.name == "default"), None)


def _classify_operation(
    operation: str,
    generated_api: GeneratedApiRecord | None,
    provider: ProviderRecord | None,
) -> tuple[str, str, list[str], HandlerRecord | None]:
    if generated_api is None or operation not in generated_api.operations:
        return "missing", "none", ["generated_api_missing"], None
    if provider is None:
        return "scaffold", "generated-stub", ["provider_missing"], None

    handler = provider.handlers.get(operation)
    if handler is None or handler.unconditional_notimplemented:
        reasons = ["generated_or_unconditional_stub"]
        if provider.fallback:
            reasons.append(f"fallback_configured:{provider.fallback}")
            return "fallback", f"delegated:{provider.fallback}", reasons, handler
        return "scaffold", "generated-stub", reasons, handler

    if handler.direct_fallback:
        return (
            "fallback",
            f"delegated:{handler.direct_fallback}",
            [f"direct_fallback:{handler.direct_fallback}"],
            handler,
        )

    reasons = ["native_handler_requires_runtime_evidence"]
    if handler.conditional_notimplemented:
        reasons.append("conditional_notimplemented")
    if provider.fallback:
        reasons.append(f"fallback_possible:{provider.fallback}")
        origin = "composite-candidate"
    else:
        origin = "native-candidate"
    return "partial", origin, reasons, handler


def _handler_payload(handler: HandlerRecord) -> dict[str, Any]:
    return {
        "module": handler.module,
        "class": handler.class_name,
        "function": handler.function,
        "source": handler.source,
        "line": handler.line,
        "unconditional_notimplemented": handler.unconditional_notimplemented,
        "conditional_notimplemented": handler.conditional_notimplemented,
        "direct_fallback": handler.direct_fallback,
    }


def _model_catalog_payload(
    models: Mapping[str, ServiceModelRecord],
) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "api_version": model.api_version,
            "protocol": model.protocol,
            "model_sha256": model.model_sha256,
            "operations": list(model.operations),
        }
        for name, model in sorted(models.items())
    }


def build_catalog(
    botocore_version: str,
    models: Mapping[str, ServiceModelRecord],
    generated_apis: Mapping[str, GeneratedApiRecord],
    providers: Mapping[str, tuple[ProviderRecord, ...]],
    cfn_by_service: Mapping[str, tuple[str, ...]],
    cfn_resources: list[dict[str, str]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    lock_services = _model_catalog_payload(models)
    lock = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "type": "botocore-service-model",
            "version": botocore_version,
            "license": "Apache-2.0",
            "uri": f"https://github.com/boto/botocore/tree/{botocore_version}/botocore/data",
        },
        "model_catalog_sha256": _sha256(lock_services),
        "services": lock_services,
    }

    services_payload: dict[str, Any] = {}
    totals = dict.fromkeys(SUPPORT_STATUSES, 0)
    total_operations = 0

    for service_name, model in sorted(models.items()):
        generated_api = generated_apis.get(service_name)
        provider_records = providers.get(service_name, ())
        default_provider = _default_provider(provider_records)
        operation_statuses = {status: [] for status in SUPPORT_STATUSES}
        implementations: dict[str, Any] = {}

        for operation in model.operations:
            status, origin, reasons, handler = _classify_operation(
                operation, generated_api, default_provider
            )
            operation_statuses[status].append(operation)
            totals[status] += 1
            total_operations += 1
            if status == "missing":
                continue

            implementation: dict[str, Any] = {
                "origin": origin,
                "reasons": reasons,
                "validation": {
                    "status": "unverified",
                    "evidence": [],
                },
                "performance": {"profiles": []},
            }
            if default_provider:
                implementation["provider"] = default_provider.name
                implementation["fallback"] = default_provider.fallback
            if handler:
                implementation["handler"] = _handler_payload(handler)
            implementations[operation] = implementation

        provider_payload = [
            {
                "name": record.name,
                "module": record.module,
                "class": record.class_name,
                "fallback": record.fallback,
                "declared_handlers": len(record.handlers),
            }
            for record in provider_records
        ]
        services_payload[service_name] = {
            "api_version": model.api_version,
            "protocol": model.protocol,
            "model_sha256": model.model_sha256,
            "generated_interface": generated_api.source if generated_api else None,
            "providers": provider_payload,
            "default_provider": default_provider.name if default_provider else None,
            "cloudformation_resources": list(cfn_by_service.get(service_name, ())),
            "operation_statuses": operation_statuses,
            "implementations": implementations,
        }

    catalog = {
        "schema_version": SCHEMA_VERSION,
        "model_catalog_sha256": lock["model_catalog_sha256"],
        "source": lock["source"],
        "classification": {
            "method": "conservative-static-analysis",
            "native_and_parity_require_runtime_evidence": True,
            "statuses": list(SUPPORT_STATUSES),
        },
        "summary": {
            "services": len(models),
            "operations": total_operations,
            "generated_interfaces": len(generated_apis),
            "services_with_providers": len(providers),
            "cloudformation_resources": len(cfn_resources),
            "by_status": totals,
        },
        "cloudformation": {"resources": cfn_resources},
        "services": services_payload,
    }
    catalog["inventory_sha256"] = _sha256(catalog)
    validate_catalog(catalog, models)
    return lock, catalog


def validate_catalog(catalog: Mapping[str, Any], models: Mapping[str, ServiceModelRecord]) -> None:
    if catalog.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported capability schema version")

    catalog_services = catalog.get("services", {})
    if set(catalog_services) != set(models):
        raise ValueError("capability services do not match the Botocore catalog")
    if catalog.get("model_catalog_sha256") != _sha256(_model_catalog_payload(models)):
        raise ValueError("capability model catalog digest does not match Botocore models")

    expected_totals = dict.fromkeys(SUPPORT_STATUSES, 0)
    expected_implementations = 0
    generated_interfaces = 0
    services_with_providers = 0
    cloudformation = catalog.get("cloudformation", {}).get("resources", [])
    cloudformation_types = [resource["type"] for resource in cloudformation]
    if len(cloudformation_types) != len(set(cloudformation_types)):
        raise ValueError("duplicate CloudFormation resource type")
    cloudformation_by_service: dict[str, set[str]] = {}
    for resource in cloudformation:
        cloudformation_by_service.setdefault(resource["source_service"], set()).add(
            resource["type"]
        )

    for service_name, model in models.items():
        service = catalog_services[service_name]
        expected_metadata = (model.api_version, model.protocol, model.model_sha256)
        actual_metadata = (service["api_version"], service["protocol"], service["model_sha256"])
        if actual_metadata != expected_metadata:
            raise ValueError(f"model metadata does not match Botocore for {service_name}")

        providers = service["providers"]
        provider_names = [provider["name"] for provider in providers]
        if len(provider_names) != len(set(provider_names)):
            raise ValueError(f"duplicate provider name for {service_name}")
        if (
            service["default_provider"] is not None
            and service["default_provider"] not in provider_names
        ):
            raise ValueError(f"unknown default provider for {service_name}")
        generated_interfaces += service["generated_interface"] is not None
        services_with_providers += bool(providers)

        if set(service["cloudformation_resources"]) != cloudformation_by_service.get(
            service_name, set()
        ):
            raise ValueError(f"CloudFormation resources do not match for {service_name}")

        status_groups = service["operation_statuses"]
        if set(status_groups) != set(SUPPORT_STATUSES):
            raise ValueError(f"invalid status groups for {service_name}")
        classified = [
            operation for status in SUPPORT_STATUSES for operation in status_groups[status]
        ]
        if len(classified) != len(set(classified)):
            raise ValueError(f"duplicate classified operation in {service_name}")
        if set(classified) != set(model.operations):
            raise ValueError(f"unclassified operation in {service_name}")

        for status in SUPPORT_STATUSES:
            expected_totals[status] += len(status_groups[status])
        non_missing = set(model.operations) - set(status_groups["missing"])
        implementations = service["implementations"]
        if set(implementations) != non_missing:
            raise ValueError(f"implementation details do not match statuses for {service_name}")
        expected_implementations += len(implementations)

    summary = catalog.get("summary", {})
    if summary.get("services") != len(models):
        raise ValueError("invalid service summary")
    if summary.get("operations") != sum(len(model.operations) for model in models.values()):
        raise ValueError("invalid operation summary")
    if summary.get("by_status") != expected_totals:
        raise ValueError("invalid status summary")
    if summary.get("generated_interfaces") != generated_interfaces:
        raise ValueError("invalid generated interface summary")
    if summary.get("services_with_providers") != services_with_providers:
        raise ValueError("invalid provider summary")
    if summary.get("cloudformation_resources") != len(cloudformation):
        raise ValueError("invalid CloudFormation summary")
    if expected_implementations != summary["operations"] - expected_totals["missing"]:
        raise ValueError("invalid implementation summary")

    inventory_payload = dict(catalog)
    inventory_digest = inventory_payload.pop("inventory_sha256", None)
    if inventory_digest != _sha256(inventory_payload):
        raise ValueError("invalid capability inventory digest")


def render_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_report(catalog: Mapping[str, Any]) -> str:
    summary = catalog["summary"]
    lines = [
        "# AWS Capability Inventory",
        "",
        "> Generated file. Do not edit manually. Static analysis identifies candidates, not AWS parity.",
        "",
        f"Botocore catalog: `{catalog['source']['version']}`",
        f"Botocore model catalog digest: `{catalog['model_catalog_sha256']}`",
        f"Capability inventory digest: `{catalog['inventory_sha256']}`",
        f"Services: **{summary['services']}**",
        f"Operations: **{summary['operations']}**",
        f"Generated interfaces: **{summary['generated_interfaces']}**",
        f"Services with registered providers: **{summary['services_with_providers']}**",
        f"CloudFormation resource types: **{summary['cloudformation_resources']}**",
        "",
        "## Operation status totals",
        "",
        "| Status | Operations |",
        "|---|---:|",
    ]
    for status in SUPPORT_STATUSES:
        lines.append(f"| `{status}` | {summary['by_status'][status]} |")

    lines.extend(
        [
            "",
            "`native` and `parity-pass` are intentionally empty until runtime and AWS evidence is ingested.",
            "",
            "## Services",
            "",
            "| Service | Ops | API | Provider | Fallback | Missing | Scaffold | Fallback ops | Partial | Native | Parity | CFN |",
            "|---|---:|:---:|---|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for service_name, service in catalog["services"].items():
        statuses = service["operation_statuses"]
        provider = next(
            (item for item in service["providers"] if item["name"] == service["default_provider"]),
            None,
        )
        lines.append(
            "| {service} | {ops} | {api} | {provider} | {fallback} | {missing} | {scaffold} | "
            "{fallback_ops} | {partial} | {native} | {parity} | {cfn} |".format(
                service=service_name,
                ops=sum(len(statuses[status]) for status in SUPPORT_STATUSES),
                api="yes" if service["generated_interface"] else "no",
                provider=service["default_provider"] or "-",
                fallback=provider["fallback"] if provider and provider["fallback"] else "-",
                missing=len(statuses["missing"]),
                scaffold=len(statuses["scaffold"]),
                fallback_ops=len(statuses["fallback"]),
                partial=len(statuses["partial"]),
                native=len(statuses["native"]),
                parity=len(statuses["parity-pass"]),
                cfn=len(service["cloudformation_resources"]),
            )
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `missing`: no generated API operation exists in this checkout.",
            "- `scaffold`: generated handler exists, but no implementation or fallback is available.",
            "- `fallback`: the generated stub delegates to Moto/HTTP, or the handler directly delegates.",
            "- `partial`: a provider override exists, but runtime behavior and AWS parity are unverified.",
            "- `native`: reserved for operations whose required local scenarios pass with native dispatch only.",
            "- `parity-pass`: reserved for fresh differential AWS/local evidence with no critical exclusions.",
            "",
        ]
    )
    return "\n".join(lines)


def generate_artifacts(project_root: Path) -> dict[str, str]:
    botocore_version, models = load_botocore_models()
    generated_apis = scan_generated_apis(project_root)
    providers = scan_providers(project_root, generated_apis)
    cfn_by_service, cfn_resources = scan_cloudformation_resources(project_root)
    lock, catalog = build_catalog(
        botocore_version,
        models,
        generated_apis,
        providers,
        cfn_by_service,
        cfn_resources,
    )
    return {
        "catalog.lock.json": render_json(lock),
        "generated/capabilities.json": render_json(catalog),
        "report.md": render_report(catalog),
    }


def parse_project_root(value: str | Path) -> Path:
    root = Path(value).resolve()
    required = root / "localstack-core" / "localstack" / "services" / "providers.py"
    if not required.exists():
        raise ValueError(f"not a LocalStack project root: {root}")
    return root
