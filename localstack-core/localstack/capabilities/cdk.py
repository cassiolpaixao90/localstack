"""Generate the pinned AWS CDK service-to-LocalStack planning inventory."""

import argparse
import ast
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
import re
import stat
import tarfile
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

CDK_DISTRIBUTION = "aws-cdk-lib"
CDK_VERSION = "2.241.0"
CDK_WHEEL_SHA256 = "sha256:5c62f97c13a2a9e65b1d2b376f267595b7b2cc3947f6bcf710e52e39a381b5e3"
CDK_JSII_ARCHIVE_SHA256 = "sha256:673416ff7c3ec084b59e805f90fb3c51df3bfe2d51b8d040e6ebabfe3c4c368f"
CDK_JSII_COMPRESSED_SHA256 = (
    "sha256:5dee15e5c477299081bdddcff1664e7eb7d44b022a0590e7d85a15960240c88c"
)
CDK_JSII_ASSEMBLY_SHA256 = "sha256:0f317165321aeeb159cb74494569f2e38186cbea46fcdbb6ce38df964a2183b2"
MAX_JSII_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_JSII_ASSEMBLY_BYTES = 128 * 1024 * 1024
MAX_SERVICE_MAP_BYTES = 2 * 1024 * 1024
MAX_SERVICE_MAP_SCHEMA_BYTES = 64 * 1024
MAX_CAPABILITY_CATALOG_BYTES = 4 * 1024 * 1024
MAX_CFN_CATALOG_BYTES = 2 * 1024 * 1024
MAX_PROVIDER_SOURCE_BYTES = 2 * 1024 * 1024
MAX_PROVIDER_SCHEMA_BYTES = 128 * 1024
RESOURCE_PROVIDER_HANDLERS = {"create", "read", "update", "delete", "list"}

CFN_NAMESPACE_API_ALIASES = {
    "APS": ("amp",),
    "AmazonMQ": ("mq",),
    "Cases": ("connectcases",),
    "Cassandra": ("keyspaces",),
    "CertificateManager": ("acm",),
    "Cognito": ("cognito-identity", "cognito-idp", "cognito-sync"),
    "DirectoryService": ("ds",),
    "ElasticLoadBalancing": ("elb",),
    "ElasticLoadBalancingV2": ("elbv2",),
    "Elasticsearch": ("opensearch",),
    "EventSchemas": ("schemas",),
    "HealthImaging": ("medical-imaging",),
    "InspectorV2": ("inspector2",),
    "IoTCoreDeviceAdvisor": ("iotdeviceadvisor",),
    "KinesisFirehose": ("firehose",),
    "Lex": ("lexv2-models",),
    "MSK": ("kafka",),
    "Macie": ("macie2",),
    "OpenSearchService": ("opensearch",),
    "RefactorSpaces": ("migration-hub-refactor-spaces",),
    "Route53RecoveryControl": ("route53-recovery-control-config",),
    "S3ObjectLambda": ("s3control",),
    "SystemsManagerSAP": ("ssm-sap",),
    "Timestream": ("timestream-influxdb", "timestream-query", "timestream-write"),
}


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _read_regular_bounded(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} is not a regular file")
        if metadata.st_size < 1 or metadata.st_size > maximum:
            raise ValueError(f"{label} is outside the accepted size")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            payload = stream.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not payload or len(payload) > maximum or len(payload) != metadata.st_size:
        raise ValueError(f"{label} is outside the accepted size")
    return payload


def _parse_python(path: Path, label: str) -> tuple[ast.Module, bytes]:
    payload = _read_regular_bounded(path, MAX_PROVIDER_SOURCE_BYTES, label)
    return ast.parse(payload, filename=str(path)), payload


def _read_assignment(payload: bytes, path: Path, variable: str) -> object:
    module = ast.parse(payload, filename=str(path))
    for statement in module.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name) and target.id == variable:
            return ast.literal_eval(statement.value)
    raise ValueError(f"{variable} is missing from {path}")


def _load_jsii_assembly() -> tuple[dict, dict]:
    distribution = importlib.metadata.distribution(CDK_DISTRIBUTION)
    if distribution.version != CDK_VERSION:
        raise ValueError(f"expected {CDK_DISTRIBUTION} {CDK_VERSION}, got {distribution.version}")
    archive_path = Path(
        distribution.locate_file(f"aws_cdk/_jsii/aws-cdk-lib@{CDK_VERSION}.jsii.tgz")
    )
    archive_payload = _read_regular_bounded(
        archive_path, MAX_JSII_ARCHIVE_BYTES, "AWS CDK JSII archive"
    )
    archive_digest = _sha256(archive_payload)
    if archive_digest != CDK_JSII_ARCHIVE_SHA256:
        raise ValueError("AWS CDK JSII archive digest is stale")
    with tarfile.open(fileobj=io.BytesIO(archive_payload), mode="r:gz") as archive:
        member = archive.getmember("package/.jsii.gz")
        if not member.isfile() or not 1 <= member.size <= MAX_JSII_ARCHIVE_BYTES:
            raise ValueError("AWS CDK JSII assembly member is invalid")
        stream = archive.extractfile(member)
        if stream is None:
            raise ValueError("AWS CDK JSII assembly member is unreadable")
        compressed = stream.read(MAX_JSII_ARCHIVE_BYTES + 1)
    compressed_digest = _sha256(compressed)
    if compressed_digest != CDK_JSII_COMPRESSED_SHA256:
        raise ValueError("AWS CDK JSII compressed assembly digest is stale")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        assembly_payload = stream.read(MAX_JSII_ASSEMBLY_BYTES + 1)
    if not assembly_payload or len(assembly_payload) > MAX_JSII_ASSEMBLY_BYTES:
        raise ValueError("AWS CDK JSII assembly is outside the accepted size")
    assembly_digest = _sha256(assembly_payload)
    if assembly_digest != CDK_JSII_ASSEMBLY_SHA256:
        raise ValueError("AWS CDK JSII assembly digest is stale")
    assembly = json.loads(assembly_payload)
    if assembly.get("name") != CDK_DISTRIBUTION or assembly.get("version") != CDK_VERSION:
        raise ValueError("AWS CDK JSII assembly identity is stale")
    return assembly, {
        "distribution": CDK_DISTRIBUTION,
        "version": CDK_VERSION,
        "distribution_wheel_sha256": CDK_WHEEL_SHA256,
        "jsii_archive_sha256": archive_digest,
        "jsii_compressed_sha256": compressed_digest,
        "jsii_assembly_sha256": assembly_digest,
    }


def _is_construct(fqn: str, bases: dict[str, str | None]) -> bool:
    seen = set()
    while fqn and fqn not in seen:
        if fqn == "constructs.Construct":
            return True
        seen.add(fqn)
        fqn = bases.get(fqn)
    return False


def _status_counts(service: dict) -> dict[str, int]:
    return {
        status: len(service["operation_statuses"][status])
        for status in ("native", "parity-pass", "partial", "fallback", "scaffold", "missing")
    }


def _planning_status(total: int, present: int) -> str:
    if total == 0:
        return "no-l1-resource-types"
    if present == total:
        return "all-resource-provider-records-present"
    if present:
        return "partial-resource-provider-records"
    return "no-resource-provider-records"


def _class_with_resource_type(module: ast.Module, resource_type: str) -> str:
    matches = []
    for statement in module.body:
        if not isinstance(statement, ast.ClassDef):
            continue
        for class_statement in statement.body:
            if not isinstance(class_statement, (ast.Assign, ast.AnnAssign)):
                continue
            targets = (
                class_statement.targets
                if isinstance(class_statement, ast.Assign)
                else [class_statement.target]
            )
            if not any(isinstance(target, ast.Name) and target.id == "TYPE" for target in targets):
                continue
            try:
                value = ast.literal_eval(class_statement.value)
            except (TypeError, ValueError):
                continue
            if value == resource_type:
                matches.append(statement.name)
    if len(matches) != 1:
        raise ValueError(f"expected one provider class for {resource_type}, found {len(matches)}")
    return matches[0]


def _is_not_implemented_raise(statement: ast.AST) -> bool:
    if not isinstance(statement, ast.Raise):
        return False
    exception = statement.exc
    if isinstance(exception, ast.Name):
        return exception.id == "NotImplementedError"
    return (
        isinstance(exception, ast.Call)
        and isinstance(exception.func, ast.Name)
        and exception.func.id == "NotImplementedError"
    )


def _handler_method_status(method: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    body = method.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if len(body) == 1 and _is_not_implemented_raise(body[0]):
        return "notimplemented-only"
    if any(_is_not_implemented_raise(statement) for statement in ast.walk(method)):
        return "contains-notimplemented"
    return "method-body-present-unverified"


def _provider_handler_contract(
    project_root: Path,
    resource_type: str,
    catalog_source: Path,
    implementation_class: ast.ClassDef,
) -> dict:
    schema_stem = catalog_source.name.removesuffix("_base.py").removesuffix(".py")
    schema_source = catalog_source.with_name(f"{schema_stem}.schema.json")
    schema_payload = _read_regular_bounded(
        schema_source, MAX_PROVIDER_SCHEMA_BYTES, f"resource provider schema for {resource_type}"
    )
    schema = json.loads(schema_payload)
    handlers = schema.get("handlers", {})
    if schema.get("typeName") != resource_type or not isinstance(handlers, dict):
        raise ValueError(f"resource provider schema is stale for {resource_type}")
    schema_declared_handlers = sorted(handlers)
    unknown_handlers = set(schema_declared_handlers) - RESOURCE_PROVIDER_HANDLERS
    if unknown_handlers:
        raise ValueError(f"resource provider handlers are stale for {resource_type}")

    methods: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = defaultdict(list)
    for statement in implementation_class.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods[statement.name].append(statement)
    handler_statuses = {}
    for handler in schema_declared_handlers:
        candidates = methods[handler]
        if len(candidates) > 1:
            raise ValueError(f"duplicate {handler} handler for {resource_type}")
        if candidates:
            handler_statuses[handler] = _handler_method_status(candidates[0])
        else:
            handler_statuses[handler] = "method-missing"
    if not schema_declared_handlers:
        static_status = "no-schema-handler-declarations"
    elif all(status == "method-body-present-unverified" for status in handler_statuses.values()):
        static_status = "all-method-bodies-present-unverified"
    else:
        static_status = "incomplete-static-handler-surface"
    return {
        "schema_source": schema_source.relative_to(project_root).as_posix(),
        "schema_sha256": _sha256(schema_payload),
        "schema_declared_handlers": schema_declared_handlers,
        "handler_statuses": handler_statuses,
        "static_status": static_status,
    }


def _resolve_provider_registration(
    project_root: Path,
    resource_type: str,
    catalog_source: Path,
    catalog_module: ast.Module,
    catalog_payload: bytes,
    catalog_class: str,
) -> tuple[Path, str, Path, ast.ClassDef, bytes, bytes]:
    if catalog_source.name.endswith("_base.py"):
        plugin_name = catalog_source.name.replace("_base.py", "_plugin.py")
    else:
        plugin_name = f"{catalog_source.stem}_plugin.py"
    plugin_path = catalog_source.with_name(plugin_name)
    plugin_module, plugin_payload = _parse_python(
        plugin_path, f"registration plugin for {resource_type}"
    )
    plugin_base_imported = any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "localstack.services.cloudformation.resource_provider"
        and any(
            imported.name == "CloudFormationResourceProviderPlugin" and imported.asname is None
            for imported in statement.names
        )
        for statement in plugin_module.body
    )
    if not plugin_base_imported:
        raise ValueError(f"registration plugin base is stale for {resource_type}")
    plugin_classes = []
    for statement in plugin_module.body:
        if not isinstance(statement, ast.ClassDef):
            continue
        if not (
            len(statement.bases) == 1
            and isinstance(statement.bases[0], ast.Name)
            and statement.bases[0].id == "CloudFormationResourceProviderPlugin"
        ):
            continue
        name_value = None
        load_method = None
        for class_statement in statement.body:
            if (
                isinstance(class_statement, ast.Assign)
                and len(class_statement.targets) == 1
                and isinstance(class_statement.targets[0], ast.Name)
                and class_statement.targets[0].id == "name"
            ):
                try:
                    name_value = ast.literal_eval(class_statement.value)
                except (TypeError, ValueError):
                    pass
            if isinstance(class_statement, ast.FunctionDef) and class_statement.name == "load":
                load_method = class_statement
        if name_value == resource_type and load_method is not None:
            plugin_classes.append(load_method)
    if len(plugin_classes) != 1:
        raise ValueError(f"expected one registration plugin for {resource_type}")

    load_method = plugin_classes[0]
    if not (
        len(load_method.body) == 2
        and isinstance(load_method.body[0], ast.ImportFrom)
        and load_method.body[0].module
        and load_method.body[0].module.startswith("localstack.services.")
        and len(load_method.body[0].names) == 1
        and isinstance(load_method.body[1], ast.Assign)
        and len(load_method.body[1].targets) == 1
        and isinstance(load_method.body[1].targets[0], ast.Attribute)
        and isinstance(load_method.body[1].targets[0].value, ast.Name)
        and load_method.body[1].targets[0].value.id == "self"
        and load_method.body[1].targets[0].attr == "factory"
        and isinstance(load_method.body[1].value, ast.Name)
    ):
        raise ValueError(f"expected one concrete provider factory for {resource_type}")
    provider_import = load_method.body[0].names[0]
    provider_binding = provider_import.asname or provider_import.name
    if load_method.body[1].value.id != provider_binding:
        raise ValueError(f"registration plugin factory is stale for {resource_type}")
    module_name = load_method.body[0].module
    class_name = provider_import.name
    implementation_path = (
        project_root / "localstack-core" / Path(*module_name.split(".")).with_suffix(".py")
    )
    if implementation_path == catalog_source:
        implementation_module = catalog_module
        implementation_payload = catalog_payload
    else:
        implementation_module, implementation_payload = _parse_python(
            implementation_path, f"implementation provider for {resource_type}"
        )
    implementations = [
        statement
        for statement in implementation_module.body
        if isinstance(statement, ast.ClassDef) and statement.name == class_name
    ]
    if len(implementations) != 1:
        raise ValueError(f"concrete provider class is missing for {resource_type}")
    if catalog_source.name.endswith("_base.py"):
        bases = {base.id for base in implementations[0].bases if isinstance(base, ast.Name)}
        if catalog_class not in bases:
            raise ValueError(
                f"concrete provider does not inherit {catalog_class} for {resource_type}"
            )
    elif implementation_path != catalog_source or class_name != catalog_class:
        raise ValueError(f"registration plugin factory is stale for {resource_type}")
    return (
        implementation_path,
        class_name,
        plugin_path,
        implementations[0],
        implementation_payload,
        plugin_payload,
    )


def _resolve_provider_record(project_root: Path, resource_type: str, record: dict) -> dict:
    catalog_source = project_root / record["source"]
    source_module, source_payload = _parse_python(
        catalog_source, f"catalog provider for {resource_type}"
    )
    provider_class = _class_with_resource_type(source_module, resource_type)
    (
        implementation_source,
        provider_class,
        registration_source,
        implementation_class,
        implementation_payload,
        registration_payload,
    ) = _resolve_provider_registration(
        project_root,
        resource_type,
        catalog_source,
        source_module,
        source_payload,
        provider_class,
    )
    return {
        "source_service": record["source_service"],
        "catalog_source": catalog_source.relative_to(project_root).as_posix(),
        "catalog_sha256": _sha256(source_payload),
        "implementation_source": implementation_source.relative_to(project_root).as_posix(),
        "implementation_class": provider_class,
        "implementation_sha256": _sha256(implementation_payload),
        "registration_source": registration_source.relative_to(project_root).as_posix(),
        "registration_sha256": _sha256(registration_payload),
        "handler_contract": _provider_handler_contract(
            project_root, resource_type, catalog_source, implementation_class
        ),
    }


def build_cdk_service_map(project_root: Path) -> dict:
    assembly, cdk_source = _load_jsii_assembly()
    capabilities_path = project_root / "capabilities/generated/capabilities.json"
    cfn_catalog_path = (
        project_root / "localstack-core/localstack/services/cloudformation/resources.py"
    )
    capabilities_payload = _read_regular_bounded(
        capabilities_path, MAX_CAPABILITY_CATALOG_BYTES, "LocalStack capability catalog"
    )
    catalog = json.loads(capabilities_payload)
    cfn_catalog_payload = _read_regular_bounded(
        cfn_catalog_path, MAX_CFN_CATALOG_BYTES, "CloudFormation resource catalog"
    )
    current_cfn = set(
        _read_assignment(cfn_catalog_payload, cfn_catalog_path, "AWS_AVAILABLE_CFN_RESOURCES")
    )
    modules = sorted(
        submodule.removeprefix(f"{CDK_DISTRIBUTION}.")
        for submodule in assembly["submodules"]
        if (
            submodule.startswith(f"{CDK_DISTRIBUTION}.aws_")
            or submodule == f"{CDK_DISTRIBUTION}.alexa_ask"
        )
        and "." not in submodule.removeprefix(f"{CDK_DISTRIBUTION}.")
    )
    module_set = set(modules)
    go_target = (assembly.get("targets") or {}).get("go") or {}
    if go_target != {
        "moduleName": "github.com/aws/aws-cdk-go",
        "packageName": "awscdk",
    }:
        raise ValueError("AWS CDK Go binding target is stale")
    go_root = (
        f"{go_target['moduleName']}/{go_target['packageName']}/v{CDK_VERSION.split('.', 1)[0]}"
    )
    types = assembly["types"]
    bases = {
        value["fqn"]: value.get("base") for value in types.values() if value.get("kind") == "class"
    }
    class_counts = Counter()
    construct_counts = Counter()
    stable_construct_counts = Counter()
    l1_classes = Counter()
    resources_by_module: dict[str, set[str]] = defaultdict(set)
    resource_classes_by_module: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    all_cdk_resources = set()
    for value in types.values():
        module = value.get("namespace")
        if module not in module_set:
            continue
        if value.get("kind") == "class":
            class_counts[module] += 1
            if _is_construct(value["fqn"], bases):
                construct_counts[module] += 1
                if (value.get("docs") or {}).get("stability") == "stable":
                    stable_construct_counts[module] += 1
        resource_type = ((value.get("docs") or {}).get("custom") or {}).get(
            "cloudformationResource"
        )
        if resource_type:
            l1_classes[module] += 1
            resources_by_module[module].add(resource_type)
            resource_classes_by_module[module][resource_type].add(value["fqn"])
            all_cdk_resources.add(resource_type)

    normalized_catalog = {
        re.sub(r"[^a-z0-9]", "", service): service for service in catalog["services"]
    }
    provider_records = {
        record["type"]: _resolve_provider_record(project_root, record["type"], record)
        for record in catalog["cloudformation"]["resources"]
    }
    for provider in provider_records.values():
        normalized_source = re.sub(r"[^a-z0-9]", "", provider["source_service"].lower())
        provider["source_service"] = normalized_catalog.get(
            normalized_source, provider["source_service"].replace("_", "-")
        )
    localstack_types = set(provider_records)
    aws_localstack_types = {item for item in localstack_types if item.startswith("AWS::")}
    missing_alias_services = sorted(
        {
            service
            for services in CFN_NAMESPACE_API_ALIASES.values()
            for service in services
            if service not in catalog["services"]
        }
    )
    if missing_alias_services:
        raise ValueError(f"CDK API aliases are stale: {missing_alias_services}")
    services = []
    static_counts = Counter()
    for module in modules:
        resource_types = sorted(resources_by_module[module])
        present_types = sorted(set(resource_types) & localstack_types)
        missing_types = sorted(set(resource_types) - localstack_types)
        provider_services = []
        for source_service in sorted(
            {provider_records[resource]["source_service"] for resource in present_types}
        ):
            normalized_provider = re.sub(r"[^a-z0-9]", "", source_service.lower())
            provider_services.append(
                normalized_catalog.get(normalized_provider, source_service.replace("_", "-"))
            )
        normalized_module = re.sub(
            r"[^a-z0-9]", "", module.removeprefix("aws_").removeprefix("alexa_")
        )
        namespace_mappings = []
        for namespace in sorted({resource.split("::", 2)[1] for resource in resource_types}):
            normalized_namespace = re.sub(r"[^a-z0-9]", "", namespace.lower())
            candidates = []
            if normalized_namespace in normalized_catalog:
                candidates.append(normalized_catalog[normalized_namespace])
            candidates.extend(CFN_NAMESPACE_API_ALIASES.get(namespace, ()))
            namespace_mappings.append(
                {
                    "namespace": namespace,
                    "normalized_name": normalized_namespace,
                    "api_candidates": candidates,
                }
            )
        api_candidates = set()
        for provider_service in provider_services:
            if provider_service in catalog["services"]:
                api_candidates.add(provider_service)
        api_candidates.update(
            candidate for mapping in namespace_mappings for candidate in mapping["api_candidates"]
        )
        if normalized_module in normalized_catalog:
            api_candidates.add(normalized_catalog[normalized_module])
        api_catalog = []
        for service_name in sorted(api_candidates):
            service = catalog["services"][service_name]
            api_catalog.append(
                {
                    "service": service_name,
                    "provider_registered": bool(service["providers"]),
                    "operation_status_counts": _status_counts(service),
                }
            )
        mapped_namespaces = sum(bool(mapping["api_candidates"]) for mapping in namespace_mappings)
        if resource_types and mapped_namespaces == len(namespace_mappings):
            api_mapping_status = "mapped"
        elif resource_types and api_catalog:
            api_mapping_status = "partial"
        elif resource_types:
            api_mapping_status = "unmapped"
        else:
            api_mapping_status = "not-applicable"
        if not resource_types:
            static_status = "not-applicable"
        elif not present_types:
            static_status = "none"
        elif len(present_types) == len(resource_types):
            static_status = "complete"
        else:
            static_status = "partial"
        static_counts[static_status] += 1
        submodule = assembly["submodules"][f"{CDK_DISTRIBUTION}.{module}"]
        targets = submodule.get("targets") or {}
        bindings = {
            "typescript_javascript": f"{CDK_DISTRIBUTION}/{module.replace('_', '-')}",
            "python": (targets.get("python") or {}).get("module"),
            "java": (targets.get("java") or {}).get("package"),
            "dotnet": (targets.get("dotnet") or {}).get("namespace"),
            "go": f"{go_root}/{module.replace('_', '')}",
        }
        if any(not isinstance(value, str) or not value for value in bindings.values()):
            raise ValueError(f"AWS CDK binding targets are incomplete for {module}")
        resource_records = []
        for resource_type in resource_types:
            provider = provider_records.get(resource_type)
            resource_records.append(
                {
                    "type": resource_type,
                    "class_fqns": sorted(resource_classes_by_module[module][resource_type]),
                    "present_in_current_cfn_catalog": resource_type in current_cfn,
                    "localstack_resource_provider": (
                        {
                            "source_service": provider["source_service"],
                            "catalog_source": provider["catalog_source"],
                            "catalog_sha256": provider["catalog_sha256"],
                            "implementation_source": provider["implementation_source"],
                            "implementation_class": provider["implementation_class"],
                            "implementation_sha256": provider["implementation_sha256"],
                            "registration_source": provider["registration_source"],
                            "registration_sha256": provider["registration_sha256"],
                            "handler_contract": provider["handler_contract"],
                        }
                        if provider
                        else None
                    ),
                }
            )
        services.append(
            {
                "module": module,
                "bindings": bindings,
                "class_count": class_counts[module],
                "construct_class_count": construct_counts[module],
                "stable_construct_class_count": stable_construct_counts[module],
                "l1_class_count": l1_classes[module],
                "resources": resource_records,
                "l1_resource_types": resource_types,
                "cloudformation_namespaces": sorted(
                    {resource.split("::", 2)[1] for resource in resource_types}
                ),
                "api_namespace_mappings": namespace_mappings,
                "unmapped_cloudformation_namespaces": [
                    mapping["namespace"]
                    for mapping in namespace_mappings
                    if not mapping["api_candidates"]
                ],
                "localstack_resource_provider_types": present_types,
                "missing_resource_provider_types": missing_types,
                "localstack_resource_provider_services": provider_services,
                "api_mapping_status": api_mapping_status,
                "api_catalog": api_catalog,
                "static_resource_provider_status": static_status,
                "planning_status": _planning_status(len(resource_types), len(present_types)),
                "support_claim": "not-established",
            }
        )

    overlap = all_cdk_resources & current_cfn
    localstack_cdk = all_cdk_resources & aws_localstack_types
    cdk_provider_records = [provider_records[resource_type] for resource_type in localstack_cdk]
    handler_status_counts = Counter(
        record["handler_contract"]["static_status"] for record in cdk_provider_records
    )
    handler_method_status_counts = Counter(
        status
        for record in cdk_provider_records
        for status in record["handler_contract"]["handler_statuses"].values()
    )
    summary = {
        "cdk_service_modules": len(modules),
        "modules_with_construct_classes": sum(bool(construct_counts[module]) for module in modules),
        "modules_with_l1_resources": sum(bool(resources_by_module[module]) for module in modules),
        "cdk_l1_resource_types": len(all_cdk_resources),
        "current_cfn_catalog_resource_types": len(current_cfn),
        "cdk_current_cfn_overlap": len(overlap),
        "cdk_only_resource_types": len(all_cdk_resources - current_cfn),
        "current_cfn_only_resource_types": len(current_cfn - all_cdk_resources),
        "localstack_resource_provider_types": len(localstack_types),
        "localstack_aws_resource_provider_types": len(aws_localstack_types),
        "localstack_cdk_l1_intersection": len(localstack_cdk),
        "static_l1_coverage_basis_points": (
            len(localstack_cdk) * 10_000 + len(all_cdk_resources) // 2
        )
        // len(all_cdk_resources),
        "modules_static_complete": static_counts["complete"],
        "modules_static_partial": static_counts["partial"],
        "modules_static_none": static_counts["none"],
        "modules_without_l1_resources": static_counts["not-applicable"],
        "modules_with_api_catalog_candidates": sum(
            bool(service["api_catalog"]) for service in services
        ),
        "modules_l1_without_api_catalog_candidate": sum(
            bool(service["l1_resource_types"]) and not service["api_catalog"]
            for service in services
        ),
        "modules_l1_with_unmapped_cfn_namespaces": sum(
            bool(service["unmapped_cloudformation_namespaces"]) for service in services
        ),
        "resource_provider_schema_declared_handlers": sum(handler_method_status_counts.values()),
        "resource_provider_handlers_method_body_present_unverified": handler_method_status_counts[
            "method-body-present-unverified"
        ],
        "resource_provider_handlers_notimplemented_only": handler_method_status_counts[
            "notimplemented-only"
        ],
        "resource_provider_handlers_contains_notimplemented": handler_method_status_counts[
            "contains-notimplemented"
        ],
        "resource_provider_handlers_method_missing": handler_method_status_counts["method-missing"],
        "resource_provider_records_all_method_bodies_present_unverified": handler_status_counts[
            "all-method-bodies-present-unverified"
        ],
        "resource_provider_records_incomplete_static_handler_surface": handler_status_counts[
            "incomplete-static-handler-surface"
        ],
        "resource_provider_records_no_schema_handler_declarations": handler_status_counts[
            "no-schema-handler-declarations"
        ],
    }
    result = {
        "schema_version": 1,
        "map_sha256": "",
        "claim": "static-inventory-only",
        "methodology": {
            "denominator": "pinned-aws-cdk-lib-jsii-cloudformation-resources",
            "local_numerator": "statically-discovered-localstack-cloudformation-resource-providers",
            "handler_classification": "static-direct-method-body-presence-only",
            "warning": "resource-provider presence does not establish lifecycle correctness or CDK support",
        },
        "sources": {
            "aws_cdk_lib": cdk_source,
            "current_cloudformation_catalog": {
                "path": cfn_catalog_path.relative_to(project_root).as_posix(),
                "sha256": _sha256(cfn_catalog_payload),
            },
            "localstack_capability_catalog": {
                "path": capabilities_path.relative_to(project_root).as_posix(),
                "sha256": _sha256(capabilities_payload),
                "inventory_sha256": catalog["inventory_sha256"],
                "botocore_version": catalog["source"]["version"],
            },
        },
        "summary": summary,
        "drift": {
            "cdk_only_resource_types": sorted(all_cdk_resources - current_cfn),
            "current_cfn_only_resource_types": sorted(current_cfn - all_cdk_resources),
        },
        "services": services,
    }
    result["map_sha256"] = _sha256(_canonical_bytes({**result, "map_sha256": ""}))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = args.output or args.project_root / "capabilities/cdk/services.json"
    payload = json.dumps(build_cdk_service_map(args.project_root), indent=2) + "\n"
    encoded_payload = payload.encode()
    if len(encoded_payload) > MAX_SERVICE_MAP_BYTES:
        raise SystemExit("CDK service map exceeds the accepted size")
    if args.check:
        try:
            current = _read_regular_bounded(output, MAX_SERVICE_MAP_BYTES, "CDK service map")
        except (OSError, ValueError):
            current = b""
        if current != encoded_payload:
            raise SystemExit("CDK service map is stale")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(encoded_payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
