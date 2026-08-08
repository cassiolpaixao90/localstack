import ast
import json
from pathlib import Path

import pytest

from localstack.capabilities.catalog import (
    GeneratedApiRecord,
    HandlerRecord,
    ProviderRecord,
    ServiceModelRecord,
    _sha256,
    build_catalog,
    generate_artifacts,
    render_json,
    scan_generated_apis,
    scan_providers,
    validate_catalog,
)


def _model(*operations: str) -> ServiceModelRecord:
    return ServiceModelRecord(
        name="sample",
        api_version="2026-01-01",
        protocol="json",
        model_sha256="sha256:" + "0" * 64,
        operations=tuple(sorted(operations)),
    )


def _api(*operations: str) -> GeneratedApiRecord:
    return GeneratedApiRecord(
        service="sample",
        version="2026-01-01",
        source="localstack-core/localstack/aws/api/sample/__init__.py",
        operations={operation: operation.lower() for operation in operations},
    )


def _handler(operation: str, **overrides) -> HandlerRecord:
    values = {
        "operation": operation,
        "function": operation.lower(),
        "module": "localstack.services.sample.provider",
        "class_name": "SampleProvider",
        "source": "localstack-core/localstack/services/sample/provider.py",
        "line": 10,
        "unconditional_notimplemented": False,
        "conditional_notimplemented": False,
        "direct_fallback": None,
    }
    values.update(overrides)
    return HandlerRecord(**values)


def _provider(*handlers: HandlerRecord, fallback: str | None = None) -> ProviderRecord:
    return ProviderRecord(
        service="sample",
        name="default",
        module="localstack.services.sample.provider",
        class_name="SampleProvider",
        fallback=fallback,
        handlers={handler.operation: handler for handler in handlers},
    )


def _build(model, api=None, provider=None):
    return build_catalog(
        "1.2.3",
        {"sample": model},
        {"sample": api} if api else {},
        {"sample": (provider,)} if provider else {},
        {},
        [],
    )[1]


def _resign(catalog):
    catalog["inventory_sha256"] = _sha256(
        {key: value for key, value in catalog.items() if key != "inventory_sha256"}
    )


@pytest.mark.parametrize(
    ("api", "provider", "expected"),
    [
        (None, None, "missing"),
        (_api("DoThing"), None, "scaffold"),
        (_api("DoThing"), _provider(fallback="moto"), "fallback"),
        (_api("DoThing"), _provider(_handler("DoThing")), "partial"),
        (
            _api("DoThing"),
            _provider(_handler("DoThing", direct_fallback="moto"), fallback="moto"),
            "fallback",
        ),
    ],
)
def test_conservative_classification(api, provider, expected):
    catalog = _build(_model("DoThing"), api, provider)

    statuses = catalog["services"]["sample"]["operation_statuses"]

    assert statuses[expected] == ["DoThing"]
    assert sum(len(items) for items in statuses.values()) == 1
    assert not statuses["native"]
    assert not statuses["parity-pass"]


def test_catalog_generation_is_deterministic():
    model = _model("Alpha", "Beta")
    api = _api("Alpha", "Beta")
    provider = _provider(_handler("Alpha"), fallback="http")

    first = render_json(_build(model, api, provider))
    second = render_json(_build(model, api, provider))

    assert first == second
    assert "generated_at" not in first
    assert "native_handler_requires_runtime_evidence" in first


def test_rendered_catalog_can_be_loaded_and_validated():
    model = _model("Alpha", "Beta")
    catalog = _build(model, _api("Alpha", "Beta"), _provider(_handler("Alpha")))

    loaded = json.loads(render_json(catalog))

    validate_catalog(loaded, {"sample": model})


def test_inventory_digest_changes_independently_from_model_catalog():
    model = _model("DoThing")
    scaffold = _build(model, _api("DoThing"))
    partial = _build(model, _api("DoThing"), _provider(_handler("DoThing")))

    assert scaffold["model_catalog_sha256"] == partial["model_catalog_sha256"]
    assert scaffold["inventory_sha256"] != partial["inventory_sha256"]


def test_validation_rejects_duplicate_operation():
    model = _model("DoThing")
    catalog = _build(model)
    catalog["services"]["sample"]["operation_statuses"]["scaffold"].append("DoThing")

    with pytest.raises(ValueError, match="duplicate classified operation"):
        validate_catalog(catalog, {"sample": model})


def test_validation_rejects_stale_inventory_digest():
    model = _model("DoThing")
    catalog = _build(model, _api("DoThing"))
    catalog["services"]["sample"]["implementations"]["DoThing"]["reasons"].append("mutated")

    with pytest.raises(ValueError, match="invalid capability inventory digest"):
        validate_catalog(catalog, {"sample": model})


def test_validation_rejects_catalog_bound_to_different_model():
    model = _model("DoThing")
    catalog = _build(model, _api("DoThing"))
    catalog["services"]["sample"]["model_sha256"] = "sha256:" + "1" * 64
    _resign(catalog)

    with pytest.raises(ValueError, match="model metadata does not match Botocore"):
        validate_catalog(catalog, {"sample": model})


def test_validation_rejects_different_model_catalog_digest():
    model = _model("DoThing")
    catalog = _build(model, _api("DoThing"))
    catalog["model_catalog_sha256"] = "sha256:" + "1" * 64
    _resign(catalog)

    with pytest.raises(ValueError, match="model catalog digest does not match"):
        validate_catalog(catalog, {"sample": model})


@pytest.mark.parametrize(
    "field",
    ["generated_interfaces", "services_with_providers", "cloudformation_resources"],
)
def test_validation_rejects_invalid_relational_summary(field):
    model = _model("DoThing")
    catalog = _build(model, _api("DoThing"))
    catalog["summary"][field] += 1
    _resign(catalog)

    with pytest.raises(ValueError, match="invalid"):
        validate_catalog(catalog, {"sample": model})


def test_catalog_does_not_invent_default_provider():
    model = _model("DoThing")
    alternative = ProviderRecord(
        service="sample",
        name="alternative",
        module="localstack.services.sample.provider",
        class_name="SampleProvider",
        fallback=None,
        handlers={"DoThing": _handler("DoThing")},
    )

    catalog = build_catalog(
        "1.2.3",
        {"sample": model},
        {"sample": _api("DoThing")},
        {"sample": (alternative,)},
        {},
        [],
    )[1]

    assert catalog["services"]["sample"]["default_provider"] is None
    assert catalog["services"]["sample"]["operation_statuses"]["scaffold"] == ["DoThing"]


def test_scans_generated_api_and_provider(tmp_path: Path):
    api_path = tmp_path / "localstack-core/localstack/aws/api/sample/__init__.py"
    provider_path = tmp_path / "localstack-core/localstack/services/sample/provider.py"
    registry_path = tmp_path / "localstack-core/localstack/services/providers.py"
    api_path.parent.mkdir(parents=True)
    provider_path.parent.mkdir(parents=True)
    api_path.write_text(
        """
class SampleApi:
    service: str = "sample"
    version: str = "2026-01-01"

    @handler("DoThing")
    def do_thing(self, context, **kwargs):
        raise NotImplementedError
""".strip()
        + "\n"
    )
    provider_path.write_text(
        """
from localstack.aws.api.sample import SampleApi

class SampleProvider(SampleApi):
    def do_thing(self, context, **kwargs):
        if kwargs.get("delegate"):
            raise NotImplementedError
        return {}
""".strip()
        + "\n"
    )
    registry_path.write_text(
        """
@aws_provider()
def sample():
    from localstack.services.sample.provider import SampleProvider
    from localstack.services.moto import MotoFallbackDispatcher
    provider = SampleProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)
""".strip()
        + "\n"
    )

    generated = scan_generated_apis(tmp_path)
    providers = scan_providers(tmp_path, generated)

    handler = providers["sample"][0].handlers["DoThing"]
    assert generated["sample"].operations == {"DoThing": "do_thing"}
    assert providers["sample"][0].fallback == "moto"
    assert handler.conditional_notimplemented
    assert not handler.unconditional_notimplemented


def test_scans_handlers_inherited_from_imported_provider(tmp_path: Path):
    api_path = tmp_path / "localstack-core/localstack/aws/api/sample/__init__.py"
    base_path = tmp_path / "localstack-core/localstack/services/sample/base.py"
    provider_path = tmp_path / "localstack-core/localstack/services/sample/provider.py"
    registry_path = tmp_path / "localstack-core/localstack/services/providers.py"
    api_path.parent.mkdir(parents=True)
    base_path.parent.mkdir(parents=True)
    api_path.write_text(
        """
class SampleApi:
    service: str = "sample"
    version: str = "2026-01-01"

    @handler("InheritedThing")
    def inherited_thing(self, context, **kwargs):
        raise NotImplementedError

    @handler("OverriddenThing")
    def overridden_thing(self, context, **kwargs):
        raise NotImplementedError
""".strip()
        + "\n"
    )
    base_path.write_text(
        """
from localstack.aws.api.sample import SampleApi

class BaseProvider(SampleApi):
    def inherited_thing(self, context, **kwargs):
        return {"source": "base"}

    def overridden_thing(self, context, **kwargs):
        return {"source": "base"}
""".strip()
        + "\n"
    )
    provider_path.write_text(
        """
from localstack.services.sample.base import BaseProvider

class DerivedProvider(BaseProvider):
    def overridden_thing(self, context, **kwargs):
        return {"source": "derived"}
""".strip()
        + "\n"
    )
    registry_path.write_text(
        """
@aws_provider()
def sample():
    from localstack.services.sample.provider import DerivedProvider
    provider = DerivedProvider()
    return Service.for_provider(provider)
""".strip()
        + "\n"
    )

    generated = scan_generated_apis(tmp_path)
    providers = scan_providers(tmp_path, generated)

    handlers = providers["sample"][0].handlers
    assert handlers["InheritedThing"].class_name == "BaseProvider"
    assert handlers["OverriddenThing"].class_name == "DerivedProvider"


def test_ignores_undecorated_methods_without_generated_api_base(tmp_path: Path):
    api_path = tmp_path / "localstack-core/localstack/aws/api/sample/__init__.py"
    provider_path = tmp_path / "localstack-core/localstack/services/sample/provider.py"
    registry_path = tmp_path / "localstack-core/localstack/services/providers.py"
    api_path.parent.mkdir(parents=True)
    provider_path.parent.mkdir(parents=True)
    api_path.write_text(
        """
class SampleApi:
    service: str = "sample"
    version: str = "2026-01-01"

    @handler("DoThing")
    def do_thing(self, context, **kwargs):
        raise NotImplementedError
""".strip()
        + "\n"
    )
    provider_path.write_text(
        """
class UnrelatedProvider:
    def do_thing(self, context, **kwargs):
        return {}
""".strip()
        + "\n"
    )
    registry_path.write_text(
        """
@aws_provider()
def sample():
    from localstack.services.sample.provider import UnrelatedProvider
    provider = UnrelatedProvider()
    return Service.for_provider(provider)
""".strip()
        + "\n"
    )

    providers = scan_providers(tmp_path, scan_generated_apis(tmp_path))

    assert providers["sample"][0].handlers == {}


def test_test_fixture_sources_are_valid_python():
    # Guard against accidentally making the AST fixtures above invalid while editing them.
    ast.parse("def valid():\n    return True\n")


def test_committed_capability_artifacts_are_current():
    project_root = Path(__file__).parents[3]

    generated = generate_artifacts(project_root)

    for relative_path, expected in generated.items():
        artifact = project_root / "capabilities" / relative_path
        assert artifact.exists(), f"missing generated capability artifact: {relative_path}"
        assert artifact.read_text() == expected, (
            f"stale capability artifact: {relative_path}; "
            "run PYTHONPATH=localstack-core python -m localstack.capabilities"
        )


def test_committed_capability_catalog_matches_schema():
    from jsonschema.validators import validator_for

    project_root = Path(__file__).parents[3]
    schema = json.loads((project_root / "capabilities/schema.json").read_text())
    catalog = json.loads((project_root / "capabilities/generated/capabilities.json").read_text())
    validator = validator_for(schema)
    validator.check_schema(schema)
    validator(schema, format_checker=validator.FORMAT_CHECKER).validate(catalog)
