from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from tests.aws.cli.test_cdk_cli_python_synth import (
    APP_PATH,
    EXPECTED_ASSEMBLY_FILES,
    PINNED_PYTHON_PACKAGES,
    _assembly_inventory,
    _expected_tree,
    _load_assembly_json,
    _load_pinned_assembly_schema,
    _python_app_command,
    _validate_assembly_reference,
)

PROJECT_ROOT = Path(__file__).parents[3]


def test_python_synth_uses_existing_exact_package_pins_and_default_synthesizer():
    requirements = set((PROJECT_ROOT / "requirements-test.txt").read_text().splitlines())

    assert {
        f"{distribution}=={version}" for distribution, version in PINNED_PYTHON_PACKAGES.items()
    } <= requirements
    app = APP_PATH.read_text()
    assert "BootstraplessSynthesizer" not in app
    assert 'Stack(app, "SynthStack")' in app
    assert 'aws_sqs.CfnQueue(stack, "Queue")' in app


def test_python_synth_pinned_cloud_assembly_schema_is_valid():
    schema = _load_pinned_assembly_schema()

    Draft7Validator.check_schema(schema)


def test_python_synth_json_and_inventory_reject_ambiguous_files(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"version":"first","version":"second"}')
    nested = tmp_path / "nested"
    nested.mkdir()

    with pytest.raises(ValueError, match="bounded valid JSON"):
        _load_assembly_json(duplicate)
    with pytest.raises(ValueError, match="regular top-level files"):
        _assembly_inventory(tmp_path)


def test_python_synth_rejects_references_outside_the_assembly(tmp_path):
    assembly = tmp_path / "assembly"
    assembly.mkdir()
    template = assembly / "SynthStack.template.json"
    template.write_text("{}")
    inventory = _assembly_inventory(assembly)

    _validate_assembly_reference(assembly, inventory, template.name)
    for reference in ("../SynthStack.template.json", "/etc/passwd", "missing.json"):
        with pytest.raises(ValueError, match="Cloud Assembly file reference"):
            _validate_assembly_reference(assembly, inventory, reference)


def test_python_synth_app_command_is_shell_quoted_and_tree_is_closed(tmp_path):
    python = tmp_path / "python with spaces"
    app = tmp_path / "app with spaces.py"
    python.write_text("")
    app.write_text("")

    assert _python_app_command(python.resolve(), app.resolve()) == (
        f"'{python.resolve()}' -I -B '{app.resolve()}'"
    )
    tree = _expected_tree()
    assert set(tree["tree"]["children"]) == {"SynthStack", "Tree"}
    assert set(tree["tree"]["children"]["SynthStack"]["children"]) == {
        "BootstrapVersion",
        "CheckBootstrapVersion",
        "Queue",
    }
    assert EXPECTED_ASSEMBLY_FILES == {
        "SynthStack.assets.json",
        "SynthStack.template.json",
        "cdk.out",
        "manifest.json",
        "tree.json",
    }
