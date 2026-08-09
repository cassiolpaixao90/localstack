import hashlib
import json
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).parents[3]
MANIFEST_PATH = PROJECT_ROOT / "capabilities/cdk/compatibility.json"
SCHEMA_PATH = PROJECT_ROOT / "capabilities/cdk/compatibility.schema.json"
STABLE_AWS_CDK_LANGUAGES = {
    "csharp",
    "go",
    "java",
    "javascript",
    "python",
    "typescript",
}


def _load(path: Path):
    return json.loads(path.read_text())


def _sha256(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def test_cdk_compatibility_manifest_matches_closed_schema():
    from jsonschema.validators import validator_for

    schema = _load(SCHEMA_PATH)
    manifest = _load(MANIFEST_PATH)
    validator = validator_for(schema)

    validator.check_schema(schema)
    validator(schema, format_checker=validator.FORMAT_CHECKER).validate(manifest)


def test_cdk_compatibility_manifest_requires_every_stable_binding():
    manifest = _load(MANIFEST_PATH)
    languages = {entry["id"]: entry for entry in manifest["languages"]}

    assert set(languages) == STABLE_AWS_CDK_LANGUAGES
    assert all(entry["official_stability"] == "stable" for entry in languages.values())
    assert all(entry["support_gate"] == "required" for entry in languages.values())
    assert manifest["policy"]["new_stable_bindings"] == "automatically-required"


def test_cdk_manifest_identity_collections_are_unique_and_ordered():
    manifest = _load(MANIFEST_PATH)

    for collection, key in (
        (manifest["sources"], "id"),
        (manifest["languages"], "id"),
        (manifest["capabilities"], "id"),
    ):
        values = [entry[key] for entry in collection]
        assert values == sorted(values)
        assert len(values) == len(set(values))

    source_uris = [entry["uri"] for entry in manifest["sources"]]
    assert len(source_uris) == len(set(source_uris))

    templates = manifest["toolchain"]["bootstrap"]["observed_templates"]
    versions = [entry["version"] for entry in templates]
    paths = [entry["path"] for entry in templates]
    assert versions == sorted(versions)
    assert len(versions) == len(set(versions))
    assert len(paths) == len(set(paths))


def test_cdk_compatibility_manifest_does_not_overclaim_current_cli_support():
    manifest = _load(MANIFEST_PATH)
    forbidden = {"cli-pass", "parity-pass"}

    assert manifest["current_evidence"]["real_cli_exercised"] is False
    assert manifest["current_evidence"]["cloud_assembly_produced"] is False
    assert manifest["toolchain"]["cdk_cli"] == {
        "minimum": None,
        "pinned": None,
        "tested": [],
    }
    assert not forbidden.intersection(
        capability["status"] for capability in manifest["capabilities"]
    )


def test_cdk_launcher_process_boundary_is_explicit():
    manifest = _load(MANIFEST_PATH)

    assert manifest["launcher"]["process_supervision"] == {
        "platform": "posix",
        "boundary": "process-group",
        "detached_descendants": "not-contained",
    }
    assert "process-tree-timeout" not in manifest["launcher"]["safety"]


def test_cdk_compatibility_manifest_digest_and_local_evidence_are_current():
    manifest = _load(MANIFEST_PATH)
    payload = dict(manifest)
    digest = payload.pop("manifest_sha256")

    assert digest == _sha256(payload)
    evidence_paths = set(manifest["current_evidence"]["local_paths"])
    for capability in manifest["capabilities"]:
        evidence_paths.update(capability["evidence"])
    for relative_path in evidence_paths:
        path = Path(relative_path)
        assert not path.is_absolute() and ".." not in path.parts, relative_path
        assert (PROJECT_ROOT / path).exists(), relative_path


def test_cdk_bootstrap_template_digests_are_current():
    manifest = _load(MANIFEST_PATH)

    for template in manifest["toolchain"]["bootstrap"]["observed_templates"]:
        content = (PROJECT_ROOT / template["path"]).read_bytes()
        assert template["sha256"] == f"sha256:{hashlib.sha256(content).hexdigest()}"


def test_latest_cdk_bootstrap_template_is_byte_exact_and_pinned():
    manifest = _load(MANIFEST_PATH)
    sources = {source["id"]: source for source in manifest["sources"]}
    latest = manifest["toolchain"]["bootstrap"]["observed_templates"][-1]

    assert latest == {
        "version": 32,
        "path": "tests/aws/templates/cdk_bootstrap_v32.yaml",
        "sha256": "sha256:a484ad768d3446874161044d986bec096e201a54037c8ce93ed5a0d215e1dd25",
        "source_id": "aws-cdk-bootstrap-v32-template",
        "upstream_revision": "6551740894bf096065331647097c1617e9e4f988",
        "retrieved_at": "2026-08-08",
        "byte_exact": True,
    }
    assert sources[latest["source_id"]] == {
        "id": "aws-cdk-bootstrap-v32-template",
        "uri": "https://raw.githubusercontent.com/aws/aws-cdk-cli/6551740894bf096065331647097c1617e9e4f988/packages/aws-cdk/lib/api/bootstrap/bootstrap-template.yaml",
        "retrieved_at": "2026-08-08",
        "claim": "byte-exact official bootstrap template version 32",
        "license": "Apache-2.0",
        "license_uri": "https://raw.githubusercontent.com/aws/aws-cdk-cli/6551740894bf096065331647097c1617e9e4f988/packages/aws-cdk/LICENSE",
        "license_sha256": "sha256:cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
        "local_license_path": "capabilities/cdk/licenses/aws-cdk-cli-LICENSE",
        "upstream_notice_uri": "https://raw.githubusercontent.com/aws/aws-cdk-cli/6551740894bf096065331647097c1617e9e4f988/packages/aws-cdk/NOTICE",
        "upstream_notice_sha256": "sha256:efec97c75d9e6fdad4725c6d9c386f3b2c73008d88245eea51bb842ee07c7592",
        "local_attribution_path": "NOTICE",
    }

    source = sources[latest["source_id"]]
    for field in ("local_license_path", "local_attribution_path"):
        path = Path(source[field])
        assert not path.is_absolute() and ".." not in path.parts
        assert (PROJECT_ROOT / path).is_file()

    license_content = (PROJECT_ROOT / source["local_license_path"]).read_bytes()
    assert source["license_sha256"] == f"sha256:{hashlib.sha256(license_content).hexdigest()}"
    notice = (PROJECT_ROOT / source["local_attribution_path"]).read_text()
    assert latest["path"] in notice
    assert "Copyright 2018-2025 Amazon.com, Inc. or its affiliates. All Rights Reserved." in notice
    assert latest["upstream_revision"] in notice

    template = yaml.safe_load((PROJECT_ROOT / latest["path"]).read_text())
    assert template["Resources"]["CdkBootstrapVersion"]["Properties"]["Value"] == "32"
    assert template["Outputs"]["BootstrapVersion"]["Value"] == "32"
