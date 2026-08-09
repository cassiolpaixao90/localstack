import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from jsonschema.exceptions import ValidationError

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

    for mutation in (
        lambda value: value["current_evidence"].update(real_cli_exercised=False),
        lambda value: value["current_evidence"].update(real_cli_scenario_ids=[]),
        lambda value: value["execution_scenarios"][0].update(artifact_path="../../etc/passwd"),
        lambda value: value["execution_scenarios"][0].update(attestation_path="/etc/passwd"),
        lambda value: value["execution_scenarios"][0]["toolchain"].update(source_bootstrap=28),
        lambda value: value["execution_scenarios"][1]["toolchain"].pop("source_bootstrap"),
        lambda value: value["execution_scenarios"][1].update(
            artifact_path=value["execution_scenarios"][0]["artifact_path"]
        ),
        lambda value: value["execution_scenarios"][1].update(
            limitations=[
                "no-bootstrap-deploy",
                "no-cloud-assembly",
                "no-language-binding",
                "no-aws-differential",
            ]
        ),
    ):
        invalid = copy.deepcopy(manifest)
        mutation(invalid)
        with pytest.raises(ValidationError):
            validator(schema, format_checker=validator.FORMAT_CHECKER).validate(invalid)


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
        (manifest["execution_scenarios"], "id"),
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


def test_cdk_compatibility_manifest_promotes_only_the_language_neutral_cli_scenario():
    manifest = _load(MANIFEST_PATH)
    forbidden = {"cli-pass", "parity-pass"}

    assert manifest["current_evidence"]["real_cli_exercised"] is True
    assert manifest["current_evidence"]["api_construct_language"] == "python"
    assert manifest["current_evidence"]["real_cli_scenario_ids"] == [
        "bootstrap-show-template-v32",
        "bootstrap-upgrade-v28-v32",
    ]
    assert manifest["current_evidence"]["real_cli_scenario_ids"] == [
        scenario["id"] for scenario in manifest["execution_scenarios"]
    ]
    assert manifest["current_evidence"]["cloud_assembly_produced"] is False
    assert manifest["toolchain"]["cdk_cli"] == {
        "minimum": None,
        "pinned": "2.1135.1",
        "tested": ["2.1135.1"],
    }
    assert manifest["toolchain"]["node"] == {
        "minimum": "22.0.0",
        "pinned": "22.23.2",
        "tested": ["22.23.2"],
    }
    assert not forbidden.intersection(
        capability["status"] for capability in manifest["capabilities"]
    )
    bootstrap = next(
        capability for capability in manifest["capabilities"] if capability["id"] == "bootstrap"
    )
    assert bootstrap["status"] == "api-simulated"
    assert bootstrap["languages"] == []
    assert bootstrap["gaps"] == ["clean-bootstrap-create-cli-not-run", "validation-stale"]


def test_cdk_cli_execution_scenario_is_content_addressed_and_attested():
    from jsonschema.validators import validator_for
    from tests.aws.cli.execution_evidence import read_regular_bounded, validate_aggregate_evidence

    manifest = _load(MANIFEST_PATH)
    scenario = manifest["execution_scenarios"][0]
    for field in ("artifact_path", "attestation_path"):
        path = Path(scenario[field])
        assert not path.is_absolute() and ".." not in path.parts
        assert path.parent.name == str(scenario["run_id"])
    evidence_path = PROJECT_ROOT / scenario["artifact_path"]
    attestation_path = PROJECT_ROOT / scenario["attestation_path"]
    evidence_bytes = read_regular_bounded(evidence_path, 64 * 1024)
    attestation_bytes = read_regular_bounded(attestation_path, 64 * 1024)
    try:
        evidence = json.loads(evidence_bytes)
        attestation = json.loads(attestation_bytes)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise AssertionError("retained CDK evidence is not bounded valid JSON") from error
    assert set(evidence_path.parent.iterdir()) == {evidence_path, attestation_path}

    schema = _load(PROJECT_ROOT / "capabilities/cdk/execution-evidence.schema.json")
    validator = validator_for(schema)
    validator.check_schema(schema)
    validator(schema, format_checker=validator.FORMAT_CHECKER).validate(evidence)
    validate_aggregate_evidence(evidence)

    assert scenario == {
        "id": "bootstrap-show-template-v32",
        "status": "cli-pass",
        "construct_language": None,
        "platforms": ["linux-amd64", "linux-arm64"],
        "source_commit": "1a23acd9b65fef0ef5a944bd4b412f9af9348665",
        "run_id": 31288954038,
        "run_attempt": 1,
        "artifact_path": (
            "capabilities/cdk/evidence/runs/31288954038/cdk-cli-execution-evidence.json"
        ),
        "artifact_sha256": (
            "sha256:3f54ed02dcd2fcd7518e9cfe40385677e7b6664997da6ad3d119f4671ac2ac18"
        ),
        "evidence_id": "sha256:409f6047952330a1467384f8eafaa173408b841cf6671e2cc3811ed02fb7df65",
        "claim_id": "sha256:cf49ba326023570fa74504ca8afba4771809b77534e57dedebf54bdb7d26308a",
        "attestation_path": (
            "capabilities/cdk/evidence/runs/31288954038/cdk-cli-execution-evidence.sigstore.json"
        ),
        "attestation_sha256": (
            "sha256:e91102cd43e17d55a12bc3ed4df8dd3575a8ad1ca2390cacbb6342876972900e"
        ),
        "toolchain": {"node": "22.23.2", "cdk_cli": "2.1135.1", "bootstrap": 32},
        "limitations": [
            "no-bootstrap-deploy",
            "no-cloud-assembly",
            "no-language-binding",
            "no-aws-differential",
        ],
    }
    assert scenario["artifact_sha256"] == f"sha256:{hashlib.sha256(evidence_bytes).hexdigest()}"
    assert scenario["attestation_sha256"] == (
        f"sha256:{hashlib.sha256(attestation_bytes).hexdigest()}"
    )
    assert evidence["evidence_id"] == scenario["evidence_id"]
    assert evidence["claim_id"] == scenario["claim_id"]
    assert evidence["subject"]["commit_sha"] == scenario["source_commit"]
    assert evidence["run"]["run_id"] == scenario["run_id"]
    assert evidence["run"]["run_attempt"] == scenario["run_attempt"]
    assert evidence["toolchain"]["node_version"] == scenario["toolchain"]["node"]
    assert evidence["toolchain"]["cdk_cli_version"] == scenario["toolchain"]["cdk_cli"]
    assert evidence["toolchain"]["bootstrap_version"] == scenario["toolchain"]["bootstrap"]

    envelope = attestation["dsseEnvelope"]
    assert len(envelope["signatures"]) == 1
    assert len(attestation["verificationMaterial"]["tlogEntries"]) == 1
    assert (
        len(attestation["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"]) <= 64
    )
    decoded_payload = base64.b64decode(envelope["payload"], validate=True)
    assert len(decoded_payload) <= 16 * 1024
    statement = json.loads(decoded_payload)
    assert statement["subject"] == [
        {
            "name": "cdk-cli-execution-evidence.json",
            "digest": {"sha256": scenario["artifact_sha256"].removeprefix("sha256:")},
        }
    ]
    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
    definition = statement["predicate"]["buildDefinition"]
    assert definition["externalParameters"]["workflow"] == {
        "ref": "refs/heads/main",
        "repository": "https://github.com/cassiolpaixao90/localstack",
        "path": ".github/workflows/cdk-cli-blackbox.yml",
    }
    assert definition["resolvedDependencies"] == [
        {
            "uri": "git+https://github.com/cassiolpaixao90/localstack@refs/heads/main",
            "digest": {"gitCommit": scenario["source_commit"]},
        }
    ]
    predicate = statement["predicate"]
    assert predicate["buildDefinition"]["internalParameters"]["github"]["event_name"] == "push"
    assert (
        predicate["buildDefinition"]["internalParameters"]["github"]["runner_environment"]
        == "github-hosted"
    )
    assert predicate["runDetails"]["metadata"]["invocationId"] == (
        "https://github.com/cassiolpaixao90/localstack/actions/runs/31288954038/attempts/1"
    )


def test_cdk_bootstrap_upgrade_scenario_is_content_addressed_and_attested():
    from jsonschema.validators import validator_for
    from tests.aws.cli.bootstrap_upgrade_execution_evidence import (
        validate_aggregate_evidence,
    )
    from tests.aws.cli.execution_evidence import read_regular_bounded

    manifest = _load(MANIFEST_PATH)
    scenario = manifest["execution_scenarios"][1]
    assert scenario == {
        "id": "bootstrap-upgrade-v28-v32",
        "status": "cli-pass",
        "construct_language": None,
        "platforms": ["linux-amd64", "linux-arm64"],
        "source_commit": "c4a933343b6be315208edd68bb4827650275fcc6",
        "run_id": 31305122966,
        "run_attempt": 1,
        "artifact_path": (
            "capabilities/cdk/evidence/runs/31305122966/"
            "cdk-bootstrap-upgrade-execution-evidence.json"
        ),
        "artifact_sha256": (
            "sha256:580004f04ad53a895a263d0433a47860ff88456749fcab0ef3e7cced17989e82"
        ),
        "evidence_id": "sha256:db8d467417dd799587642a7a0fb574b21fe5076e3082771ef833d289ea5f2838",
        "claim_id": "sha256:aef3c9925e419b95fb67db8bed66185dfa8790ef5ca0c9ad0e2dd41d9b0448f1",
        "attestation_path": (
            "capabilities/cdk/evidence/runs/31305122966/"
            "cdk-bootstrap-upgrade-execution-evidence.sigstore.json"
        ),
        "attestation_sha256": (
            "sha256:5114b0affe0362c980a9984fe9ac38e15bb64703b8fb0a46a3f1263ccb9e55e8"
        ),
        "toolchain": {
            "node": "22.23.2",
            "cdk_cli": "2.1135.1",
            "source_bootstrap": 28,
            "bootstrap": 32,
        },
        "limitations": [
            "no-clean-bootstrap-create",
            "no-cloud-assembly",
            "no-language-binding",
            "no-aws-differential",
        ],
    }
    for field in ("artifact_path", "attestation_path"):
        path = Path(scenario[field])
        assert not path.is_absolute() and ".." not in path.parts
        assert path.parent.name == str(scenario["run_id"])

    evidence_path = PROJECT_ROOT / scenario["artifact_path"]
    attestation_path = PROJECT_ROOT / scenario["attestation_path"]
    evidence_bytes = read_regular_bounded(evidence_path, 64 * 1024)
    attestation_bytes = read_regular_bounded(attestation_path, 64 * 1024)
    assert set(evidence_path.parent.iterdir()) == {evidence_path, attestation_path}
    try:
        evidence = json.loads(evidence_bytes)
        attestation = json.loads(attestation_bytes)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise AssertionError("retained CDK upgrade evidence is not bounded valid JSON") from error

    schema = _load(
        PROJECT_ROOT / "capabilities/cdk/bootstrap-upgrade-execution-evidence.schema.json"
    )
    validator = validator_for(schema)
    validator.check_schema(schema)
    validator(schema, format_checker=validator.FORMAT_CHECKER).validate(evidence)
    validate_aggregate_evidence(evidence)

    assert scenario["artifact_sha256"] == f"sha256:{hashlib.sha256(evidence_bytes).hexdigest()}"
    assert scenario["attestation_sha256"] == (
        f"sha256:{hashlib.sha256(attestation_bytes).hexdigest()}"
    )
    assert evidence["evidence_id"] == scenario["evidence_id"]
    assert evidence["claim_id"] == scenario["claim_id"]
    assert evidence["subject"] == {
        "repository": "cassiolpaixao90/localstack",
        "commit_sha": scenario["source_commit"],
        "ref": "refs/heads/main",
    }
    assert evidence["run"] == {
        "provider": "github-actions",
        "workflow_path": ".github/workflows/cdk-cli-blackbox.yml",
        "run_id": scenario["run_id"],
        "run_attempt": scenario["run_attempt"],
        "event": "push",
    }
    assert evidence["scenario"] == {
        "id": scenario["id"],
        "result": "cli-pass",
        "construct_language": None,
        "cloud_assembly_produced": False,
        "resource_deployment_performed": True,
        "aws_differential": False,
        "seed_mechanism": "cloudformation-api-change-set",
        "target_template_source": "cdk-cli-built-in",
        "cleanup_required": True,
    }
    assert evidence["toolchain"]["node_version"] == scenario["toolchain"]["node"]
    assert evidence["toolchain"]["cdk_cli_version"] == scenario["toolchain"]["cdk_cli"]
    assert evidence["toolchain"]["source_bootstrap_version"] == 28
    assert evidence["toolchain"]["target_bootstrap_version"] == 32
    assert evidence["promotion"]["eligible"] is False

    envelope = attestation["dsseEnvelope"]
    assert len(envelope["signatures"]) == 1
    assert len(attestation["verificationMaterial"]["tlogEntries"]) == 1
    proof = attestation["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
    assert len(proof["hashes"]) <= 64
    decoded_payload = base64.b64decode(envelope["payload"], validate=True)
    assert len(decoded_payload) <= 16 * 1024
    statement = json.loads(decoded_payload)
    assert statement["subject"] == [
        {
            "name": "cdk-bootstrap-upgrade-execution-evidence.json",
            "digest": {"sha256": scenario["artifact_sha256"].removeprefix("sha256:")},
        }
    ]
    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
    definition = statement["predicate"]["buildDefinition"]
    assert definition["externalParameters"]["workflow"] == {
        "ref": "refs/heads/main",
        "repository": "https://github.com/cassiolpaixao90/localstack",
        "path": ".github/workflows/cdk-cli-blackbox.yml",
    }
    assert definition["resolvedDependencies"] == [
        {
            "uri": "git+https://github.com/cassiolpaixao90/localstack@refs/heads/main",
            "digest": {"gitCommit": scenario["source_commit"]},
        }
    ]
    predicate = statement["predicate"]
    github = predicate["buildDefinition"]["internalParameters"]["github"]
    assert github["event_name"] == "push"
    assert github["runner_environment"] == "github-hosted"
    assert predicate["runDetails"]["metadata"]["invocationId"] == (
        "https://github.com/cassiolpaixao90/localstack/actions/runs/31305122966/attempts/1"
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
