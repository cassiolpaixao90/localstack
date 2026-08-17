import ast
import copy
import importlib
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[3]
V1_SCHEMA_PATH = PROJECT_ROOT / "capabilities/cdk/python-synth-execution-evidence.schema.json"
V2_SCHEMA_PATH = PROJECT_ROOT / "capabilities/cdk/python-synth-execution-evidence-v2.schema.json"

_SHARED_CONSTANTS = (
    "ARGV_CONTRACT",
    "ASSEMBLY_CONTRACT",
    "ASSEMBLY_FILES",
    "CLEANUP_CONTRACT",
    "EXPECTED_ARCHITECTURES",
    "EXPECTED_PLATFORMS",
    "MAX_ASSEMBLY_FILE_BYTES",
    "MAX_ASSEMBLY_TOTAL_BYTES",
    "MAX_EVIDENCE_BYTES",
    "MAX_OBSERVATION_BYTES",
    "NPM_INTEGRITY",
    "PINNED_PYTHON_PACKAGES",
    "PINNED_TOOLCHAIN",
    "SCENARIO",
    "UTC",
    "WORKFLOW_PATH",
)
_SHARED_FUNCTIONS = (
    "_add_run_arguments",
    "_aggregate_command",
    "_expected_argv",
    "_lane_command",
    "_pinned_input_digests",
    "_validate_assembly",
    "_validate_command",
    "_validate_platform",
    "_validate_result",
    "_validate_run",
    "_validate_toolchain",
    "_validate_utc",
    "_value_digest",
    "main",
)
_DIVERGENT_CONSTANTS = {"PINNED_INPUTS", "PROMOTION_BLOCKERS", "SCHEMA_VERSION"}
_V1_INPUTS = {
    "capabilities/cdk/python-synth-execution-evidence.schema.json",
    "tests/aws/cli/python_synth_execution_evidence.py",
}
_V2_INPUTS = {
    "capabilities/cdk/python-synth-execution-evidence-v2.schema.json",
    "tests/aws/cli/python-synth-requirements.lock",
    "tests/aws/cli/python-synth-wheel-origins.json",
    "tests/aws/cli/python_synth_execution_evidence_v2.py",
    "tests/aws/cli/python_synth_toolchain.py",
}
_SUPPLY_ONLY_IFS = {
    "lanes[0]['supply_chain']['contract'] != lanes[1]['supply_chain']['contract']": (
        "raise ValueError('Python synth lanes disagree on the supply chain contract')"
    ),
    "lanes[0]['supply_chain']['installed_tree_sha256'] != "
    "lanes[1]['supply_chain']['installed_tree_sha256']": (
        "raise ValueError('Python synth lanes disagree on the installed environment')"
    ),
}
_SUPPLY_SETS = {
    "_validate_observation": frozenset(
        {
            "schema_version",
            "record_type",
            "observation_id",
            "scenario",
            "toolchain",
            "supply_chain",
            "run",
            "platform",
            "command",
            "assembly",
            "result",
            "observed_at",
        }
    ),
    "_validate_lane_receipt": frozenset(
        {
            "schema_version",
            "record_type",
            "receipt_id",
            "scenario",
            "toolchain",
            "supply_chain",
            "run",
            "platform",
            "command",
            "assembly",
            "result",
            "junit",
            "isolation",
            "cleanup",
            "observed_at",
            "completed_at",
        }
    ),
}
_SUPPLY_DICTS = {
    "create_observation": (_SUPPLY_SETS["_validate_observation"], "supply_chain"),
    "create_lane_receipt": (
        _SUPPLY_SETS["_validate_lane_receipt"],
        "copy.deepcopy(observation['supply_chain'])",
    ),
    "_claim_id": (
        frozenset(
            {
                "scenario",
                "toolchain",
                "verification_contract",
                "harness",
                "command",
                "assembly",
                "supply_chain",
                "platforms",
            }
        ),
        "[lane['supply_chain'] for lane in evidence['lanes']]",
    ),
    "build_aggregate_evidence": (
        frozenset({"assembly", "cleanup", "supply_chain"}),
        "copy.deepcopy(SUPPLY_CHAIN_CONTRACT)",
    ),
    "validate_aggregate_evidence": (
        frozenset({"assembly", "cleanup", "supply_chain"}),
        "SUPPLY_CHAIN_CONTRACT",
    ),
}
_SUPPLY_VALIDATIONS = {
    "_validate_observation": "_validate_supply_chain(observation['supply_chain'])",
    "_validate_lane_receipt": "_validate_supply_chain(receipt['supply_chain'])",
}


def _module_contract(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    module = ast.parse(path.read_text())
    functions = {
        node.name: ast.dump(node, include_attributes=False)
        for node in module.body
        if isinstance(node, ast.FunctionDef)
    }
    constants = {
        node.targets[0].id: ast.dump(node.value, include_attributes=False)
        for node in module.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    }
    return functions, constants


class _StripSupplyChain(ast.NodeTransformer):
    def __init__(self):
        self._current_function = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        previous_function = self._current_function
        self._current_function = node.name
        node = self.generic_visit(node)
        self._current_function = previous_function
        if node.name == "create_observation":
            keyword_arguments = [
                (argument, default)
                for argument, default in zip(
                    node.args.kwonlyargs, node.args.kw_defaults, strict=True
                )
                if argument.arg != "toolchain_manifest_path"
            ]
            node.args.kwonlyargs = [argument for argument, _ in keyword_arguments]
            node.args.kw_defaults = [default for _, default in keyword_arguments]
        return node

    def visit_Expr(self, node: ast.Expr):
        if ast.unparse(node) == _SUPPLY_VALIDATIONS.get(self._current_function):
            return None
        return self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if self._current_function == "create_observation" and ast.unparse(node) == (
            "supply_chain = _supply_chain_from_manifest(load_toolchain_manifest(toolchain_manifest_path))"
        ):
            return None
        return self.generic_visit(node)

    def visit_If(self, node: ast.If):
        expected_raise = _SUPPLY_ONLY_IFS.get(ast.unparse(node.test))
        if (
            self._current_function in {"build_aggregate_evidence", "validate_aggregate_evidence"}
            and expected_raise is not None
            and len(node.body) == 1
            and ast.unparse(node.body[0]) == expected_raise
            and not node.orelse
        ):
            return None
        return self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict):
        node = self.generic_visit(node)
        pairs = list(zip(node.keys, node.values, strict=True))
        expected = _SUPPLY_DICTS.get(self._current_function)
        keys = [key.value for key, _ in pairs if isinstance(key, ast.Constant)]
        if (
            expected is not None
            and len(keys) == len(pairs) == len(expected[0])
            and frozenset(keys) == expected[0]
        ):
            pairs = [
                (key, value)
                for key, value in pairs
                if not (key.value == "supply_chain" and ast.unparse(value) == expected[1])
            ]
        node.keys = [key for key, _ in pairs]
        node.values = [value for _, value in pairs]
        return node

    def visit_Set(self, node: ast.Set):
        node = self.generic_visit(node)
        expected = _SUPPLY_SETS.get(self._current_function)
        values = [element.value for element in node.elts if isinstance(element, ast.Constant)]
        if expected is not None and len(values) == len(node.elts) == len(expected):
            if frozenset(values) == expected:
                node.elts = [element for element in node.elts if element.value != "supply_chain"]
        return node


def _normalized_function_contract(path: Path, *, strip_supply_chain: bool) -> dict[str, str]:
    return _normalized_source_contract(path.read_text(), strip_supply_chain=strip_supply_chain)


def _normalized_source_contract(source: str, *, strip_supply_chain: bool) -> dict[str, str]:
    module = ast.parse(source)
    result = {}
    for node in module.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if strip_supply_chain:
            node = _StripSupplyChain().visit(node)
        result[node.name] = ast.dump(node, include_attributes=False)
    return result


def _sort_required(value: object) -> None:
    if isinstance(value, dict):
        if isinstance(value.get("required"), list):
            value["required"].sort()
        for child in value.values():
            _sort_required(child)
    elif isinstance(value, list):
        for child in value:
            _sort_required(child)


def _normalize_v2_schema_to_v1(schema: dict) -> dict:
    result = copy.deepcopy(schema)
    result["$id"] = "https://localstack.cloud/schemas/cdk-python-synth-execution-evidence-v1.json"
    result["properties"]["schema_version"] = {"const": 1}

    result["$defs"].pop("supplyChain")
    result["$defs"].pop("supplyChainContract")
    lane_receipt = result["$defs"]["laneReceipt"]
    lane_receipt["properties"]["schema_version"] = {"const": 1}
    lane_receipt["properties"].pop("supply_chain")
    lane_receipt["required"].remove("supply_chain")

    verification = result["properties"]["verification_contract"]
    verification["properties"].pop("supply_chain")
    verification["required"].remove("supply_chain")
    result["properties"]["promotion"]["properties"]["blockers"]["const"] = [
        "not-reviewed-for-promotion",
        "python-distribution-origin-not-attested",
        "no-deploy",
        "no-aws-differential",
        "only-python",
    ]

    inputs = result["properties"]["harness"]["properties"]["input_sha256"]
    input_properties = inputs["properties"]
    input_properties["capabilities/cdk/python-synth-execution-evidence.schema.json"] = (
        input_properties.pop("capabilities/cdk/python-synth-execution-evidence-v2.schema.json")
    )
    input_properties["tests/aws/cli/python_synth_execution_evidence.py"] = input_properties.pop(
        "tests/aws/cli/python_synth_execution_evidence_v2.py"
    )
    for name in _V2_INPUTS - {
        "capabilities/cdk/python-synth-execution-evidence-v2.schema.json",
        "tests/aws/cli/python_synth_execution_evidence_v2.py",
    }:
        input_properties.pop(name)
    inputs["required"] = [name for name in inputs["required"] if name not in _V2_INPUTS]
    inputs["required"].extend(_V1_INPUTS)
    _sort_required(result)
    return result


def test_v2_delta_from_v1_is_exactly_the_supply_chain_contract():
    import_probe = (
        "import sys;"
        f"sys.path.insert(0, {str(PROJECT_ROOT)!r});"
        "before=set(sys.modules);"
        "import tests.aws.cli.python_synth_execution_evidence;"
        "import tests.aws.cli.python_synth_execution_evidence_v2;"
        "loaded=set(sys.modules)-before;"
        "assert not any(n=='jsii' or n.startswith(('jsii.','aws_cdk.')) for n in loaded)"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", import_probe],
        check=False,
        timeout=10,
        stdin=subprocess.DEVNULL,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")

    evidence_v1 = importlib.import_module("tests.aws.cli.python_synth_execution_evidence")
    evidence_v2 = importlib.import_module("tests.aws.cli.python_synth_execution_evidence_v2")

    for name in _SHARED_CONSTANTS:
        assert getattr(evidence_v2, name) == getattr(evidence_v1, name)
    assert evidence_v1.SCHEMA_VERSION == 1
    assert evidence_v2.SCHEMA_VERSION == 2
    assert set(evidence_v1.PROMOTION_BLOCKERS) - set(evidence_v2.PROMOTION_BLOCKERS) == {
        "python-distribution-origin-not-attested"
    }
    assert set(evidence_v2.PROMOTION_BLOCKERS) <= set(evidence_v1.PROMOTION_BLOCKERS)
    assert set(evidence_v1.PINNED_INPUTS) - set(evidence_v2.PINNED_INPUTS) == _V1_INPUTS
    assert set(evidence_v2.PINNED_INPUTS) - set(evidence_v1.PINNED_INPUTS) == _V2_INPUTS

    v1_functions, v1_constants = _module_contract(Path(evidence_v1.__file__))
    v2_functions, v2_constants = _module_contract(Path(evidence_v2.__file__))
    assert set(v1_functions) - set(v2_functions) == set()
    assert set(v2_functions) - set(v1_functions) == {
        "_supply_chain_from_manifest",
        "_validate_supply_chain",
    }
    normalized_v1 = _normalized_function_contract(
        Path(evidence_v1.__file__), strip_supply_chain=False
    )
    normalized_v2 = _normalized_function_contract(
        Path(evidence_v2.__file__), strip_supply_chain=True
    )
    normalized_v2.pop("_supply_chain_from_manifest")
    normalized_v2.pop("_validate_supply_chain")
    assert normalized_v2 == normalized_v1
    for name in _SHARED_FUNCTIONS:
        assert normalized_v2[name] == normalized_v1[name]
    assert {
        name
        for name in set(v1_constants) & set(v2_constants)
        if v1_constants[name] != v2_constants[name]
    } == _DIVERGENT_CONSTANTS
    assert set(v1_constants) - set(v2_constants) == set()
    assert set(v2_constants) - set(v1_constants) == {"SUPPLY_CHAIN_CONTRACT"}

    v1_schema = json.loads(V1_SCHEMA_PATH.read_bytes())
    v2_schema = json.loads(V2_SCHEMA_PATH.read_bytes())
    _sort_required(v1_schema)
    assert _normalize_v2_schema_to_v1(v2_schema) == v1_schema


def test_supply_chain_normalization_does_not_hide_synth_semantic_drift():
    v1_contract = _normalized_function_contract(
        PROJECT_ROOT / "tests/aws/cli/python_synth_execution_evidence.py",
        strip_supply_chain=False,
    )
    v2_source = (PROJECT_ROOT / "tests/aws/cli/python_synth_execution_evidence_v2.py").read_text()
    mutations = (
        ('"app_sha256": _sha256_bytes(app_bytes),', '"app_sha256": _sha256_bytes(schema_payload),'),
        ('"bytes": len(payload),', '"bytes": 0,'),
        ('"returncode": returncode,', '"returncode": 0,'),
        ('"cleanup": copy.deepcopy(CLEANUP_CONTRACT),', '"cleanup": {},'),
        (
            'if lanes[0]["supply_chain"]["contract"] != lanes[1]["supply_chain"]["contract"]:',
            'if (lanes[0]["supply_chain"]["contract"] '
            '!= lanes[1]["supply_chain"]["contract"] '
            'or lanes[0]["command"] != lanes[1]["command"]):',
        ),
        (
            '{"repository", "commit_sha", "ref", "event", "workflow_path", "run_id", '
            '"run_attempt"},',
            '{"repository", "commit_sha", "ref", "event", "workflow_path", "run_id", '
            '"run_attempt", "supply_chain"},',
        ),
        (
            '"run": {\n            "repository": repository,',
            '"run": {\n            "supply_chain": supply_chain,\n            "repository": repository,',
        ),
    )
    for current, replacement in mutations:
        assert v2_source.count(current) >= 1
        mutated = v2_source.replace(current, replacement, 1)
        normalized = _normalized_source_contract(mutated, strip_supply_chain=True)
        normalized.pop("_supply_chain_from_manifest")
        normalized.pop("_validate_supply_chain")
        assert normalized != v1_contract
