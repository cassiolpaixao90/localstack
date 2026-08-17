import importlib.util
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[3]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "generate_aws_feature_gap_report.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_aws_feature_gap_report", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_feature_gap_report_is_current_and_exhaustive():
    generator = _load_generator()
    assert generator.main(["--project-root", str(PROJECT_ROOT), "--check"]) == 0

    report = (PROJECT_ROOT / generator.DEFAULT_OUTPUT_PATH).read_text()
    assert "429 servicos" in report
    assert "18,993 operacoes" in report
    assert "1,557 recursos CDK L1" in report
    assert "425 handlers declarados" in report
    assert "97** stubs exatos" in report
    assert "`parity-pass` | 0" in report

    api_catalog = json.loads((PROJECT_ROOT / generator.API_CATALOG_PATH).read_text())
    cdk_map = json.loads((PROJECT_ROOT / generator.CDK_SERVICE_MAP_PATH).read_text())
    for service_name in api_catalog["services"]:
        assert report.count(f"| `{service_name}` |") >= 1
    for service in cdk_map["services"]:
        assert report.count(f"| `{service['module']}` |") >= 1


def test_feature_gap_report_rejects_stale_output(tmp_path):
    generator = _load_generator()
    output = tmp_path / "report.md"
    output.write_text("stale\n")

    assert (
        generator.main(
            [
                "--project-root",
                str(PROJECT_ROOT),
                "--output",
                str(output),
                "--check",
            ]
        )
        == 1
    )
