import copy
import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

import pytest
from tests.aws.cli import python_synth_toolchain as toolchain

PROJECT_ROOT = Path(__file__).parents[3]
REAL_LOCK = PROJECT_ROOT / "tests/aws/cli/python-synth-requirements.lock"
REAL_ORIGINS = PROJECT_ROOT / "tests/aws/cli/python-synth-wheel-origins.json"


def _wheel(project: str, version: str = "1.0") -> tuple[bytes, str]:
    distribution = project.replace("-", "_")
    metadata = f"Metadata-Version: 2.1\nName: {project}\nVersion: {version}\n\n".encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{distribution}-{version}.dist-info/METADATA", metadata)
        archive.writestr(
            f"{distribution}-{version}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: unit-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{distribution}-{version}.dist-info/RECORD", "")
        archive.writestr(f"{distribution}/__init__.py", "")
    return output.getvalue(), hashlib.sha256(metadata).hexdigest()


def _fixture_contract(tmp_path: Path) -> tuple[Path, Path, Path]:
    real = json.loads(REAL_ORIGINS.read_bytes())
    app_names = [item["project"] for item in real["artifacts"] if item["role"] == "application"]
    artifacts = []
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    for name in app_names:
        payload, metadata_sha256 = _wheel(name)
        filename = f"{name.replace('-', '_')}-1.0-py3-none-any.whl"
        (wheelhouse / filename).write_bytes(payload)
        artifacts.append(
            {
                "role": "application",
                "project": name,
                "version": "1.0",
                "filename": filename,
                "url": f"https://files.pythonhosted.org/packages/unit/{filename}",
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "metadata_sha256": metadata_sha256,
                "tags": ["py3-none-any"],
            }
        )
    payload, metadata_sha256 = _wheel("pip")
    filename = "pip-1.0-py3-none-any.whl"
    (wheelhouse / filename).write_bytes(payload)
    artifacts.append(
        {
            "role": "installer",
            "project": "pip",
            "version": "1.0",
            "filename": filename,
            "url": f"https://files.pythonhosted.org/packages/unit/{filename}",
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "metadata_sha256": metadata_sha256,
            "tags": ["py3-none-any"],
        }
    )
    origins = tmp_path / "origins.json"
    origins.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "index_url": "https://pypi.org/simple",
                "roots": list(toolchain.ROOTS),
                "artifacts": artifacts,
            }
        )
    )
    lock = tmp_path / "requirements.lock"
    lock.write_bytes(toolchain._expected_lock(artifacts[:-1]))
    return origins, lock, wheelhouse


def test_real_origins_pin_complete_closure_and_installer():
    contract = toolchain.load_contract()

    assert len(contract["applications"]) == 14
    assert {item["project"] for item in contract["applications"]} == {
        "attrs",
        "aws-cdk-asset-awscli-v1",
        "aws-cdk-asset-node-proxy-agent-v6",
        "aws-cdk-cloud-assembly-schema",
        "aws-cdk-lib",
        "cattrs",
        "constructs",
        "importlib-resources",
        "jsii",
        "publication",
        "python-dateutil",
        "six",
        "typeguard",
        "typing-extensions",
    }
    assert contract["installer"]["project"] == "pip"
    assert contract["installer"]["version"] == "26.0.1"
    assert contract["installer"]["sha256"] == (
        "bdb1b08f4274833d62c1aa29e20907365a2ceb950410df15fc9521bad440122b"
    )
    assert all(
        item["url"].startswith("https://files.pythonhosted.org/") for item in contract["artifacts"]
    )
    assert sum(item["bytes"] for item in contract["artifacts"]) < toolchain.MAX_WHEELHOUSE_BYTES


def test_contract_rejects_top_level_only_or_stale_lock(tmp_path):
    origins, lock, _ = _fixture_contract(tmp_path)
    value = json.loads(origins.read_bytes())
    value["artifacts"] = [
        item
        for item in value["artifacts"]
        if item["role"] == "installer" or item["project"] in toolchain.ROOTS
    ]
    origins.write_text(json.dumps(value))
    with pytest.raises(toolchain.ToolchainError, match="fourteen applications"):
        toolchain.load_contract(origins, lock)

    origins, lock, _ = _fixture_contract(tmp_path / "stale")
    lines = lock.read_text().splitlines()
    lock.write_text("\n".join(lines[:-1]) + "\n")
    with pytest.raises(toolchain.ToolchainError, match="requirements lock"):
        toolchain.load_contract(origins, lock)

    origins, lock, _ = _fixture_contract(tmp_path / "oversized")
    value = json.loads(origins.read_bytes())
    for artifact in value["artifacts"]:
        artifact["bytes"] = toolchain.MAX_WHEEL_BYTES
    origins.write_text(json.dumps(value))
    with pytest.raises(toolchain.ToolchainError, match="declared wheelhouse size"):
        toolchain.load_contract(origins, lock)


def test_contract_rejects_non_official_url_sdist_or_duplicate_project(tmp_path):
    origins, lock, _ = _fixture_contract(tmp_path)
    value = json.loads(origins.read_bytes())
    value["artifacts"][0]["url"] = "https://example.test/attrs.whl"
    origins.write_text(json.dumps(value))
    with pytest.raises(toolchain.ToolchainError, match="direct official"):
        toolchain.load_contract(origins, lock)

    origins, lock, _ = _fixture_contract(tmp_path / "sdist")
    value = json.loads(origins.read_bytes())
    value["artifacts"][0]["filename"] = "attrs-1.0.tar.gz"
    origins.write_text(json.dumps(value))
    with pytest.raises(toolchain.ToolchainError, match="filename"):
        toolchain.load_contract(origins, lock)

    origins, lock, _ = _fixture_contract(tmp_path / "duplicate")
    value = json.loads(origins.read_bytes())
    value["artifacts"][1]["project"] = value["artifacts"][0]["project"]
    origins.write_text(json.dumps(value))
    with pytest.raises(toolchain.ToolchainError, match="duplicate"):
        toolchain.load_contract(origins, lock)


def test_wheelhouse_validation_is_exact_bounded_and_metadata_pinned(tmp_path):
    origins, lock, wheelhouse = _fixture_contract(tmp_path)
    contract = toolchain.load_contract(origins, lock)
    assert len(toolchain.validate_wheelhouse(wheelhouse, contract)) == 15

    target = wheelhouse / contract["applications"][0]["filename"]
    target.write_bytes(target.read_bytes() + b"tamper")
    with pytest.raises(toolchain.ToolchainError, match="wheel bytes"):
        toolchain.validate_wheelhouse(wheelhouse, contract)

    origins, lock, wheelhouse = _fixture_contract(tmp_path / "extra")
    contract = toolchain.load_contract(origins, lock)
    (wheelhouse / "extra.whl").write_bytes(b"extra")
    with pytest.raises(toolchain.ToolchainError, match="inventory"):
        toolchain.validate_wheelhouse(wheelhouse, contract)

    origins, lock, wheelhouse = _fixture_contract(tmp_path / "metadata")
    contract = toolchain.load_contract(origins, lock)
    contract["applications"][0]["metadata_sha256"] = "0" * 64
    with pytest.raises(toolchain.ToolchainError, match="metadata"):
        toolchain.validate_wheelhouse(wheelhouse, contract)


def test_wheelhouse_rejects_symlink_fifo_and_archive_traversal(tmp_path):
    origins, lock, wheelhouse = _fixture_contract(tmp_path)
    contract = toolchain.load_contract(origins, lock)
    artifact = contract["applications"][0]
    target = wheelhouse / artifact["filename"]
    regular = tmp_path / "regular.whl"
    target.replace(regular)
    try:
        target.symlink_to(regular)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(OSError):
        toolchain.validate_wheelhouse(wheelhouse, contract)

    target.unlink()
    os.mkfifo(target)
    with pytest.raises(toolchain.ToolchainError, match="regular file"):
        toolchain.validate_wheelhouse(wheelhouse, contract)

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("../escape", b"x")
        archive.writestr("attrs-1.0.dist-info/METADATA", "Name: attrs\nVersion: 1.0\n")
        archive.writestr("attrs-1.0.dist-info/WHEEL", "Tag: py3-none-any\n")
    artifact = dict(artifact)
    artifact["metadata_sha256"] = hashlib.sha256(b"Name: attrs\nVersion: 1.0\n").hexdigest()
    with pytest.raises(toolchain.ToolchainError, match="unsafe member"):
        toolchain._validate_zip(payload.getvalue(), artifact)


def test_direct_downloader_enforces_size_hash_and_fresh_output(tmp_path, monkeypatch):
    payload = b"wheel-bytes"

    class Response:
        status = 200
        headers = {"Content-Length": str(len(payload))}

        def geturl(self):
            return "https://files.pythonhosted.org/packages/unit/example.whl"

        def read(self, maximum):
            assert maximum == len(payload) + 1
            return payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    class Opener:
        def open(self, request, timeout):
            assert timeout == 15
            return Response()

    monkeypatch.setattr(toolchain.urllib.request, "build_opener", lambda *args: Opener())
    output = tmp_path / "example.whl"
    toolchain._download_one(
        Response().geturl(), output, len(payload), hashlib.sha256(payload).hexdigest()
    )
    assert output.read_bytes() == payload
    with pytest.raises(FileExistsError):
        toolchain._download_one(
            Response().geturl(), output, len(payload), hashlib.sha256(payload).hexdigest()
        )
    with pytest.raises(toolchain.ToolchainError, match="downloaded wheel bytes"):
        toolchain._download_one(Response().geturl(), tmp_path / "bad.whl", len(payload), "0" * 64)


def test_offline_venv_uses_pinned_pip_and_closed_flags_as_non_root(tmp_path, monkeypatch):
    origins, lock, wheelhouse = _fixture_contract(tmp_path)
    contract = toolchain.load_contract(origins, lock)
    base_python = Path(os.path.abspath(os.sys.executable))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if "--report" in argv:
            report = Path(argv[argv.index("--report") + 1])
            report.write_text(
                json.dumps(
                    {
                        "version": "1",
                        "pip_version": contract["installer"]["version"],
                        "install": [
                            {
                                "requested": item["project"] in toolchain.ROOTS,
                                "metadata": {
                                    "name": item["project"],
                                    "version": item["version"],
                                },
                            }
                            for item in contract["applications"]
                        ],
                        "environment": {"python_version": "3.13"},
                    }
                )
            )
        return type("Result", (), {"stdout": b""})()

    installed = [
        {
            "project": item["project"],
            "version": item["version"],
            "metadata_sha256": item["metadata_sha256"],
        }
        for item in contract["applications"]
    ]
    monkeypatch.setattr(toolchain.subprocess, "run", run)
    monkeypatch.setattr(toolchain, "_network_isolated", lambda: True)
    monkeypatch.setattr(toolchain, "_installed_inventory", lambda *args: (installed, "1" * 64))
    manifest = toolchain.create_offline_venv(
        base_python=base_python,
        venv_path=tmp_path / "venv",
        wheelhouse=wheelhouse,
        manifest_path=tmp_path / "manifest.json",
        origins_path=origins,
        lock_path=lock,
        expected_uid=os.geteuid(),
    )

    assert calls[0][0][1:] == [
        "-I",
        "-m",
        "venv",
        "--copies",
        "--without-pip",
        str(tmp_path / "venv"),
    ]
    resolve_argv, resolve_options = calls[1]
    assert "--dry-run" in resolve_argv
    assert "--ignore-installed" in resolve_argv
    assert "--require-hashes" not in resolve_argv
    assert resolve_argv[-4:] == toolchain._resolver_roots(contract)
    assert not (tmp_path / f".venv-resolver-{os.getpid()}.json").exists()
    install_argv, install_options = calls[2]
    assert str(wheelhouse / contract["installer"]["filename"]) in install_argv
    for flag in (
        "--isolated",
        "--no-index",
        "--require-hashes",
        "--only-binary=:all:",
    ):
        assert flag in install_argv
    assert "--no-deps" not in install_argv
    assert resolve_options["env"] == install_options["env"]
    assert set(install_options["env"]) == {
        "HOME",
        "PATH",
        "PIP_CONFIG_FILE",
        "PIP_NO_INDEX",
        "PYTHONNOUSERSITE",
        "SOURCE_DATE_EPOCH",
    }
    assert install_options["stdout"] is toolchain.subprocess.DEVNULL
    assert install_options["stderr"] is toolchain.subprocess.DEVNULL
    assert manifest["installer"]["version"] == "1.0"
    assert manifest["resolved"] == installed
    assert len(manifest["installed"]) == 14
    assert manifest["installed_metadata_sha256"] == toolchain._sha256(
        toolchain._canonical_bytes(installed)
    )
    assert json.loads((tmp_path / "manifest.json").read_bytes()) == manifest


def test_resolver_report_must_select_the_exact_root_reachable_closure(tmp_path):
    origins, lock, _ = _fixture_contract(tmp_path)
    contract = toolchain.load_contract(origins, lock)

    def report(entries):
        path = tmp_path / "report.json"
        path.write_text(
            json.dumps(
                {
                    "version": "1",
                    "pip_version": contract["installer"]["version"],
                    "install": entries,
                    "environment": {"python_version": "3.13"},
                }
            )
        )
        return path

    entries = [
        {
            "requested": item["project"] in toolchain.ROOTS,
            "metadata": {"name": item["project"], "version": item["version"]},
        }
        for item in contract["applications"]
    ]
    assert toolchain._load_resolver_report(
        report(entries), contract
    ) == toolchain._expected_installed(contract)

    with pytest.raises(toolchain.ToolchainError, match="closure"):
        toolchain._load_resolver_report(report(entries[:-1]), contract)

    wrong_version = copy.deepcopy(entries)
    wrong_version[0]["metadata"]["version"] = "2.0"
    with pytest.raises(toolchain.ToolchainError, match="unpinned version"):
        toolchain._load_resolver_report(report(wrong_version), contract)

    wrong_root = copy.deepcopy(entries)
    wrong_root[0]["requested"] = True
    with pytest.raises(toolchain.ToolchainError, match="roots or closure"):
        toolchain._load_resolver_report(report(wrong_root), contract)


def test_runtime_interpreter_must_match_the_toolchain_manifest(tmp_path, monkeypatch):
    origins, lock, wheelhouse = _fixture_contract(tmp_path)
    contract = toolchain.load_contract(origins, lock)
    site_packages = (tmp_path / "venv/lib/python/site-packages").resolve()
    site_packages.mkdir(parents=True)
    for item in contract["applications"]:
        with zipfile.ZipFile(wheelhouse / item["filename"]) as archive:
            metadata_name = next(
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            )
            metadata = archive.read(metadata_name)
        metadata_path = site_packages / metadata_name
        metadata_path.parent.mkdir()
        metadata_path.write_bytes(metadata)
    package_file = site_packages / "runtime_fixture.py"
    package_file.write_bytes(b"VALUE = 1\n")
    installed, tree_sha256 = toolchain._inventory_site_packages(site_packages, contract)
    keys = (
        "role",
        "project",
        "version",
        "filename",
        "bytes",
        "sha256",
        "metadata_sha256",
        "tags",
    )
    manifest = {
        "schema_version": 2,
        "contract": toolchain.TOOLCHAIN_CONTRACT,
        "origins_sha256": contract["origins_sha256"],
        "lock_sha256": contract["lock_sha256"],
        "roots": list(toolchain.ROOTS),
        "installer": {key: contract["installer"][key] for key in keys},
        "wheels": [{key: item[key] for key in keys} for item in contract["applications"]],
        "resolved": installed,
        "installed": installed,
        "installed_metadata_sha256": toolchain._sha256(toolchain._canonical_bytes(installed)),
        "installed_tree_sha256": tree_sha256,
        "resolve_argv_contract": list(toolchain.RESOLVE_ARGV_CONTRACT),
        "install_argv_contract": list(toolchain.INSTALL_ARGV_CONTRACT),
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    interpreter = Path(os.path.abspath(os.sys.executable))
    monkeypatch.setattr(
        toolchain.subprocess,
        "run",
        lambda *args, **kwargs: type("Result", (), {"stdout": f"{site_packages}\n".encode()})(),
    )
    assert (
        toolchain.validate_installed_environment(interpreter, manifest_path, origins, lock)[
            "installed_tree_sha256"
        ]
        == tree_sha256
    )

    package_file.write_bytes(b"VALUE = 2\n")
    with pytest.raises(toolchain.ToolchainError, match="runtime Python environment"):
        toolchain.validate_installed_environment(interpreter, manifest_path, origins, lock)

    package_file.write_bytes(b"VALUE = 1\n")
    extra_file = site_packages / "unexpected.py"
    extra_file.write_bytes(b"")
    with pytest.raises(toolchain.ToolchainError, match="runtime Python environment"):
        toolchain.validate_installed_environment(interpreter, manifest_path, origins, lock)

    extra_file.unlink()
    unsafe_file = site_packages / "unsafe.py"
    unsafe_file.symlink_to(package_file)
    with pytest.raises(toolchain.ToolchainError, match="non-regular file"):
        toolchain.validate_installed_environment(interpreter, manifest_path, origins, lock)

    unsafe_file.unlink()
    monkeypatch.setattr(toolchain, "MAX_INSTALLED_FILES", 1)
    with pytest.raises(toolchain.ToolchainError, match="outside the accepted bounds"):
        toolchain.validate_installed_environment(interpreter, manifest_path, origins, lock)


def test_offline_venv_rejects_root_uid_mismatch_or_network(tmp_path, monkeypatch):
    monkeypatch.setattr(toolchain.os, "geteuid", lambda: 0)
    with pytest.raises(toolchain.ToolchainError, match="non-root"):
        toolchain.create_offline_venv(
            base_python=Path("/usr/bin/python3"),
            venv_path=tmp_path / "venv",
            wheelhouse=tmp_path / "wheels",
            manifest_path=tmp_path / "manifest",
            expected_uid=0,
        )

    monkeypatch.setattr(toolchain.os, "geteuid", lambda: 1234)
    monkeypatch.setattr(toolchain, "_network_isolated", lambda: False)
    with pytest.raises(toolchain.ToolchainError, match="isolated"):
        toolchain.create_offline_venv(
            base_python=Path("/usr/bin/python3"),
            venv_path=tmp_path / "venv",
            wheelhouse=tmp_path / "wheels",
            manifest_path=tmp_path / "manifest",
            expected_uid=1234,
        )
