"""Stdlib-only, content-addressed Python toolchain for the CDK synth gate."""

import argparse
import hashlib
import io
import json
import os
import re
import socket
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Mapping, Sequence
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
DEFAULT_LOCK = HERE / "python-synth-requirements.lock"
DEFAULT_ORIGINS = HERE / "python-synth-wheel-origins.json"
MAX_CONTRACT_BYTES = 64 * 1024
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_WHEELHOUSE_BYTES = 128 * 1024 * 1024
MAX_WHEEL_ENTRIES = 2_000
MAX_WHEEL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_WHEELHOUSE_ENTRIES = 10_000
MAX_WHEELHOUSE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_INSTALLED_ENTRIES = 4_000
MAX_INSTALLED_FILES = 2_000
MAX_INSTALLED_BYTES = 512 * 1024 * 1024
MAX_RESOLVER_REPORT_BYTES = 2 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 45
ROOTS = ("aws-cdk-cloud-assembly-schema", "aws-cdk-lib", "constructs", "jsii")
TOOLCHAIN_CONTRACT = "offline-wheelhouse-resolved-require-hashes-v2"
RESOLVE_ARGV_CONTRACT = [
    "python",
    "-I",
    "-c",
    "pinned-pip-wheel",
    "--isolated",
    "--disable-pip-version-check",
    "install",
    "--dry-run",
    "--ignore-installed",
    "--report",
    "resolver-report",
    "--no-input",
    "--no-index",
    "--find-links",
    "wheelhouse",
    "--only-binary=:all:",
    "roots-exact",
]
INSTALL_ARGV_CONTRACT = [
    "python",
    "-I",
    "-c",
    "pinned-pip-wheel",
    "--isolated",
    "--disable-pip-version-check",
    "install",
    "--no-input",
    "--no-index",
    "--find-links",
    "wheelhouse",
    "--require-hashes",
    "--only-binary=:all:",
    "-r",
    "requirements-lock",
]
_ARTIFACT_KEYS = {
    "role",
    "project",
    "version",
    "filename",
    "url",
    "bytes",
    "sha256",
    "metadata_sha256",
    "tags",
}
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_PROJECT_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,63}\Z")


class ToolchainError(ValueError):
    pass


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _closed(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ToolchainError(f"{label} does not match the closed contract")
    return value


def _canonical_project(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ToolchainError("JSON contains a duplicate key")
        result[key] = value
    return result


def _read_regular(path: Path, maximum: int, *, allow_empty: bool = False) -> bytes:
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_CLOEXEC", "O_NONBLOCK", "O_NOFOLLOW"):
        flags |= getattr(os, name, 0)
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ToolchainError(f"{path.name} must be a regular file")
        if (
            details.st_size < 0
            or (details.st_size == 0 and not allow_empty)
            or details.st_size > maximum
        ):
            raise ToolchainError(f"{path.name} is outside the accepted size")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(maximum + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) != details.st_size:
        raise ToolchainError(f"{path.name} changed while it was read")
    return payload


def _load_json(path: Path, maximum: int = MAX_CONTRACT_BYTES) -> tuple[dict, bytes]:
    payload = _read_regular(path, maximum)
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ToolchainError(f"{path.name} is not bounded valid JSON") from error
    if not isinstance(value, dict):
        raise ToolchainError(f"{path.name} root must be an object")
    return value, payload


def _expected_lock(artifacts: Sequence[Mapping[str, object]]) -> bytes:
    lines = [
        "# Python synth application closure. Every entry is an exact wheel hash from",
        "# tests/aws/cli/python-synth-wheel-origins.json. Keep this file hand-auditable.",
    ]
    for item in artifacts:
        if item["role"] == "application":
            lines.append(f"{item['project']}=={item['version']} --hash=sha256:{item['sha256']}")
    return ("\n".join(lines) + "\n").encode()


def load_contract(origins_path: Path = DEFAULT_ORIGINS, lock_path: Path = DEFAULT_LOCK) -> dict:
    value, origins_payload = _load_json(origins_path)
    value = _closed(value, {"schema_version", "index_url", "roots", "artifacts"}, "origins")
    if value["schema_version"] != 1 or value["index_url"] != "https://pypi.org/simple":
        raise ToolchainError("unsupported Python synth origins contract")
    if value["roots"] != list(ROOTS):
        raise ToolchainError("Python synth roots are not exact")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 15:
        raise ToolchainError("origins must contain fourteen applications and one installer")
    applications = []
    installer = None
    filenames = set()
    projects = set()
    for raw in artifacts:
        item = _closed(raw, _ARTIFACT_KEYS, "wheel origin")
        for field in ("project", "version", "filename", "url", "sha256", "metadata_sha256"):
            if not isinstance(item[field], str) or not item[field]:
                raise ToolchainError(f"wheel origin {field} is invalid")
        project = item["project"]
        if not _PROJECT_RE.fullmatch(project) or _canonical_project(project) != project:
            raise ToolchainError("wheel origin project is not canonical")
        if not _VERSION_RE.fullmatch(item["version"]):
            raise ToolchainError("wheel origin version is invalid")
        if item["filename"] != Path(item["filename"]).name or not item["filename"].endswith(".whl"):
            raise ToolchainError("wheel filename is unsafe")
        parsed = urllib.parse.urlsplit(item["url"])
        if (
            parsed.scheme != "https"
            or parsed.hostname != "files.pythonhosted.org"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or PurePosixPath(parsed.path).name != item["filename"]
        ):
            raise ToolchainError("wheel URL is not a direct official artifact URL")
        if isinstance(item["bytes"], bool) or not isinstance(item["bytes"], int):
            raise ToolchainError("wheel size is invalid")
        if not 1 <= item["bytes"] <= MAX_WHEEL_BYTES:
            raise ToolchainError("wheel size is outside the accepted bounds")
        if not _SHA256_RE.fullmatch(item["sha256"]) or not _SHA256_RE.fullmatch(
            item["metadata_sha256"]
        ):
            raise ToolchainError("wheel digest is invalid")
        if (
            not isinstance(item["tags"], list)
            or not item["tags"]
            or any(tag not in {"py3-none-any", "py2-none-any"} for tag in item["tags"])
            or "py3-none-any" not in item["tags"]
        ):
            raise ToolchainError("wheel tags are not universal Python 3")
        if project in projects or item["filename"] in filenames:
            raise ToolchainError("wheel origins contain a duplicate")
        projects.add(project)
        filenames.add(item["filename"])
        if item["role"] == "application":
            applications.append(item)
        elif item["role"] == "installer" and project == "pip" and installer is None:
            installer = item
        else:
            raise ToolchainError("wheel role is invalid")
    if (
        len(applications) != 14
        or installer is None
        or applications != sorted(applications, key=lambda item: item["project"])
        or artifacts != [*applications, installer]
    ):
        raise ToolchainError("wheel origin order or role partition is invalid")
    if sum(item["bytes"] for item in artifacts) > MAX_WHEELHOUSE_BYTES:
        raise ToolchainError("declared wheelhouse size is outside the accepted bounds")
    if not set(ROOTS) <= {item["project"] for item in applications}:
        raise ToolchainError("wheel application roots are incomplete")
    lock_payload = _read_regular(lock_path, MAX_CONTRACT_BYTES)
    if lock_payload != _expected_lock(applications):
        raise ToolchainError("Python synth requirements lock does not match the wheel origins")
    return {
        "schema_version": 1,
        "index_url": value["index_url"],
        "roots": list(ROOTS),
        "artifacts": artifacts,
        "applications": applications,
        "installer": installer,
        "origins_sha256": _sha256(origins_payload),
        "lock_sha256": _sha256(lock_payload),
        "lock_path": lock_path,
    }


def _validate_zip(payload: bytes, artifact: Mapping[str, object]) -> tuple[int, int]:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
            if (
                len(infos) > MAX_WHEEL_ENTRIES
                or sum(info.file_size for info in infos) > MAX_WHEEL_UNCOMPRESSED_BYTES
            ):
                raise ToolchainError("wheel archive expands outside the accepted bounds")
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ToolchainError("wheel archive contains duplicate members")
            for info in infos:
                relative = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if relative.is_absolute() or ".." in relative.parts or stat.S_ISLNK(mode):
                    raise ToolchainError("wheel archive contains an unsafe member")
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
            if len(metadata_names) != 1 or len(wheel_names) != 1:
                raise ToolchainError("wheel archive metadata layout is invalid")
            metadata = archive.read(metadata_names[0])
            wheel = BytesParser(policy=compat32).parsebytes(archive.read(wheel_names[0]))
    except (zipfile.BadZipFile, RuntimeError) as error:
        raise ToolchainError("wheel is not a valid bounded archive") from error
    parsed = BytesParser(policy=compat32).parsebytes(metadata)
    if (
        _canonical_project(parsed.get("Name", "")) != artifact["project"]
        or parsed.get("Version") != artifact["version"]
        or _sha256(metadata) != artifact["metadata_sha256"]
        or sorted(wheel.get_all("Tag") or []) != artifact["tags"]
    ):
        raise ToolchainError("wheel metadata does not match its pinned origin")
    return len(infos), sum(info.file_size for info in infos)


def validate_wheelhouse(wheelhouse: Path, contract: Mapping[str, object]) -> list[dict]:
    try:
        root_stat = wheelhouse.lstat()
    except FileNotFoundError as error:
        raise ToolchainError("wheelhouse is missing") from error
    if not stat.S_ISDIR(root_stat.st_mode) or wheelhouse.is_symlink():
        raise ToolchainError("wheelhouse must be a regular directory")
    expected = {item["filename"] for item in contract["artifacts"]}
    entries = []
    for entry in wheelhouse.iterdir():
        entries.append(entry)
        if len(entries) > len(expected):
            raise ToolchainError("wheelhouse inventory is not exact")
    if {entry.name for entry in entries} != expected or len(entries) != len(expected):
        raise ToolchainError("wheelhouse inventory is not exact")
    result = []
    total = 0
    total_entries = 0
    total_uncompressed = 0
    for artifact in contract["artifacts"]:
        payload = _read_regular(wheelhouse / artifact["filename"], MAX_WHEEL_BYTES)
        total += len(payload)
        if len(payload) != artifact["bytes"] or _sha256(payload) != artifact["sha256"]:
            raise ToolchainError("wheel bytes do not match their pinned origin")
        entries, uncompressed = _validate_zip(payload, artifact)
        total_entries += entries
        total_uncompressed += uncompressed
        result.append(
            {
                key: artifact[key]
                for key in (
                    "role",
                    "project",
                    "version",
                    "filename",
                    "bytes",
                    "sha256",
                    "metadata_sha256",
                    "tags",
                )
            }
        )
    if (
        total > MAX_WHEELHOUSE_BYTES
        or total_entries > MAX_WHEELHOUSE_ENTRIES
        or total_uncompressed > MAX_WHEELHOUSE_UNCOMPRESSED_BYTES
    ):
        raise ToolchainError("wheelhouse total is outside the accepted bounds")
    return result


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ToolchainError("wheel origin redirected away from its pinned URL")


def _download_one(url: str, output: Path, expected_size: int, expected_sha256: str) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirects())
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200 or response.geturl() != url:
                raise ToolchainError("wheel origin response is not exact")
            length = response.headers.get("Content-Length")
            if length is not None and length != str(expected_size):
                raise ToolchainError("wheel origin content length is stale")
            payload = response.read(expected_size + 1)
    except (OSError, urllib.error.URLError) as error:
        raise ToolchainError("wheel origin download failed") from error
    if len(payload) != expected_size or _sha256(payload) != expected_sha256:
        raise ToolchainError("downloaded wheel bytes do not match the pinned origin")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def download_wheelhouse(
    wheelhouse: Path,
    origins_path: Path = DEFAULT_ORIGINS,
    lock_path: Path = DEFAULT_LOCK,
) -> list[dict]:
    contract = load_contract(origins_path, lock_path)
    if not wheelhouse.is_absolute() or os.path.lexists(wheelhouse):
        raise ToolchainError("wheelhouse destination must be a fresh absolute path")
    wheelhouse.mkdir(parents=True, mode=0o700)
    try:
        for artifact in contract["artifacts"]:
            command = [
                sys.executable,
                "-I",
                "-S",
                str(Path(__file__).resolve()),
                "_download-one",
                artifact["url"],
                str(wheelhouse / artifact["filename"]),
                str(artifact["bytes"]),
                artifact["sha256"],
            ]
            subprocess.run(
                command,
                check=True,
                timeout=DOWNLOAD_TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env={"PATH": os.environ.get("PATH", "")},
            )
        return validate_wheelhouse(wheelhouse, contract)
    except BaseException:
        for path in wheelhouse.iterdir():
            path.unlink(missing_ok=True)
        wheelhouse.rmdir()
        raise


def _is_ipv6_default_route(line: str) -> bool:
    fields = line.split()
    if len(fields) < 6 or fields[0] != "0" * 32 or fields[1] != "00":
        return False
    # The kernel installs an unreachable ::/0 reject route (metric 0xffffffff) when
    # loopback comes up with IPv6 enabled; it is not egress.
    return fields[5] != "ffffffff"


def _network_isolated() -> bool:
    if sys.platform != "linux" or {name for _, name in socket.if_nameindex()} != {"lo"}:
        return False
    try:
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return False
    # A missing ipv6_route file means IPv6 is disabled in this namespace, i.e. there are
    # no IPv6 routes to audit — that is isolated, not a failure to prove isolation.
    try:
        routes6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    except OSError:
        routes6 = []
    return not any(line.split()[1] == "00000000" for line in routes if line.split()) and not any(
        _is_ipv6_default_route(line) for line in routes6 if line.split()
    )


def _installed_inventory(
    venv_python: Path, contract: Mapping[str, object]
) -> tuple[list[dict], str]:
    result = subprocess.run(
        [
            str(venv_python),
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        check=True,
        timeout=10,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )
    if len(result.stdout) > 4096:
        raise ToolchainError("venv site-packages path is unbounded")
    site_packages = Path(result.stdout.decode().strip())
    return _inventory_site_packages(site_packages, contract)


def _inventory_site_packages(
    site_packages: Path, contract: Mapping[str, object]
) -> tuple[list[dict], str]:
    if not site_packages.is_absolute() or not site_packages.is_dir() or site_packages.is_symlink():
        raise ToolchainError("venv site-packages path is invalid")
    expected = {item["project"]: item for item in contract["applications"]}
    installed = {}
    for dist_info in site_packages.glob("*.dist-info"):
        if len(installed) >= len(expected):
            raise ToolchainError("installed distribution set is not exact")
        if dist_info.is_symlink() or not dist_info.is_dir():
            raise ToolchainError("installed distribution metadata is unsafe")
        metadata = _read_regular(dist_info / "METADATA", 1024 * 1024)
        parsed = BytesParser(policy=compat32).parsebytes(metadata)
        name = _canonical_project(parsed.get("Name", ""))
        if name in installed or name not in expected:
            raise ToolchainError("installed distribution set is not exact")
        item = expected[name]
        if parsed.get("Version") != item["version"] or _sha256(metadata) != item["metadata_sha256"]:
            raise ToolchainError("installed distribution metadata differs from its wheel")
        installed[name] = {
            "project": name,
            "version": item["version"],
            "metadata_sha256": _sha256(metadata),
        }
    if set(installed) != set(expected):
        raise ToolchainError("installed distribution closure is incomplete")
    paths = []
    for path in site_packages.rglob("*"):
        paths.append(path)
        if len(paths) > MAX_INSTALLED_ENTRIES:
            raise ToolchainError("installed environment inventory is outside the accepted bounds")
    tree = []
    total_bytes = 0
    for path in sorted(paths):
        details = path.lstat()
        if stat.S_ISDIR(details.st_mode):
            continue
        if not stat.S_ISREG(details.st_mode):
            raise ToolchainError("installed environment contains a non-regular file")
        if len(tree) >= MAX_INSTALLED_FILES or details.st_size > MAX_WHEEL_BYTES:
            raise ToolchainError("installed environment inventory is outside the accepted bounds")
        total_bytes += details.st_size
        if total_bytes > MAX_INSTALLED_BYTES:
            raise ToolchainError("installed environment size is outside the accepted bounds")
        payload = _read_regular(path, MAX_WHEEL_BYTES, allow_empty=True)
        tree.append([path.relative_to(site_packages).as_posix(), len(payload), _sha256(payload)])
    return [installed[name] for name in sorted(installed)], _sha256(_canonical_bytes(tree))


def _expected_installed(contract: Mapping[str, object]) -> list[dict]:
    return [
        {
            "project": artifact["project"],
            "version": artifact["version"],
            "metadata_sha256": artifact["metadata_sha256"],
        }
        for artifact in contract["applications"]
    ]


def _resolver_roots(contract: Mapping[str, object]) -> list[str]:
    versions = {item["project"]: item["version"] for item in contract["applications"]}
    return [f"{project}=={versions[project]}" for project in ROOTS]


def _load_resolver_report(report_path: Path, contract: Mapping[str, object]) -> list[dict]:
    value, _ = _load_json(report_path, MAX_RESOLVER_REPORT_BYTES)
    value = _closed(value, {"version", "pip_version", "install", "environment"}, "pip report")
    if value["version"] != "1" or value["pip_version"] != contract["installer"]["version"]:
        raise ToolchainError("pip resolver report version is not exact")
    if not isinstance(value["environment"], dict):
        raise ToolchainError("pip resolver environment is invalid")
    entries = value["install"]
    if not isinstance(entries, list) or len(entries) != len(contract["applications"]):
        raise ToolchainError("pip resolver closure is not exact")
    expected = {item["project"]: item for item in contract["applications"]}
    resolved = {}
    requested = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("metadata"), dict):
            raise ToolchainError("pip resolver entry is invalid")
        metadata = entry["metadata"]
        project = _canonical_project(metadata.get("name", ""))
        if project in resolved or project not in expected:
            raise ToolchainError("pip resolver closure is not exact")
        artifact = expected[project]
        if metadata.get("version") != artifact["version"]:
            raise ToolchainError("pip resolver selected an unpinned version")
        if entry.get("requested") is True:
            requested.add(project)
        elif entry.get("requested") is not False:
            raise ToolchainError("pip resolver requested marker is invalid")
        resolved[project] = {
            "project": project,
            "version": artifact["version"],
            "metadata_sha256": artifact["metadata_sha256"],
        }
    if set(resolved) != set(expected) or requested != set(ROOTS):
        raise ToolchainError("pip resolver roots or closure are not exact")
    return [resolved[project] for project in sorted(resolved)]


def load_toolchain_manifest(
    manifest_path: Path,
    origins_path: Path = DEFAULT_ORIGINS,
    lock_path: Path = DEFAULT_LOCK,
) -> dict:
    contract = load_contract(origins_path, lock_path)
    value, payload = _load_json(manifest_path)
    value = _closed(
        value,
        {
            "schema_version",
            "contract",
            "origins_sha256",
            "lock_sha256",
            "roots",
            "installer",
            "wheels",
            "resolved",
            "installed",
            "installed_metadata_sha256",
            "installed_tree_sha256",
            "resolve_argv_contract",
            "install_argv_contract",
        },
        "Python synth toolchain manifest",
    )
    expected_wheels = [
        {
            key: artifact[key]
            for key in (
                "role",
                "project",
                "version",
                "filename",
                "bytes",
                "sha256",
                "metadata_sha256",
                "tags",
            )
        }
        for artifact in contract["applications"]
    ]
    expected_installer = {
        key: contract["installer"][key]
        for key in (
            "role",
            "project",
            "version",
            "filename",
            "bytes",
            "sha256",
            "metadata_sha256",
            "tags",
        )
    }
    expected_installed = _expected_installed(contract)
    if (
        value["schema_version"] != 2
        or value["contract"] != TOOLCHAIN_CONTRACT
        or value["origins_sha256"] != contract["origins_sha256"]
        or value["lock_sha256"] != contract["lock_sha256"]
        or value["roots"] != list(ROOTS)
        or value["installer"] != expected_installer
        or value["wheels"] != expected_wheels
        or value["resolved"] != expected_installed
        or value["installed"] != expected_installed
        or value["installed_metadata_sha256"] != _sha256(_canonical_bytes(expected_installed))
        or value["resolve_argv_contract"] != RESOLVE_ARGV_CONTRACT
        or value["install_argv_contract"] != INSTALL_ARGV_CONTRACT
        or not isinstance(value["installed_tree_sha256"], str)
        or not _SHA256_RE.fullmatch(value["installed_tree_sha256"])
    ):
        raise ToolchainError("Python synth toolchain manifest is stale or contradictory")
    return {**value, "manifest_sha256": _sha256(payload)}


def validate_installed_environment(
    venv_python: Path,
    manifest_path: Path,
    origins_path: Path = DEFAULT_ORIGINS,
    lock_path: Path = DEFAULT_LOCK,
) -> dict:
    if not venv_python.is_absolute() or not venv_python.is_file():
        raise ToolchainError("venv Python must be an absolute file-backed interpreter")
    manifest = load_toolchain_manifest(manifest_path, origins_path, lock_path)
    contract = load_contract(origins_path, lock_path)
    installed, tree_sha256 = _installed_inventory(venv_python, contract)
    if installed != manifest["installed"] or tree_sha256 != manifest["installed_tree_sha256"]:
        raise ToolchainError("runtime Python environment differs from its toolchain manifest")
    return manifest


def create_offline_venv(
    *,
    base_python: Path,
    venv_path: Path,
    wheelhouse: Path,
    manifest_path: Path,
    origins_path: Path = DEFAULT_ORIGINS,
    lock_path: Path = DEFAULT_LOCK,
    expected_uid: int,
    require_isolated_network: bool = True,
) -> dict:
    if os.geteuid() == 0 or os.geteuid() != expected_uid:
        raise ToolchainError("offline venv installation must run as the expected non-root user")
    if require_isolated_network and not _network_isolated():
        raise ToolchainError("offline venv installation requires an isolated loopback-only network")
    if not base_python.is_absolute() or not base_python.is_file():
        raise ToolchainError("base Python must be an absolute regular executable")
    if not venv_path.is_absolute() or os.path.lexists(venv_path):
        raise ToolchainError("venv destination must be a fresh absolute path")
    if not manifest_path.is_absolute() or os.path.lexists(manifest_path):
        raise ToolchainError("toolchain manifest destination must be fresh and absolute")
    contract = load_contract(origins_path, lock_path)
    wheels = validate_wheelhouse(wheelhouse, contract)
    subprocess.run(
        [str(base_python), "-I", "-m", "venv", "--without-pip", str(venv_path)],
        check=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    venv_python = venv_path / "bin/python"
    pip_wheel = wheelhouse / contract["installer"]["filename"]
    bootstrap = "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
    pip_environment = {
        "HOME": str(venv_path.parent),
        "PATH": "/usr/bin:/bin",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_NO_INDEX": "1",
        "PYTHONNOUSERSITE": "1",
        "SOURCE_DATE_EPOCH": "0",
    }
    resolver_report = venv_path.parent / f".{venv_path.name}-resolver-{os.getpid()}.json"
    if os.path.lexists(resolver_report):
        raise ToolchainError("pip resolver report destination must be fresh")
    resolve_argv = [
        str(venv_python),
        "-I",
        "-c",
        bootstrap,
        str(pip_wheel),
        "--isolated",
        "--disable-pip-version-check",
        "install",
        "--dry-run",
        "--ignore-installed",
        "--report",
        str(resolver_report),
        "--no-input",
        "--no-index",
        "--find-links",
        str(wheelhouse),
        "--only-binary=:all:",
        *_resolver_roots(contract),
    ]
    try:
        subprocess.run(
            resolve_argv,
            check=True,
            timeout=120,
            cwd=venv_path.parent,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=pip_environment,
        )
        resolved = _load_resolver_report(resolver_report, contract)
    finally:
        resolver_report.unlink(missing_ok=True)
    install_argv = [
        str(venv_python),
        "-I",
        "-c",
        bootstrap,
        str(pip_wheel),
        "--isolated",
        "--disable-pip-version-check",
        "install",
        "--no-input",
        "--no-index",
        "--find-links",
        str(wheelhouse),
        "--require-hashes",
        "--only-binary=:all:",
        "-r",
        str(lock_path),
    ]
    subprocess.run(
        install_argv,
        check=True,
        timeout=120,
        cwd=venv_path.parent,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=pip_environment,
    )
    installed, tree_sha256 = _installed_inventory(venv_python, contract)
    manifest = {
        "schema_version": 2,
        "contract": TOOLCHAIN_CONTRACT,
        "origins_sha256": contract["origins_sha256"],
        "lock_sha256": contract["lock_sha256"],
        "roots": list(ROOTS),
        "installer": next(item for item in wheels if item["role"] == "installer"),
        "wheels": [item for item in wheels if item["role"] == "application"],
        "resolved": resolved,
        "installed": installed,
        "installed_metadata_sha256": _sha256(_canonical_bytes(installed)),
        "installed_tree_sha256": tree_sha256,
        "resolve_argv_contract": list(RESOLVE_ARGV_CONTRACT),
        "install_argv_contract": list(INSTALL_ARGV_CONTRACT),
    }
    payload = _canonical_bytes(manifest) + b"\n"
    if len(payload) > MAX_CONTRACT_BYTES:
        raise ToolchainError("toolchain manifest is outside the accepted size")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = manifest_path.with_name(f".{manifest_path.name}.tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, manifest_path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    download = commands.add_parser("download")
    download.add_argument("--wheelhouse", type=Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--wheelhouse", type=Path, required=True)
    install = commands.add_parser("install")
    install.add_argument("--base-python", type=Path, required=True)
    install.add_argument("--venv", type=Path, required=True)
    install.add_argument("--wheelhouse", type=Path, required=True)
    install.add_argument("--manifest", type=Path, required=True)
    install.add_argument("--expected-uid", type=int, required=True)
    hidden = commands.add_parser("_download-one", help=argparse.SUPPRESS)
    hidden.add_argument("url")
    hidden.add_argument("output", type=Path)
    hidden.add_argument("expected_size", type=int)
    hidden.add_argument("expected_sha256")
    args = parser.parse_args(argv)
    if args.command == "download":
        download_wheelhouse(args.wheelhouse)
    elif args.command == "validate":
        validate_wheelhouse(args.wheelhouse, load_contract())
    elif args.command == "install":
        create_offline_venv(
            base_python=args.base_python,
            venv_path=args.venv,
            wheelhouse=args.wheelhouse,
            manifest_path=args.manifest,
            expected_uid=args.expected_uid,
        )
    else:
        _download_one(args.url, args.output, args.expected_size, args.expected_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
