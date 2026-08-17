"""Amplify Android 2.39.0 protocol gate on a hermetic Robolectric JVM.

This qualifies the Android SDK protocol implementation. It is not Android
emulator, device, or Authenticator UI evidence.
"""

import fcntl
import hashlib
import json
import os
import platform
import shutil
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from tests.aws.services.cognito_idp.test_amplify_native_swift import (
    MAX_RUNTIME_OUTPUT,
    _bounded_run,
    _tls_relay,
)
from tests.aws.services.cognito_idp.test_amplify_v6_runtime import (
    AmplifyV6Stack,
    _local_api_endpoint,
)
from tests.aws.services.cognito_idp.test_amplify_v6_runtime import (
    amplify_v6_stack as _amplify_v6_stack,
)

from localstack.testing.pytest import markers

THIS_FOLDER = Path(__file__).parent
ANDROID_SOURCE = THIS_FOLDER / "native" / "android" / "AmplifyNativeProtocolTest.kt"
ANDROID_VERIFICATION_SHA256 = "7f54f0dbd029381b54048963e856dce89efeabcef1f6a27393ca37c5a9617e18"
GRADLE_VERSION = "8.13"
GRADLE_URL = f"https://services.gradle.org/distributions/gradle-{GRADLE_VERSION}-bin.zip"
GRADLE_SHA256 = "20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78"
AMPLIFY_ANDROID_VERSION = "2.39.0"
MAX_BUILD_OUTPUT = 2 * 1024 * 1024

amplify_v6_stack = _amplify_v6_stack


@pytest.fixture
def amplify_android_gate_lock():
    """Fail closed when another native Android gate owns the shared toolchain/relay."""
    root = _cache_root()
    root.mkdir(parents=True, exist_ok=True)
    lock_path = root / "gate.lock"
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AssertionError(
                "another Amplify Android native gate is already running"
            ) from error
        lock.write(f"{os.getpid()}\n")
        lock.flush()
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _cache_root() -> Path:
    return Path.home() / "Library" / "Caches" / "localstack" / "amplify-native-android"


def _download_gradle(work: Path) -> Path:
    root = _cache_root()
    archive = root / f"gradle-{GRADLE_VERSION}-bin.zip"
    distribution = work / "gradle-toolchain" / f"gradle-{GRADLE_VERSION}"
    executable = distribution / "bin" / "gradle"
    root.mkdir(parents=True, exist_ok=True)
    if archive.is_file() and hashlib.sha256(archive.read_bytes()).hexdigest() != GRADLE_SHA256:
        raise AssertionError("cached Gradle distribution hash mismatch")
    if not archive.is_file():
        temporary = archive.with_suffix(".download")
        curl = shutil.which("curl")
        if not curl:
            raise AssertionError("Gradle download requires curl with the system trust store")
        result = _bounded_run(
            [
                curl,
                "--fail",
                "--location",
                "--max-time",
                "180",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--output",
                str(temporary),
                "--write-out",
                "%{url_effective}",
                GRADLE_URL,
            ],
            cwd=root,
            env={"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "")},
            timeout=190,
            limit=4096,
        )
        if result.returncode:
            raise AssertionError(
                f"Gradle download failed: {result.stderr.decode(errors='replace')}"
            )
        final_url = result.stdout.decode().split("?", 1)[0]
        if (
            not final_url.startswith("https://services.gradle.org/")
            and not final_url.startswith("https://github.com/gradle/gradle-distributions/")
            and not final_url.startswith("https://release-assets.githubusercontent.com/")
        ):
            raise AssertionError("Gradle download redirected to an untrusted origin")
        if temporary.stat().st_size > 256 * 1024 * 1024:
            raise AssertionError("Gradle distribution exceeded size bound")
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        if digest != GRADLE_SHA256:
            temporary.unlink(missing_ok=True)
            raise AssertionError("downloaded Gradle distribution hash mismatch")
        temporary.replace(archive)
    extraction_root = distribution.parent
    extraction_root.mkdir()
    with zipfile.ZipFile(archive) as bundle:
        for item in bundle.infolist():
            target = (extraction_root / item.filename).resolve()
            if extraction_root.resolve() not in target.parents:
                raise AssertionError("Gradle archive attempted path traversal")
        bundle.extractall(extraction_root)
    executable.chmod(executable.stat().st_mode | 0o100)
    return executable


def _write_project(project: Path):
    (project / "src" / "test" / "java" / "localstack" / "cognito" / "nativegate").mkdir(
        parents=True
    )
    (project / "src" / "main").mkdir(parents=True)
    (project / "gradle").mkdir()
    shutil.copy2(
        ANDROID_SOURCE,
        project
        / "src"
        / "test"
        / "java"
        / "localstack"
        / "cognito"
        / "nativegate"
        / ANDROID_SOURCE.name,
    )
    (project / "settings.gradle.kts").write_text(
        """
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "amplify-android-native-gate"
""".strip()
        + "\n"
    )
    (project / "build.gradle.kts").write_text(
        f"""
plugins {{
    id("com.android.library") version "8.11.1"
    id("org.jetbrains.kotlin.android") version "2.2.0"
}}

android {{
    namespace = "localstack.cognito.nativegate"
    compileSdk = 36
    defaultConfig {{ minSdk = 24 }}
    compileOptions {{
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }}
    kotlinOptions {{ jvmTarget = "17" }}
    testOptions {{ unitTests.isIncludeAndroidResources = true }}
}}

tasks.register("writeNativeGateRuntime") {{
    dependsOn("compileDebugUnitTestKotlin")
    doLast {{
        val testTask = tasks.named<org.gradle.api.tasks.testing.Test>("testDebugUnitTest").get()
        file(System.getenv("AMPLIFY_ANDROID_CLASSPATH_FILE")).writeText(testTask.classpath.asPath)
        copy {{
            from(testTask.classpath.filter {{ it.name.startsWith("android-all-instrumented-") }})
            into(file(System.getenv("AMPLIFY_ANDROID_ROBOLECTRIC_DIR")))
        }}
        file(System.getenv("AMPLIFY_ANDROID_PROPERTIES_FILE")).printWriter().use {{ writer ->
            testTask.systemProperties.toSortedMap().forEach {{ (key, value) ->
                writer.println("$key\t$value")
            }}
        }}
    }}
}}

dependencies {{
    implementation("com.amplifyframework:aws-api:{AMPLIFY_ANDROID_VERSION}")
    implementation("com.amplifyframework:aws-auth-cognito:{AMPLIFY_ANDROID_VERSION}")
    implementation("com.amplifyframework:core-kotlin:{AMPLIFY_ANDROID_VERSION}")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    testImplementation("org.robolectric:robolectric:4.15.1")
    testRuntimeOnly("org.robolectric:android-all-instrumented:15-robolectric-12650502-i7")
}}
""".lstrip()
    )
    (project / "src" / "main" / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <uses-permission android:name="android.permission.INTERNET" />\n'
        "</manifest>\n"
    )
    (project / "gradle.properties").write_text(
        "android.useAndroidX=true\n"
        "org.gradle.daemon=false\n"
        "org.gradle.jvmargs=-Xmx1536m -Dfile.encoding=UTF-8\n"
    )


def _android_environment(work: Path) -> dict[str, str]:
    android_sdk = Path("/usr/local/share/android-commandlinetools")
    java_home = Path("/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home")
    if platform.system() != "Darwin" or not (android_sdk / "platforms" / "android-36").is_dir():
        pytest.skip("Android SDK platform 36 is unavailable")
    if not (java_home / "bin" / "java").is_file():
        pytest.skip("pinned local Java 21 toolchain is unavailable")
    return {
        "ANDROID_HOME": str(android_sdk),
        "ANDROID_SDK_ROOT": str(android_sdk),
        "GRADLE_USER_HOME": str(_cache_root() / "gradle-user-home"),
        "HOME": str(work / "home"),
        "JAVA_HOME": str(java_home),
        "JAVA_TOOL_OPTIONS": "-Djava.net.preferIPv4Stack=true",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": str(work / "tmp"),
    }


@markers.aws.only_localstack
def test_amplify_android_native_protocol(
    amplify_android_gate_lock,
    amplify_v6_stack: AmplifyV6Stack,
    region_name: str,
):
    endpoint = urlsplit(os.environ.get("AWS_ENDPOINT_URL", "http://127.0.0.1:4566"))
    if endpoint.hostname not in {"127.0.0.1", "localhost"} or endpoint.port is None:
        raise AssertionError("native Android gate requires an explicit loopback edge port")
    source_hash = hashlib.sha256(ANDROID_SOURCE.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="amplify-android-native-") as directory:
        work = Path(directory)
        project = work / "project"
        project.mkdir()
        _write_project(project)
        environment = _android_environment(work)
        Path(environment["HOME"]).mkdir()
        Path(environment["TMPDIR"]).mkdir()
        classpath_file = work / "runtime-classpath"
        properties_file = work / "runtime-properties"
        environment["AMPLIFY_ANDROID_CLASSPATH_FILE"] = str(classpath_file)
        environment["AMPLIFY_ANDROID_PROPERTIES_FILE"] = str(properties_file)
        environment["AMPLIFY_ANDROID_ROBOLECTRIC_DIR"] = str(work / "robolectric-offline")
        gradle = _download_gradle(work)
        build = _bounded_run(
            [
                str(gradle),
                "--no-daemon",
                "--write-verification-metadata",
                "sha256",
                "writeNativeGateRuntime",
            ],
            cwd=project,
            env=environment,
            timeout=1200,
            limit=MAX_BUILD_OUTPUT,
        )
        if build.returncode:
            raise AssertionError(
                f"Amplify Android build failed: {build.stderr.decode(errors='replace')}"
            )
        verification = project / "gradle" / "verification-metadata.xml"
        verification_digest = hashlib.sha256(verification.read_bytes()).hexdigest()
        if verification_digest != ANDROID_VERIFICATION_SHA256:
            raise AssertionError(
                f"Amplify Android dependency verification graph changed: {verification_digest}"
            )
        verified_build = _bounded_run(
            [
                str(gradle),
                "--no-daemon",
                "--offline",
                "--dependency-verification=strict",
                "writeNativeGateRuntime",
            ],
            cwd=project,
            env=environment,
            timeout=300,
            limit=MAX_BUILD_OUTPUT,
        )
        if verified_build.returncode:
            raise AssertionError(
                "Amplify Android strict offline verification failed: "
                f"{verified_build.stderr.decode(errors='replace')}"
            )

        stack = AmplifyV6Stack(
            **{
                **amplify_v6_stack.__dict__,
                "api_endpoint": _local_api_endpoint(amplify_v6_stack.api_endpoint),
            }
        )
        evidence_file = work / "android-evidence.json"
        environment.update(
            {
                "AMPLIFY_ANDROID_API_ENDPOINT": stack.api_endpoint,
                "AMPLIFY_ANDROID_CLIENT_ID": stack.user_pool_client_id,
                "AMPLIFY_ANDROID_COGNITO_HOST": "cognito-native.localhost.localstack.cloud",
                "AMPLIFY_ANDROID_EVIDENCE_FILE": str(evidence_file),
                "AMPLIFY_ANDROID_NEW_PASSWORD": stack.new_password,
                "AMPLIFY_ANDROID_POOL_ID": stack.user_pool_id,
                "AMPLIFY_ANDROID_REGION": region_name,
                "AMPLIFY_ANDROID_TEMPORARY_PASSWORD": stack.temporary_password,
                "AMPLIFY_ANDROID_TENANT_ID": stack.tenant_id,
                "AMPLIFY_ANDROID_USERNAME": stack.username,
            }
        )
        profile = (
            "(version 1)(allow default)(deny network*)"
            '(allow network-outbound (literal "/private/var/run/mDNSResponder"))'
            '(allow network-outbound (remote ip "localhost:*"))'
        )
        runtime_properties = []
        for line in properties_file.read_text().splitlines():
            key, separator, value = line.partition("\t")
            if not separator or not key or "\x00" in value:
                raise AssertionError("Amplify Android runtime property shape changed")
            runtime_properties.append(f"-D{key}={value}")
        runtime_properties.extend(
            [
                f"-Drobolectric.dependency.dir={environment['AMPLIFY_ANDROID_ROBOLECTRIC_DIR']}",
                "-Drobolectric.offline=true",
            ]
        )
        with _tls_relay(endpoint.port) as relay:
            try:
                runtime = _bounded_run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-p",
                        profile,
                        str(Path(environment["JAVA_HOME"]) / "bin" / "java"),
                        "-ea",
                        "-Djava.net.preferIPv4Stack=true",
                        *runtime_properties,
                        "-cp",
                        classpath_file.read_text(),
                        "org.junit.runner.JUnitCore",
                        "localstack.cognito.nativegate.AmplifyNativeProtocolTest",
                    ],
                    cwd=project,
                    env=environment,
                    timeout=120,
                    limit=MAX_RUNTIME_OUTPUT,
                )
            except AssertionError as error:
                progress = evidence_file.read_text() if evidence_file.is_file() else "not-entered"
                raise AssertionError(f"{error}; Android gate progress: {progress}") from error
        if runtime.returncode:
            raise AssertionError(
                "Amplify Android native gate failed:\n"
                f"stdout:\n{runtime.stdout.decode(errors='replace')}\n"
                f"stderr:\n{runtime.stderr.decode(errors='replace')}"
            )
        evidence = json.loads(evidence_file.read_text())
        assert evidence == {
            "apiStatus": "ok",
            "globalSignOut": True,
            "groups": ["trainer"],
            "newPassword": True,
            "refresh": True,
            "robolectricKeyStoreAliases": 0,
            "robolectricKeyStoreProviderClass": (
                "localstack.cognito.nativegate.TestOwnedLegacyKeyStoreProvider"
            ),
            "robolectricKeyStoreProviderName": "LocalStackRobolectricAndroidKeyStore",
            "robolectricKeyStoreWritesRejected": True,
            "sdk": "Amplify Android 2.39.0",
            "tenantId": stack.tenant_id,
            "totp": True,
        }
        assert relay.connections > 0
        assert relay.transferred > 0
    assert hashlib.sha256(ANDROID_SOURCE.read_bytes()).hexdigest() == source_hash
