import argparse
import os
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_JUNIT_BYTES = 1024 * 1024
EXPECTED_CLASSNAME = "tests.aws.cli.test_cdk_cli_blackbox"
EXPECTED_TEST_NAME = "test_cdk_cli_bootstrap_show_template_matches_pinned_v32"


def _required_count(element: ET.Element, name: str, expected: int) -> None:
    try:
        actual = int(element.attrib[name])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"JUnit {element.tag} has an invalid {name} count") from error
    if actual != expected:
        raise ValueError(f"JUnit {element.tag} expected {name}={expected}, got {actual}")


def validate_junit_payload(payload: bytes) -> None:
    if not payload or len(payload) > MAX_JUNIT_BYTES:
        raise ValueError("JUnit report size is outside the accepted bounds")
    if b"<!DOCTYPE" in payload.upper():
        raise ValueError("JUnit report must not contain a document type")

    root = ET.fromstring(payload)
    if root.tag != "testsuites":
        raise ValueError("JUnit root must be testsuites")
    suites = list(root)
    if len(suites) != 1 or suites[0].tag != "testsuite":
        raise ValueError("JUnit report must contain exactly one test suite")
    suite = suites[0]
    for name, expected in (("tests", 1), ("failures", 0), ("errors", 0), ("skipped", 0)):
        _required_count(suite, name, expected)

    testcases = list(suite)
    if len(testcases) != 1 or testcases[0].tag != "testcase":
        raise ValueError("JUnit report must contain exactly one test case")
    testcase = testcases[0]
    if testcase.attrib.get("classname") != EXPECTED_CLASSNAME:
        raise ValueError("JUnit report contains an unexpected test class")
    if testcase.attrib.get("name") != EXPECTED_TEST_NAME:
        raise ValueError("JUnit report contains an unexpected test name")
    if list(testcase):
        raise ValueError("JUnit test case contains a non-passing outcome")


def load_junit(path: Path) -> bytes:
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_CLOEXEC", "O_NONBLOCK", "O_NOFOLLOW"):
        flags |= getattr(os, name, 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("JUnit report must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(MAX_JUNIT_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return payload


def validate_junit(path: Path) -> None:
    validate_junit_payload(load_junit(path))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", type=Path, nargs="+")
    args = parser.parse_args()
    for report in args.reports:
        validate_junit(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
