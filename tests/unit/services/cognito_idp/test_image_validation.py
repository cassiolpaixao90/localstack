import base64
import struct

import pytest

from localstack.services.cognito_idp.image_validation import (
    ImageValidationError,
    validate_jpeg,
    validate_webp,
)

BASELINE_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcU"
    "FhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgo"
    "KCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCAACAAIDASIAAhEB"
    "AxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQ"
    "IDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RF"
    "RkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztL"
    "W2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEB"
    "AQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMo"
    "EIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVm"
    "Z2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0t"
    "PU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3X4b6Ppk/w78LTT6dZySyaVau"
    "7vApZmMKkkkjkmiiivlcR/Fn6v8AM+Kxf8efq/zP/9k="
)

PROGRESSIVE_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcU"
    "FhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgo"
    "KCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wgARCAACAAIDASIAAhEB"
    "AxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAUAQEAAAAAAAAAAAAAAAAAAAAF/9oADAMBAAIQAxAA"
    "AAG6BQn/xAAWEAEBAQAAAAAAAAAAAAAAAAADBQH/2gAIAQEAAQUCmiezv//EABcRAAMBAAAAAAAAAAAA"
    "AAAAAAABAzL/2gAIAQMBAT8Brtn/xAAXEQADAQAAAAAAAAAAAAAAAAAAAQMy/9oACAECAQE/AaaZ/8QA"
    "GhABAAIDAQAAAAAAAAAAAAAAAQIDAARBYf/aAAgBAQAGPwLVWuCtUeeZ/8QAFhABAQEAAAAAAAAAAAAA"
    "AAAAAREA/9oACAEBAAE/IUzAqmrO/9oADAMBAAIAAwAAABD3/8QAFxEAAwEAAAAAAAAAAAAAAAAAAAGh"
    "sf/aAAgBAwEBPxC96f/EABcRAAMBAAAAAAAAAAAAAAAAAAABobH/2gAIAQIBAT8Qren/xAAWEAEBAQAA"
    "AAAAAAAAAAAAAAABACH/2gAIAQEAAT8QTWV8hFVNW//Z"
)


@pytest.mark.parametrize("content", [BASELINE_JPEG, PROGRESSIVE_JPEG])
def test_jpeg_validator_consumes_real_entropy_stream(content):
    assert validate_jpeg(content, max_width=350, max_height=178, max_pixels=62_300) == (
        2,
        2,
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value[:-1],
        lambda value: value + b"trailing",
        lambda value: value[: value.index(b"\xff\xda") + 20] + b"\xff\xd9",
        lambda value: value.replace(b"\xff\xc4", b"\xff\xee", 1),
    ],
)
def test_jpeg_validator_rejects_truncation_bad_entropy_and_missing_tables(mutate):
    with pytest.raises(ImageValidationError):
        validate_jpeg(mutate(BASELINE_JPEG), max_width=350, max_height=178, max_pixels=62_300)


def test_jpeg_validator_rejects_dimensions_before_allocating_coefficient_state():
    content = bytearray(BASELINE_JPEG)
    sof = content.index(b"\xff\xc0")
    content[sof + 5 : sof + 9] = struct.pack(">HH", 65_535, 65_535)
    with pytest.raises(ImageValidationError, match="dimensions|budget"):
        validate_jpeg(bytes(content), max_width=4096, max_height=4096, max_pixels=16_777_216)


def test_webp_remains_rejected_because_aws_managed_login_has_no_accepted_category():
    # A RIFF/VP8X envelope is not evidence that the VP8 payload can be decoded. More
    # importantly, the current Cognito category table accepts no WEBP asset role.
    fake = b"RIFF" + struct.pack("<I", 22) + b"WEBPVP8X" + struct.pack("<I", 10) + b"\0" * 10
    with pytest.raises(ImageValidationError, match="not accepted"):
        validate_webp(fake, max_width=4096, max_height=4096, max_pixels=16_777_216)
