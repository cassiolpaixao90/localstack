from __future__ import annotations

import base64
import copy
import html
import json
import re
import struct
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from localstack.services.cognito_idp.image_validation import (
    ImageValidationError,
    validate_jpeg,
)

MAX_CLASSIC_UI_REQUEST_BYTES = 135 * 1024
MAX_CLASSIC_UI_CSS_BYTES = 131_072
MAX_CLASSIC_UI_IMAGE_BYTES = 100 * 1024

_SELECTOR_PROPERTIES = {
    "background-customizable": {"background-color"},
    "banner-customizable": {"background-color", "padding"},
    "errorMessage-customizable": {
        "background",
        "border",
        "box-sizing",
        "color",
        "font-size",
        "margin",
        "padding",
        "width",
    },
    "idpButton-customizable": {
        "background-color",
        "border-color",
        "color",
        "height",
        "margin-bottom",
        "text-align",
        "width",
    },
    "idpButton-customizable:hover": {"background-color", "color"},
    "idpDescription-customizable": {
        "color",
        "display",
        "font-size",
        "padding-bottom",
        "padding-top",
    },
    "inputField-customizable": {
        "background-color",
        "border",
        "border-radius",
        "color",
        "height",
        "width",
    },
    "inputField-customizable:focus": {"border-color", "outline"},
    "label-customizable": {"color", "font-weight"},
    "legalText-customizable": {"color", "font-size"},
    "logo-customizable": {"background-color", "max-height", "max-width"},
    "passwordCheck-notValid-customizable": {"color"},
    "passwordCheck-valid-customizable": {"color"},
    "redirect-customizable": {"text-align"},
    "socialButton-customizable": {
        "border-radius",
        "height",
        "margin-bottom",
        "padding",
        "text-align",
        "width",
    },
    "submitButton-customizable": {
        "background-color",
        "color",
        "font-size",
        "font-weight",
        "height",
        "margin",
        "text-align",
        "width",
    },
    "submitButton-customizable:hover": {"background-color", "color"},
    "textDescription-customizable": {
        "color",
        "display",
        "font-size",
        "padding-bottom",
        "padding-top",
    },
}

_COLOR = re.compile(
    r"(?:#[0-9a-fA-F]{3,8}|[a-zA-Z]{1,32}|rgba?\([0-9.,% ]{5,64}\)|hsla?\([0-9.,% ]{5,64}\))"
)
_LENGTH = re.compile(r"-?(?:0|[1-9][0-9]{0,3})(?:\.[0-9]{1,3})?(?:px|%)")
_BLOCK = re.compile(r"\s*\.([A-Za-z][A-Za-z0-9-]*(?::(?:focus|hover))?)\s*\{([^{}]*)\}")


class ClassicUIError(ValueError):
    pass


@dataclass
class ClassicUICustomization:
    client_id: str
    css: str
    image: bytes | None
    image_extension: str | None
    image_url: str | None
    css_version: str
    created_at: datetime
    updated_at: datetime


def validate_classic_ui_update(
    *, css: Any = None, image: Any = None, css_supplied: bool, image_supplied: bool
) -> tuple[str | None, tuple[bytes, str] | None]:
    validated_css = validate_classic_css(css) if css_supplied else None
    validated_image = validate_classic_image(image) if image_supplied else None
    request = {}
    if css_supplied:
        request["CSS"] = css
    if image_supplied:
        request["ImageFile"] = (
            "" if validated_image is None else base64.b64encode(validated_image[0]).decode()
        )
    if len(json.dumps(request, separators=(",", ":")).encode()) > MAX_CLASSIC_UI_REQUEST_BYTES:
        raise ClassicUIError("Classic UI customization request exceeds 135 KB")
    return validated_css, validated_image


def validate_classic_css(value: Any) -> str:
    if not isinstance(value, str) or len(value.encode()) > MAX_CLASSIC_UI_CSS_BYTES:
        raise ClassicUIError("Invalid classic UI CSS")
    if not value:
        return ""
    if any(ord(character) < 0x20 and character not in "\t\r\n" for character in value):
        raise ClassicUIError("Invalid control character in classic UI CSS")
    if "\\" in value or "@" in value or "<" in value or ">" in value:
        raise ClassicUIError("CSS escapes and at-rules are not supported")
    without_comments = re.sub(r"/\*.*?\*/", "", value, flags=re.DOTALL)
    if "/*" in without_comments or "*/" in without_comments:
        raise ClassicUIError("Unterminated classic UI CSS comment")
    offset = 0
    found = False
    for match in _BLOCK.finditer(without_comments):
        if without_comments[offset : match.start()].strip():
            raise ClassicUIError("Invalid classic UI CSS syntax")
        selector, declarations = match.groups()
        allowed = _SELECTOR_PROPERTIES.get(selector)
        if allowed is None:
            raise ClassicUIError(f"Unsupported classic UI selector: {selector}")
        _validate_declarations(declarations, allowed)
        found, offset = True, match.end()
    if without_comments[offset:].strip() or not found:
        raise ClassicUIError("Invalid classic UI CSS syntax")
    return without_comments.strip()


def validate_classic_image(value: Any) -> tuple[bytes, str] | None:
    if value is None or value == b"" or value == bytearray():
        return None
    if not isinstance(value, (bytes, bytearray)):
        raise ClassicUIError("ImageFile must be binary")
    content = bytes(value)
    if len(content) > MAX_CLASSIC_UI_IMAGE_BYTES:
        raise ClassicUIError("Classic UI image exceeds 100 KB")
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        _validate_png(content)
        return content, "png"
    if content.startswith(b"\xff\xd8"):
        try:
            validate_jpeg(
                content,
                max_width=350,
                max_height=178,
                max_pixels=350 * 178,
            )
        except ImageValidationError as exc:
            raise ClassicUIError("Invalid JPEG classic UI image") from exc
        return content, "jpeg"
    raise ClassicUIError("Classic UI ImageFile must be PNG, JPG, or JPEG")


def apply_classic_ui_update(
    existing: ClassicUICustomization | None,
    *,
    client_id: str,
    css: str | None,
    image: tuple[bytes, str] | None,
    css_supplied: bool,
    image_supplied: bool,
    image_url: str | None,
    now: datetime,
) -> ClassicUICustomization:
    if now.tzinfo is None:
        raise ClassicUIError("Classic UI timestamps must be timezone-aware")
    next_css = css if css_supplied else existing.css if existing else ""
    next_image = image[0] if image_supplied and image else existing.image if existing else None
    next_extension = (
        image[1] if image_supplied and image else existing.image_extension if existing else None
    )
    if image_supplied and image is None:
        next_image = next_extension = None
        image_url = None
    elif not image_supplied and existing is not None:
        image_url = existing.image_url
    version = now.astimezone(UTC).strftime("%Y%m%d%H%M%S%f")
    if existing is not None:
        if now < existing.updated_at:
            raise ClassicUIError("Classic UI update clock moved backwards")
        if version <= existing.css_version:
            version = str(int(existing.css_version) + 1).zfill(len(existing.css_version))
    return ClassicUICustomization(
        client_id=client_id,
        css=next_css or "",
        image=bytes(next_image) if next_image is not None else None,
        image_extension=next_extension,
        image_url=image_url,
        css_version=version,
        created_at=existing.created_at if existing else now,
        updated_at=now,
    )


def customization_response(pool_id: str, item: ClassicUICustomization) -> dict[str, Any]:
    result = {
        "ClientId": item.client_id,
        "CreationDate": item.created_at,
        "CSS": item.css,
        "CSSVersion": item.css_version,
        "LastModifiedDate": item.updated_at,
        "UserPoolId": pool_id,
    }
    if item.image_url is not None:
        result["ImageUrl"] = item.image_url
    return result


def inherited_customization(
    customizations: dict[str, ClassicUICustomization], client_id: str | None
) -> ClassicUICustomization | None:
    if client_id is not None and client_id in customizations:
        return copy.deepcopy(customizations[client_id])
    default = customizations.get("ALL")
    return copy.deepcopy(default) if default is not None else None


def safe_image_path(pool_id: str, client_id: str, version: str, extension: str) -> str:
    if (
        re.fullmatch(r"[\w-]+_[A-Za-z0-9]+", pool_id) is None
        or re.fullmatch(r"(?:ALL|[\w+]{1,128})", client_id) is None
        or re.fullmatch(r"[0-9]{14,20}", version) is None
        or extension not in {"jpeg", "jpg", "png"}
    ):
        raise ClassicUIError("Invalid classic UI image path")
    return f"/cognito-idp/classic-ui/{pool_id}/{client_id}/{version}/logo.{extension}"


def classic_markup(item: ClassicUICustomization | None) -> tuple[str, str]:
    if item is None:
        return "", ""
    style = f'<style id="classic-ui-customization">{item.css}</style>' if item.css else ""
    if item.image_url is None:
        return style, ""
    if not item.image_url.startswith("/cognito-idp/classic-ui/") or any(
        character in item.image_url for character in {'"', "'", "<", ">", "\\"}
    ):
        raise ClassicUIError("Unsafe classic UI ImageUrl")
    logo = f'<img class="logo-customizable" alt="" src="{html.escape(item.image_url, quote=True)}">'
    return style, logo


def _validate_declarations(value: str, allowed: set[str]) -> None:
    declarations = [item.strip() for item in value.split(";") if item.strip()]
    if not declarations or len(declarations) > 32:
        raise ClassicUIError("Invalid classic UI CSS declarations")
    seen = set()
    for declaration in declarations:
        if declaration.count(":") != 1:
            raise ClassicUIError("Invalid classic UI CSS declaration")
        name, item = (part.strip() for part in declaration.split(":", 1))
        if name not in allowed or name in seen:
            raise ClassicUIError(f"Unsupported classic UI CSS property: {name}")
        if not _valid_property(name, item):
            raise ClassicUIError(f"Invalid classic UI CSS value for {name}")
        seen.add(name)


def _valid_property(name: str, value: str) -> bool:
    lowered = value.lower()
    if any(
        marker in lowered
        for marker in ("javascript", "expression", "url(", "var(", "attr(", "<!--", "-->")
    ):
        return False
    if name in {
        "background",
        "background-color",
        "border-color",
        "color",
    }:
        return _COLOR.fullmatch(value) is not None
    if name in {"height", "font-size", "margin-bottom", "padding-bottom", "padding-top"}:
        return _LENGTH.fullmatch(value) is not None
    if name in {"max-height", "max-width", "width"}:
        return _percentage(value)
    if name in {"margin", "padding"}:
        parts = value.split()
        return 1 <= len(parts) <= 4 and all(_LENGTH.fullmatch(item) for item in parts)
    if name == "border":
        parts = value.split()
        return (
            len(parts) == 3
            and _bounded_pixels(parts[0], 1, 100)
            and parts[1] in {"none", "solid"}
            and _COLOR.fullmatch(parts[2]) is not None
        )
    if name == "border-radius":
        return _bounded_pixels(value, 0, 100)
    if name == "outline":
        return value == "0" or _bounded_pixels(value, 0, 100)
    if name == "font-weight":
        return value in {"bold", "italic", "normal"} or (
            value.isdigit() and 100 <= int(value) <= 900 and int(value) % 100 == 0
        )
    if name == "display":
        return value in {"block", "inline"}
    if name == "text-align":
        return value in {"center", "left", "right"}
    if name == "box-sizing":
        return value in {"border-box", "content-box"}
    return False


def _percentage(value: str) -> bool:
    if re.fullmatch(r"(?:0|[1-9][0-9]{0,2})(?:\.[0-9]{1,3})?%", value) is None:
        return False
    return 0 <= float(value[:-1]) <= 200


def _bounded_pixels(value: str, minimum: int, maximum: int) -> bool:
    match = re.fullmatch(r"([0-9]{1,3})(?:\.([0-9]{1,3}))?px", value)
    return match is not None and minimum <= float(value[:-2]) <= maximum


def _validate_png(content: bytes) -> None:
    offset = 8
    compressed = bytearray()
    width = height = channels = expected_size = 0
    saw_header = saw_data = saw_end = False
    chunks = 0
    while offset < len(content) and chunks < 128:
        if offset + 12 > len(content):
            break
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        kind = content[offset + 4 : offset + 8]
        end = offset + 12 + length
        if length > MAX_CLASSIC_UI_IMAGE_BYTES or end > len(content):
            break
        data = content[offset + 8 : offset + 8 + length]
        crc = struct.unpack(">I", content[offset + 8 + length : end])[0]
        if zlib.crc32(kind + data) & 0xFFFFFFFF != crc:
            break
        if chunks == 0:
            if kind != b"IHDR" or length != 13:
                break
            width, height = struct.unpack(">II", data[:8])
            channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(data[9], 0)
            if (
                not 1 <= width <= 350
                or not 1 <= height <= 178
                or data[8] != 8
                or channels == 0
                or data[10:13] != b"\0\0\0"
            ):
                break
            expected_size = height * (1 + width * channels)
            saw_header = True
        elif kind == b"IDAT":
            if not saw_header or saw_end:
                break
            compressed.extend(data)
            saw_data = True
        elif kind == b"IEND":
            saw_end = length == 0 and end == len(content)
            offset = end
            break
        offset, chunks = end, chunks + 1
    valid = saw_header and saw_data and saw_end and offset == len(content)
    if valid:
        try:
            decompressor = zlib.decompressobj()
            pixels = decompressor.decompress(bytes(compressed), expected_size + 1)
            if decompressor.unconsumed_tail:
                raise zlib.error("PNG expands beyond declared dimensions")
            pixels += decompressor.flush()
            stride = 1 + width * channels
            valid = (
                decompressor.eof
                and not decompressor.unused_data
                and len(pixels) == expected_size
                and all(pixels[row * stride] <= 4 for row in range(height))
            )
        except zlib.error:
            valid = False
    if not valid:
        raise ClassicUIError("Invalid PNG classic UI image")
