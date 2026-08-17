from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from localstack.services.cloudformation.resource_provider import OperationStatus, ProgressEvent


def failed(message: str, *, error_code: str = "InvalidRequest") -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.FAILED,
        message=message,
        error_code=error_code,
    )


def not_found(resource_type: str, identifier: str) -> ProgressEvent:
    return failed(
        f"Resource of type '{resource_type}' with identifier '{identifier}' was not found.",
        error_code="NotFound",
    )


def is_not_found(error: Exception) -> bool:
    return isinstance(error, ClientError) and error.response.get("Error", {}).get("Code") in {
        "ResourceNotFoundException",
        "UserNotFoundException",
    }


def unsupported_properties(model: dict[str, Any], allowed: set[str]) -> list[str]:
    return sorted(set(model) - allowed)
