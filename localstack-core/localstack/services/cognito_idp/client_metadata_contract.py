from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from types import MappingProxyType

_OPERATIONS = frozenset(
    {
        "SignUp",
        "ConfirmSignUp",
        "ForgotPassword",
        "ConfirmForgotPassword",
        "ResendConfirmationCode",
        "GetTokensFromRefreshToken",
    }
)
_MAX_STRING_CHARACTERS = 131_072
_MAX_TOTAL_BYTES = 8 * 1024 * 1024


class ClientMetadataError(ValueError):
    """ClientMetadata doesn't satisfy the public API contract."""


@dataclasses.dataclass(frozen=True)
class TransientClientMetadata:
    operation: str
    _metadata: Mapping[str, str]

    def trigger_payload(self) -> dict[str, dict[str, str]]:
        return {"clientMetadata": dict(self._metadata)}

    def __getstate__(self):
        raise TypeError("ClientMetadata is request-scoped and must not be persisted")


def transient_client_metadata(
    operation: object, metadata: object = None
) -> TransientClientMetadata:
    if not isinstance(operation, str) or operation not in _OPERATIONS:
        raise ClientMetadataError("Unsupported ClientMetadata operation")
    normalized = normalize_client_metadata(metadata)
    return TransientClientMetadata(operation=operation, _metadata=MappingProxyType(normalized))


def normalize_client_metadata(metadata: object = None) -> dict[str, str]:
    if metadata is None:
        normalized: dict[str, str] = {}
    elif isinstance(metadata, Mapping):
        normalized = {}
        total_bytes = 0
        for key, value in metadata.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ClientMetadataError("ClientMetadata must be a string-to-string map")
            if len(key) > _MAX_STRING_CHARACTERS or len(value) > _MAX_STRING_CHARACTERS:
                raise ClientMetadataError("ClientMetadata entry exceeds the API shape")
            total_bytes += len(key.encode()) + len(value.encode())
            if total_bytes > _MAX_TOTAL_BYTES:
                raise ClientMetadataError("ClientMetadata request is too large")
            normalized[key] = value
    else:
        raise ClientMetadataError("ClientMetadata must be a string-to-string map")
    return normalized
