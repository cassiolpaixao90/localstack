from __future__ import annotations

import threading
from collections.abc import MutableMapping

_MAX_STRING_CHARACTERS = 131_072
_MAX_STRING_BYTES = 131_072
_MAX_POOL_ID_BYTES = 55
_MAX_USERNAME_BYTES = 128


class FriendlyDeviceNameError(ValueError):
    """The authenticator name or its identity binding is invalid."""


class FriendlyDeviceNames:
    """A persistence-friendly store for VerifySoftwareToken friendly device names."""

    def __init__(
        self,
        state: MutableMapping[tuple[str, str], str],
        *,
        lock: threading.RLock | None = None,
    ):
        if not isinstance(state, MutableMapping):
            raise TypeError("state must be mutable mapping")
        self._state = state
        self._lock = lock or threading.RLock()

    def set(self, pool_id: object, username: object, name: object) -> None:
        key = self._key(pool_id, username)
        name = normalize_friendly_device_name(name)
        with self._lock:
            self._state[key] = name

    def get(self, pool_id: object, username: object) -> str | None:
        key = self._key(pool_id, username)
        with self._lock:
            return self._state.get(key)

    def remove_user(self, pool_id: object, username: object) -> None:
        key = self._key(pool_id, username)
        with self._lock:
            self._state.pop(key, None)

    def remove_pool(self, pool_id: object) -> None:
        pool_id = self._bounded_text(pool_id, "pool ID", _MAX_POOL_ID_BYTES)
        with self._lock:
            for key in tuple(self._state):
                if key[0] == pool_id:
                    self._state.pop(key, None)

    @classmethod
    def _key(cls, pool_id: object, username: object) -> tuple[str, str]:
        return (
            cls._bounded_text(pool_id, "pool ID", _MAX_POOL_ID_BYTES),
            cls._bounded_text(username, "username", _MAX_USERNAME_BYTES),
        )

    @staticmethod
    def _bounded_text(value: object, label: str, maximum: int) -> str:
        if not isinstance(value, str) or not value or len(value.encode()) > maximum:
            raise FriendlyDeviceNameError(f"Invalid {label}")
        return value


def normalize_friendly_device_name(name: object) -> str:
    if not isinstance(name, str):
        raise FriendlyDeviceNameError("FriendlyDeviceName must be a string")
    if len(name) > _MAX_STRING_CHARACTERS or len(name.encode()) > _MAX_STRING_BYTES:
        raise FriendlyDeviceNameError("FriendlyDeviceName exceeds supported bounds")
    return name
