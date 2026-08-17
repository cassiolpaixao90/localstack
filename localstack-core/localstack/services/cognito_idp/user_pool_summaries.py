from __future__ import annotations

import copy
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

_REGION = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")


class UserPoolSummaryError(ValueError):
    """A ListUserPools summary can't be safely constructed."""


def user_pool_summary(pool: object, *, replica_regions: Iterable[object]) -> dict[str, Any]:
    pool_id = _field(pool, "pool_id")
    name = _field(pool, "name")
    created_at = _field(pool, "created_at")
    updated_at = _field(pool, "updated_at")
    if not isinstance(pool_id, str) or not pool_id or len(pool_id) > 55:
        raise UserPoolSummaryError("Invalid user pool ID")
    if not isinstance(name, str) or not 1 <= len(name) <= 128:
        raise UserPoolSummaryError("Invalid user pool name")
    if not isinstance(created_at, datetime) or not isinstance(updated_at, datetime):
        raise UserPoolSummaryError("Invalid user pool timestamps")
    regions: list[str] = []
    for region in replica_regions:
        if not isinstance(region, str) or len(region) > 64 or _REGION.fullmatch(region) is None:
            raise UserPoolSummaryError("Invalid replica region")
        regions.append(region)
    response: dict[str, Any] = {
        "Id": pool_id,
        "Name": name,
        "CreationDate": created_at,
        "LastModifiedDate": updated_at,
    }
    lambda_config = _field(pool, "lambda_config", default={})
    if lambda_config:
        if not isinstance(lambda_config, Mapping):
            raise UserPoolSummaryError("Invalid LambdaConfig")
        response["LambdaConfig"] = copy.deepcopy(dict(lambda_config))
    unique_regions = sorted(set(regions))
    if unique_regions:
        response["ReplicaRegions"] = unique_regions
    return response


def _field(value: object, name: str, *, default: object = None) -> object:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)
