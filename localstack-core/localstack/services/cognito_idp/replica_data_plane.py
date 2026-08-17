import copy
import dataclasses
import re
from datetime import datetime
from typing import Any

from localstack.services.cognito_idp.user_pool_replicas import (
    UserPoolReplicaError,
    UserPoolReplicaTopology,
    reconcile_replica,
)

_OPERATIONS = {"AUTHENTICATE", "CONFIG_WRITE", "JWKS", "READ", "TOKEN", "USER_WRITE"}
_SECONDARY_OPERATIONS = {"AUTHENTICATE", "CONFIG_WRITE", "JWKS", "READ", "TOKEN"}
_DNS_SUFFIXES = {
    "aws": "amazonaws.com",
    "aws-cn": "amazonaws.com.cn",
    "aws-iso": "c2s.ic.gov",
    "aws-iso-b": "sc2s.sgov.gov",
    "aws-us-gov": "amazonaws.com",
}
_POOL_ID_PATTERN = re.compile(r"[\w-]+_[0-9a-zA-Z]+")


class ReplicaDataPlaneError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class RegionalPoolView:
    primary_pool: Any
    serving_region: str
    role: str
    issuer: str
    user_pool_arn: str

    @property
    def users(self) -> Any:
        return self.primary_pool.users

    @property
    def clients(self) -> Any:
        return self.primary_pool.clients

    def jwks(self) -> dict[str, list[dict[str, Any]]]:
        keys = []
        for identifier_field, jwk_field in (
            ("access_signing_key_id", "access_signing_jwk"),
            ("id_signing_key_id", "id_signing_jwk"),
        ):
            identifier = getattr(self.primary_pool, identifier_field, None)
            jwk = getattr(self.primary_pool, jwk_field, None)
            if (
                not isinstance(identifier, str)
                or not 1 <= len(identifier) <= 256
                or not isinstance(jwk, dict)
                or jwk.get("kid") != identifier
            ):
                raise ReplicaDataPlaneError(
                    "InternalError", "Primary user pool signing configuration is invalid"
                )
            keys.append(copy.deepcopy(jwk))
        if keys[0]["kid"] == keys[1]["kid"]:
            raise ReplicaDataPlaneError(
                "InternalError", "Primary user pool signing keys are not distinct"
            )
        return {"keys": keys}

    def token_claims(self, claims: Any) -> dict[str, Any]:
        if not isinstance(claims, dict) or len(claims) > 128:
            raise ReplicaDataPlaneError("InvalidParameterException", "Invalid token claims")
        result = copy.deepcopy(claims)
        result["iss"] = self.issuer
        return result


def resolve_regional_pool(
    topology: UserPoolReplicaTopology,
    primary_pool: Any,
    *,
    serving_region: Any,
    operation: Any,
    dns_suffix: Any,
    now: datetime | None = None,
) -> RegionalPoolView:
    try:
        secondary = reconcile_replica(topology, now=now)
    except UserPoolReplicaError as error:
        raise ReplicaDataPlaneError(error.code, str(error))
    if operation not in _OPERATIONS:
        raise ReplicaDataPlaneError("InvalidParameterException", "Unknown replica operation class")
    if (
        not isinstance(serving_region, str)
        or not isinstance(dns_suffix, str)
        or _DNS_SUFFIXES.get(topology.partition) != dns_suffix
    ):
        raise ReplicaDataPlaneError("InvalidParameterException", "Invalid regional endpoint")
    pool_id = getattr(primary_pool, "pool_id", None)
    pool_arn = getattr(primary_pool, "arn", None)
    expected_primary_arn = (
        f"arn:{topology.partition}:cognito-idp:{topology.primary_region}:"
        f"{topology.account_id}:userpool/{topology.pool_id}"
    )
    if (
        pool_id != topology.pool_id
        or not isinstance(pool_id, str)
        or _POOL_ID_PATTERN.fullmatch(pool_id) is None
        or pool_arn != expected_primary_arn
        or not isinstance(getattr(primary_pool, "users", None), dict)
        or not isinstance(getattr(primary_pool, "clients", None), dict)
    ):
        raise ReplicaDataPlaneError("InternalError", "Primary user pool topology is inconsistent")

    if serving_region == topology.primary_region:
        role = "PRIMARY"
    elif secondary is None or serving_region != secondary.region_name:
        raise ReplicaDataPlaneError(
            "ResourceNotFoundException", "Regional user pool does not exist"
        )
    else:
        role = "SECONDARY"
        if secondary.status != "ACTIVE" or operation not in _SECONDARY_OPERATIONS:
            raise ReplicaDataPlaneError(
                "OperationNotEnabledException",
                "The secondary user pool is not enabled for this operation",
            )

    issuer = f"https://cognito-idp.{serving_region}.{dns_suffix}/{pool_id}"
    user_pool_arn = (
        f"arn:{topology.partition}:cognito-idp:{serving_region}:"
        f"{topology.account_id}:userpool/{pool_id}"
    )
    return RegionalPoolView(
        primary_pool=primary_pool,
        serving_region=serving_region,
        role=role,
        issuer=issuer,
        user_pool_arn=user_pool_arn,
    )
