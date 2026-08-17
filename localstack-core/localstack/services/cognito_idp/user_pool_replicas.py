import base64
import dataclasses
import hashlib
import hmac
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

_REGION_PATTERN = re.compile(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]")
_POOL_ID_PATTERN = re.compile(r"[\w-]+_[0-9a-zA-Z]+")
_STATUSES = {"ACTIVE", "INACTIVE"}
_MAX_TAGS = 50
_TRANSITION_DELAY = timedelta(seconds=1)


class UserPoolReplicaError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass
class UserPoolReplica:
    region_name: str
    status: str
    tags: dict[str, str] = dataclasses.field(default_factory=dict)
    regional_configuration: dict[str, Any] = dataclasses.field(default_factory=dict)
    transition_at: datetime | None = None


@dataclasses.dataclass
class UserPoolReplicaTopology:
    account_id: str
    partition: str
    pool_id: str
    primary_region: str
    secondary: UserPoolReplica | None = None


def create_replica(
    topology: UserPoolReplicaTopology,
    *,
    caller_region: Any,
    region_name: Any,
    tags: Any = None,
    eligible: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    _validate_topology(topology)
    now = _time(now)
    _reconcile(topology, now)
    caller_region = _region(caller_region)
    region_name = _region(region_name)
    tags = _tags(tags)
    if caller_region != topology.primary_region:
        raise UserPoolReplicaError(
            "OperationNotEnabledException", "CreateUserPoolReplica must run in the primary Region"
        )
    if not eligible:
        raise UserPoolReplicaError(
            "FeatureUnavailableInTierException", "User pool is not eligible for replication"
        )
    if region_name == topology.primary_region:
        raise UserPoolReplicaError(
            "InvalidParameterException", "Replica Region must differ from the primary Region"
        )
    if topology.secondary is not None:
        if topology.secondary.region_name == region_name:
            raise UserPoolReplicaError("InvalidParameterException", "Replica already exists")
        raise UserPoolReplicaError(
            "LimitExceededException", "Only one secondary replica is allowed"
        )
    topology.secondary = UserPoolReplica(
        region_name=region_name,
        status="CREATING",
        tags=tags,
        transition_at=now + _TRANSITION_DELAY,
    )
    return {"UserPoolReplica": _secondary_response(topology, topology.secondary)}


def update_replica(
    topology: UserPoolReplicaTopology,
    *,
    caller_region: Any,
    region_name: Any,
    status: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    _validate_topology(topology)
    _reconcile(topology, _time(now))
    caller_region = _region(caller_region)
    region_name = _region(region_name)
    if caller_region not in {topology.primary_region, region_name}:
        raise UserPoolReplicaError(
            "OperationNotEnabledException", "Replica update must run in a replica Region"
        )
    if status not in _STATUSES:
        raise UserPoolReplicaError("InvalidParameterException", "Invalid replica Status")
    replica = _secondary(topology, region_name)
    if replica.status in {"CREATING", "DELETING"}:
        raise UserPoolReplicaError(
            "InvalidParameterException", "Replica transition is still in progress"
        )
    replica.status = status
    replica.transition_at = None
    return {"UserPoolReplica": _secondary_response(topology, replica)}


def delete_replica(
    topology: UserPoolReplicaTopology,
    *,
    caller_region: Any,
    region_name: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    _validate_topology(topology)
    now = _time(now)
    _reconcile(topology, now)
    caller_region = _region(caller_region)
    region_name = _region(region_name)
    if caller_region != topology.primary_region:
        raise UserPoolReplicaError(
            "OperationNotEnabledException", "DeleteUserPoolReplica must run in the primary Region"
        )
    replica = _secondary(topology, region_name)
    if replica.status != "INACTIVE":
        raise UserPoolReplicaError(
            "InvalidParameterException", "Only an INACTIVE replica can be deleted"
        )
    replica.status = "DELETING"
    replica.transition_at = now + _TRANSITION_DELAY
    response = _secondary_response(topology, replica)
    return {"UserPoolReplica": response}


def list_replicas(
    topology: UserPoolReplicaTopology,
    *,
    next_token: Any = None,
    signing_key: bytes,
    page_size: int = 2,
    now: datetime | None = None,
) -> dict[str, Any]:
    _validate_topology(topology)
    _reconcile(topology, _time(now))
    if not isinstance(signing_key, bytes) or len(signing_key) < 16:
        raise UserPoolReplicaError("InvalidParameterException", "Invalid pagination signing key")
    if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= 2:
        raise UserPoolReplicaError("InvalidParameterException", "Invalid replica page size")
    replicas = [_primary_response(topology)]
    if topology.secondary is not None:
        replicas.append(_secondary_response(topology, topology.secondary))
    offset = _decode_page_token(topology, next_token, signing_key)
    page = replicas[offset : offset + page_size]
    response: dict[str, Any] = {"UserPoolReplicas": page}
    next_offset = offset + len(page)
    if next_offset < len(replicas):
        response["NextToken"] = _encode_page_token(topology, next_offset, signing_key)
    return response


def reconcile_replica(
    topology: UserPoolReplicaTopology, *, now: datetime | None = None
) -> UserPoolReplica | None:
    """Reconcile asynchronous replica state and return the current secondary."""
    _validate_topology(topology)
    _reconcile(topology, _time(now))
    return topology.secondary


def _primary_response(topology: UserPoolReplicaTopology) -> dict[str, str]:
    return {
        "RegionName": topology.primary_region,
        "Role": "PRIMARY",
        "Status": "ACTIVE",
        "UserPoolArn": _arn(topology, topology.primary_region),
    }


def _secondary_response(
    topology: UserPoolReplicaTopology, replica: UserPoolReplica
) -> dict[str, str]:
    return {
        "RegionName": replica.region_name,
        "Role": "SECONDARY",
        "Status": replica.status,
        "UserPoolArn": _arn(topology, replica.region_name),
    }


def _arn(topology: UserPoolReplicaTopology, region: str) -> str:
    return (
        f"arn:{topology.partition}:cognito-idp:{region}:{topology.account_id}:"
        f"userpool/{topology.pool_id}"
    )


def _secondary(topology: UserPoolReplicaTopology, region_name: str) -> UserPoolReplica:
    if topology.secondary is None or topology.secondary.region_name != region_name:
        raise UserPoolReplicaError("ResourceNotFoundException", "User pool replica does not exist")
    return topology.secondary


def _reconcile(topology: UserPoolReplicaTopology, now: datetime) -> None:
    replica = topology.secondary
    if replica is None:
        return
    transition_at = getattr(replica, "transition_at", None)
    if transition_at is None or now < transition_at:
        return
    if replica.status == "CREATING":
        replica.status = "INACTIVE"
        replica.transition_at = None
    elif replica.status == "DELETING":
        topology.secondary = None


def _time(value: datetime | None) -> datetime:
    value = value or datetime.now(UTC)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise UserPoolReplicaError("InvalidParameterException", "Invalid transition clock")
    return value


def _validate_topology(topology: Any) -> None:
    if not isinstance(topology, UserPoolReplicaTopology):
        raise UserPoolReplicaError("InvalidParameterException", "Invalid replica topology")
    _region(topology.primary_region)
    if (
        not isinstance(topology.account_id, str)
        or re.fullmatch(r"[0-9]{12}", topology.account_id) is None
        or topology.partition not in {"aws", "aws-cn", "aws-iso", "aws-iso-b", "aws-us-gov"}
        or not isinstance(topology.pool_id, str)
        or not 1 <= len(topology.pool_id) <= 55
        or _POOL_ID_PATTERN.fullmatch(topology.pool_id) is None
    ):
        raise UserPoolReplicaError("InvalidParameterException", "Invalid replica topology")


def _region(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 5 <= len(value) <= 32
        or _REGION_PATTERN.fullmatch(value) is None
    ):
        raise UserPoolReplicaError("InvalidParameterException", "Invalid RegionName")
    return value


def _tags(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > _MAX_TAGS:
        raise UserPoolReplicaError("InvalidParameterException", "Invalid UserPoolTags")
    result = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not isinstance(item, str)
            or len(item) > 256
        ):
            raise UserPoolReplicaError("InvalidParameterException", "Invalid UserPoolTags")
        result[key] = item
    return result


def _encode_page_token(topology: UserPoolReplicaTopology, offset: int, signing_key: bytes) -> str:
    payload = json.dumps(
        {"account": topology.account_id, "offset": offset, "pool": topology.pool_id},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    signature = hmac.new(signing_key, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + signature).rstrip(b"=").decode()


def _decode_page_token(topology: UserPoolReplicaTopology, value: Any, signing_key: bytes) -> int:
    if value is None:
        return 0
    if not isinstance(value, str) or not 1 <= len(value) <= 1024 or any(c.isspace() for c in value):
        raise UserPoolReplicaError("InvalidParameterException", "Invalid NextToken")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        payload, signature = decoded[:-32], decoded[-32:]
        expected = hmac.new(signing_key, payload, hashlib.sha256).digest()
        data = json.loads(payload)
    except (ValueError, TypeError, json.JSONDecodeError):
        raise UserPoolReplicaError("InvalidParameterException", "Invalid NextToken")
    if (
        len(signature) != 32
        or not hmac.compare_digest(expected, signature)
        or data.get("account") != topology.account_id
        or data.get("pool") != topology.pool_id
        or not isinstance(data.get("offset"), int)
        or isinstance(data.get("offset"), bool)
        or not 1 <= data["offset"] <= 1
    ):
        raise UserPoolReplicaError("InvalidParameterException", "Invalid NextToken")
    return data["offset"]
