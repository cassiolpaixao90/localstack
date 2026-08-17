# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class DynamoDBTableProperties(TypedDict):
    KeySchema: list[KeySchema] | dict | None
    Arn: str | None
    AttributeDefinitions: list[AttributeDefinition] | None
    BillingMode: str | None
    ContributorInsightsSpecification: ContributorInsightsSpecification | None
    DeletionProtectionEnabled: bool | None
    GlobalSecondaryIndexes: list[GlobalSecondaryIndex] | None
    ImportSourceSpecification: ImportSourceSpecification | None
    KinesisStreamSpecification: KinesisStreamSpecification | None
    LocalSecondaryIndexes: list[LocalSecondaryIndex] | None
    PointInTimeRecoverySpecification: PointInTimeRecoverySpecification | None
    ProvisionedThroughput: ProvisionedThroughput | None
    SSESpecification: SSESpecification | None
    StreamArn: str | None
    StreamSpecification: StreamSpecification | None
    TableClass: str | None
    TableName: str | None
    Tags: list[Tag] | None
    TimeToLiveSpecification: TimeToLiveSpecification | None


class AttributeDefinition(TypedDict):
    AttributeName: str | None
    AttributeType: str | None


class KeySchema(TypedDict):
    AttributeName: str | None
    KeyType: str | None


class Projection(TypedDict):
    NonKeyAttributes: list[str] | None
    ProjectionType: str | None


class ProvisionedThroughput(TypedDict):
    ReadCapacityUnits: int | None
    WriteCapacityUnits: int | None


class ContributorInsightsSpecification(TypedDict):
    Enabled: bool | None


class GlobalSecondaryIndex(TypedDict):
    IndexName: str | None
    KeySchema: list[KeySchema] | None
    Projection: Projection | None
    ContributorInsightsSpecification: ContributorInsightsSpecification | None
    ProvisionedThroughput: ProvisionedThroughput | None


class LocalSecondaryIndex(TypedDict):
    IndexName: str | None
    KeySchema: list[KeySchema] | None
    Projection: Projection | None


class PointInTimeRecoverySpecification(TypedDict):
    PointInTimeRecoveryEnabled: bool | None


class SSESpecification(TypedDict):
    SSEEnabled: bool | None
    KMSMasterKeyId: str | None
    SSEType: str | None


class StreamSpecification(TypedDict):
    StreamViewType: str | None


class Tag(TypedDict):
    Key: str | None
    Value: str | None


class TimeToLiveSpecification(TypedDict):
    AttributeName: str | None
    Enabled: bool | None


class KinesisStreamSpecification(TypedDict):
    StreamArn: str | None


class S3BucketSource(TypedDict):
    S3Bucket: str | None
    S3BucketOwner: str | None
    S3KeyPrefix: str | None


class Csv(TypedDict):
    Delimiter: str | None
    HeaderList: list[str] | None


class InputFormatOptions(TypedDict):
    Csv: Csv | None


class ImportSourceSpecification(TypedDict):
    InputFormat: str | None
    S3BucketSource: S3BucketSource | None
    InputCompressionType: str | None
    InputFormatOptions: InputFormatOptions | None


REPEATED_INVOCATION = "repeated_invocation"
CREATE_TABLE_ID = "create_table_id"
UPDATE_TABLE_ID = "update_table_id"
DDB_UPDATE_JOURNAL = "dynamodb_update_journal_v1"
DELETE_TABLE_ID = "delete_table_id"
DELETE_REQUESTED = "delete_requested"
MAX_TAG_PAGES = 100
MAX_TAG_ITEMS = 50
MAX_TABLE_PAGES = 100
MAX_UPDATE_JOURNAL_BYTES = 128 * 1024
MAX_UPDATE_JOURNAL_ENTRIES = 4
MAX_UPDATE_JOURNAL_TAGS = 100
MAX_UPDATE_JOURNAL_STRING_BYTES = 2048
MAX_UPDATE_JOURNAL_FAILURE_BYTES = 512
MAX_UPDATE_JOURNAL_ATTEMPTS = 32
MAX_UPDATE_JOURNAL_FORWARD_ATTEMPTS = 16

_JOURNALED_UPDATE_KINDS = {
    "tag_remove",
    "tag_upsert",
    "tag_create",
    "deletion_protection",
}
_NON_COMPENSATED_UPDATE_PROPERTIES = (
    "BillingMode",
    "ProvisionedThroughput",
    "StreamSpecification",
    "TableClass",
    "PointInTimeRecoverySpecification",
    "TimeToLiveSpecification",
    "KinesisStreamSpecification",
)


class _Mutation(NamedTuple):
    descriptor: dict
    apply: Callable[[], object]


def _mutation(*, kind: str, before, after, apply: Callable[[], object]) -> _Mutation:
    return _Mutation(
        descriptor={
            "kind": kind,
            "before": copy.deepcopy(before),
            "after": copy.deepcopy(after),
        },
        apply=apply,
    )


def _is_not_found(dynamodb, error: Exception) -> bool:
    not_found_types = tuple(
        exception
        for name in ("ResourceNotFoundException", "TableNotFoundException")
        if isinstance((exception := getattr(dynamodb.exceptions, name, None)), type)
    )
    if not_found_types and isinstance(error, not_found_types):
        return True
    response = getattr(error, "response", {})
    return response.get("Error", {}).get("Code") in {
        "ResourceNotFoundException",
        "TableNotFoundException",
    }


def _failed(message: str, error_code: str = "InvalidRequest") -> ProgressEvent:
    return ProgressEvent(
        status=OperationStatus.FAILED,
        resource_model={},
        message=message,
        error_code=error_code,
    )


def _canonical_json_bytes(value) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError("DynamoDB update journal is not canonical JSON") from error


def _bounded_failure_message(error: BaseException) -> str:
    message = str(error) or type(error).__name__
    encoded = message.encode("utf-8")[:MAX_UPDATE_JOURNAL_FAILURE_BYTES]
    return encoded.decode("utf-8", errors="ignore") or type(error).__name__


class DynamoDBTableProvider(ResourceProvider[DynamoDBTableProperties]):
    TYPE = "AWS::DynamoDB::Table"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[DynamoDBTableProperties],
    ) -> ProgressEvent[DynamoDBTableProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/TableName

        Required properties:
          - KeySchema

        Create-only properties:
          - /properties/TableName
          - /properties/ImportSourceSpecification

        Read-only properties:
          - /properties/Arn
          - /properties/StreamArn

        IAM permissions required:
          - dynamodb:CreateTable
          - dynamodb:DescribeImport
          - dynamodb:DescribeTable
          - dynamodb:DescribeTimeToLive
          - dynamodb:UpdateTimeToLive
          - dynamodb:UpdateContributorInsights
          - dynamodb:UpdateContinuousBackups
          - dynamodb:DescribeContinuousBackups
          - dynamodb:DescribeContributorInsights
          - dynamodb:EnableKinesisStreamingDestination
          - dynamodb:DisableKinesisStreamingDestination
          - dynamodb:DescribeKinesisStreamingDestination
          - dynamodb:ImportTable
          - dynamodb:ListTagsOfResource
          - dynamodb:TagResource
          - dynamodb:UpdateTable
          - kinesis:DescribeStream
          - kinesis:PutRecords
          - iam:CreateServiceLinkedRole
          - kms:CreateGrant
          - kms:Decrypt
          - kms:Describe*
          - kms:Encrypt
          - kms:Get*
          - kms:List*
          - kms:RevokeGrant
          - logs:CreateLogGroup
          - logs:CreateLogStream
          - logs:DescribeLogGroups
          - logs:DescribeLogStreams
          - logs:PutLogEvents
          - logs:PutRetentionPolicy
          - s3:GetObject
          - s3:GetObjectMetadata
          - s3:ListBucket

        """
        model = copy.deepcopy(request.desired_state)

        if model.get("ImportSourceSpecification"):
            return _failed("ImportSourceSpecification is not supported by this provider")
        if model.get("ContributorInsightsSpecification") or any(
            index.get("ContributorInsightsSpecification")
            for index in model.get("GlobalSecondaryIndexes", [])
        ):
            return _failed("ContributorInsightsSpecification is not supported by this provider")

        if not request.custom_context.get(REPEATED_INVOCATION):
            request.custom_context[REPEATED_INVOCATION] = True

            if not model.get("TableName"):
                model["TableName"] = util.generate_default_name(
                    request.stack_name, request.logical_resource_id
                )

            if model.get("ProvisionedThroughput"):
                model["ProvisionedThroughput"] = self.get_ddb_provisioned_throughput(model)

            if model.get("GlobalSecondaryIndexes"):
                model["GlobalSecondaryIndexes"] = self.get_ddb_global_sec_indexes(model)

            properties = [
                "TableName",
                "AttributeDefinitions",
                "KeySchema",
                "BillingMode",
                "ProvisionedThroughput",
                "LocalSecondaryIndexes",
                "GlobalSecondaryIndexes",
                "Tags",
                "SSESpecification",
                "TableClass",
                "DeletionProtectionEnabled",
            ]
            create_params = util.select_attributes(model, properties)

            if sse_specification := create_params.get("SSESpecification"):
                # rename bool attribute to fit boto call
                sse_specification = dict(sse_specification)
                sse_specification["Enabled"] = sse_specification.pop("SSEEnabled")
                create_params["SSESpecification"] = sse_specification

            if stream_spec := model.get("StreamSpecification"):
                create_params["StreamSpecification"] = {
                    "StreamEnabled": True,
                    **(stream_spec or {}),
                }

            response = request.aws_client_factory.dynamodb.create_table(**create_params)
            table_description = response["TableDescription"]
            table_id = table_description.get("TableId")
            if not isinstance(table_id, str) or not table_id:
                return _failed(
                    f"DynamoDB table {model['TableName']} did not return a stable TableId"
                )
            model["Arn"] = table_description["TableArn"]
            request.custom_context[CREATE_TABLE_ID] = table_id

            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        dynamodb = request.aws_client_factory.dynamodb
        try:
            description = dynamodb.describe_table(TableName=model["TableName"])
        except Exception as error:
            if _is_not_found(dynamodb, error):
                return _failed(
                    f"DynamoDB table disappeared during create for {model['TableName']}",
                    "NotFound",
                )
            raise

        expected_table_id = request.custom_context.get(CREATE_TABLE_ID)
        table_id = description["Table"].get("TableId")
        if not isinstance(expected_table_id, str) or not expected_table_id:
            return _failed(
                f"DynamoDB table {model['TableName']} create context has no stable TableId"
            )
        if table_id != expected_table_id:
            return _failed(
                f"DynamoDB table identity changed during create for {model['TableName']}"
            )

        if description["Table"]["TableStatus"] != "ACTIVE":
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        transitions = set()
        live_model = self._read_create_auxiliary_model(
            dynamodb, description, model, transitions=transitions
        )
        if transitions:
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )
        if mutation := self._next_auxiliary_mutation(
            dynamodb=dynamodb,
            desired=model,
            previous={},
            live=live_model,
            create=True,
        ):
            try:
                pre_write = dynamodb.describe_table(TableName=model["TableName"])
            except Exception as error:
                if _is_not_found(dynamodb, error):
                    return _failed(
                        f"DynamoDB table disappeared during create for {model['TableName']}",
                        "NotFound",
                    )
                raise
            if pre_write["Table"].get("TableId") != expected_table_id:
                return _failed(
                    f"DynamoDB table identity changed during create for {model['TableName']}"
                )
            try:
                mutation.apply()
            except Exception as error:
                if _is_not_found(dynamodb, error):
                    return _failed(
                        f"DynamoDB table disappeared during create for {model['TableName']}",
                        "NotFound",
                    )
                raise
            try:
                post_write = dynamodb.describe_table(TableName=model["TableName"])
            except Exception as error:
                if _is_not_found(dynamodb, error):
                    return _failed(
                        f"DynamoDB table disappeared during create for {model['TableName']}",
                        "NotFound",
                    )
                raise
            if post_write["Table"].get("TableId") != expected_table_id:
                return _failed(
                    f"DynamoDB table identity changed during create for {model['TableName']}"
                )
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        if description["Table"].get("LatestStreamArn"):
            model["StreamArn"] = description["Table"]["LatestStreamArn"]

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
        )

    def read(
        self,
        request: ResourceRequest[DynamoDBTableProperties],
    ) -> ProgressEvent[DynamoDBTableProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - dynamodb:DescribeTable
          - dynamodb:DescribeContinuousBackups
          - dynamodb:DescribeTimeToLive
          - dynamodb:DescribeKinesisStreamingDestination
          - dynamodb:ListTagsOfResource
        """
        dynamodb = request.aws_client_factory.dynamodb
        table_name = request.desired_state["TableName"]
        try:
            description = dynamodb.describe_table(TableName=table_name)
        except Exception as error:
            if _is_not_found(dynamodb, error):
                return _failed(
                    f"Resource of type '{self.TYPE}' with identifier '{table_name}' was not found.",
                    "NotFound",
                )
            raise
        table_id = description["Table"].get("TableId")
        if not isinstance(table_id, str) or not table_id:
            return _failed(f"DynamoDB table {table_name} did not return a stable TableId")
        model = self._read_model(dynamodb, description)
        try:
            post_read = dynamodb.describe_table(TableName=table_name)
        except Exception as error:
            if _is_not_found(dynamodb, error):
                return _failed(
                    f"Resource of type '{self.TYPE}' with identifier '{table_name}' was not found.",
                    "NotFound",
                )
            raise
        if post_read["Table"].get("TableId") != table_id:
            return _failed(f"DynamoDB table identity changed during read for {table_name}")
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def delete(
        self,
        request: ResourceRequest[DynamoDBTableProperties],
    ) -> ProgressEvent[DynamoDBTableProperties]:
        """
        Delete a resource

        IAM permissions required:
          - dynamodb:DeleteTable
          - dynamodb:DescribeTable
        """
        model = copy.deepcopy(request.previous_state or request.desired_state)
        dynamodb = request.aws_client_factory.dynamodb
        expected_table_id = request.custom_context.get(DELETE_TABLE_ID)
        try:
            description = dynamodb.describe_table(TableName=model["TableName"])
        except Exception as error:
            if _is_not_found(dynamodb, error):
                return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})
            raise

        table_id = description["Table"].get("TableId")
        if not isinstance(table_id, str) or not table_id:
            return _failed(f"DynamoDB table {model['TableName']} did not return a stable TableId")
        if expected_table_id is None:
            context = {
                **request.custom_context,
                DELETE_TABLE_ID: table_id,
                DELETE_REQUESTED: description["Table"]["TableStatus"] == "DELETING",
            }
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=context,
            )
        if expected_table_id != table_id:
            return _failed(
                f"DynamoDB table identity changed during delete for {model['TableName']}"
            )

        table_status = description["Table"]["TableStatus"]
        if table_status == "DELETING":
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context={**request.custom_context, DELETE_REQUESTED: True},
            )
        if table_status in {"CREATING", "UPDATING"}:
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )
        if table_status != "ACTIVE":
            return _failed(
                f"Table deletion failed. Table {model['TableName']} found in state {table_status}"
            )

        if not request.custom_context.get(DELETE_REQUESTED):
            try:
                dynamodb.delete_table(TableName=model["TableName"])
            except Exception as error:
                if _is_not_found(dynamodb, error):
                    return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})
                raise
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context={**request.custom_context, DELETE_REQUESTED: True},
            )

        return _failed(f"Table deletion failed. Table {model['TableName']} returned to ACTIVE")

    @staticmethod
    def _journal_binding(
        request, desired: dict, previous: dict, entries: list[dict] | None = None
    ) -> str:
        binding = {
            "stack_id": getattr(request, "stack_id", ""),
            "stack_name": getattr(request, "stack_name", ""),
            "logical_resource_id": getattr(request, "logical_resource_id", ""),
            "action": getattr(request, "action", "UPDATE"),
            "table_name": desired.get("TableName"),
            "desired": desired,
            "previous": previous,
            "plan": [
                {
                    "seq": entry["seq"],
                    "kind": entry["kind"],
                    "before": entry["before"],
                    "after": entry["after"],
                }
                for entry in (entries or [])
            ],
        }
        return f"sha256:{hashlib.sha256(_canonical_json_bytes(binding)).hexdigest()}"

    @staticmethod
    def _uses_compensating_update_lane(desired: dict, previous: dict) -> bool:
        if any(
            desired.get(property_name) != previous.get(property_name)
            for property_name in _NON_COMPENSATED_UPDATE_PROPERTIES
        ):
            return False
        return desired.get("Tags", []) != previous.get("Tags", []) or bool(
            desired.get("DeletionProtectionEnabled", False)
        ) != bool(previous.get("DeletionProtectionEnabled", False))

    def _build_update_journal(
        self,
        *,
        request,
        desired: dict,
        previous: dict,
        live: dict,
        table_id: str,
    ) -> dict | None:
        desired_tags = {tag["Key"]: tag["Value"] for tag in desired.get("Tags", [])}
        previous_tag_keys = {tag["Key"] for tag in previous.get("Tags", [])}
        live_tags = {tag["Key"]: tag["Value"] for tag in live.get("Tags", [])}
        entries = []

        removed_keys = sorted((previous_tag_keys - set(desired_tags)) & set(live_tags))
        if removed_keys:
            entries.append(
                {
                    "seq": len(entries),
                    "kind": "tag_remove",
                    "state": "prepared",
                    "before": {key: live_tags[key] for key in removed_keys},
                    "after": {},
                    "owned_keys": [],
                }
            )

        updated_keys = sorted(
            key
            for key, value in desired_tags.items()
            if key in live_tags and live_tags[key] != value
        )
        if updated_keys:
            entries.append(
                {
                    "seq": len(entries),
                    "kind": "tag_upsert",
                    "state": "prepared",
                    "before": {key: live_tags[key] for key in updated_keys},
                    "after": {key: desired_tags[key] for key in updated_keys},
                    "owned_keys": [],
                }
            )

        created_keys = sorted(key for key in desired_tags if key not in live_tags)
        if created_keys:
            entries.append(
                {
                    "seq": len(entries),
                    "kind": "tag_create",
                    "state": "prepared",
                    "before": {},
                    "after": {key: desired_tags[key] for key in created_keys},
                    "owned_keys": [],
                }
            )

        target_deletion_protection = bool(desired.get("DeletionProtectionEnabled", False))
        live_deletion_protection = bool(live.get("DeletionProtectionEnabled", False))
        if live_deletion_protection != target_deletion_protection:
            entries.append(
                {
                    "seq": len(entries),
                    "kind": "deletion_protection",
                    "state": "prepared",
                    "before": live_deletion_protection,
                    "after": target_deletion_protection,
                    "owned_keys": [],
                }
            )

        if not entries:
            return None
        journal = {
            "version": 1,
            "binding_sha256": self._journal_binding(request, desired, previous, entries),
            "table_id": table_id,
            "phase": "forward",
            "failure": None,
            "attempts": 0,
            "entries": entries,
        }
        self._validate_update_journal(journal)
        return journal

    @staticmethod
    def _validate_tag_projection(value: object, *, allow_empty: bool) -> None:
        if not isinstance(value, dict) or (not allow_empty and not value):
            raise ValueError("DynamoDB update journal tag projection is invalid")
        if len(value) > 50:
            raise ValueError("DynamoDB update journal tag entry has too many keys")
        for key, tag_value in value.items():
            if not isinstance(key, str) or not isinstance(tag_value, str):
                raise ValueError("DynamoDB update journal tag values must be strings")
            if (
                not key
                or len(key) > MAX_UPDATE_JOURNAL_STRING_BYTES
                or len(key.encode("utf-8")) > MAX_UPDATE_JOURNAL_STRING_BYTES
            ):
                raise ValueError("DynamoDB update journal tag key is outside the accepted bounds")
            if (
                len(tag_value) > MAX_UPDATE_JOURNAL_STRING_BYTES
                or len(tag_value.encode("utf-8")) > MAX_UPDATE_JOURNAL_STRING_BYTES
            ):
                raise ValueError("DynamoDB update journal tag value is outside the accepted bounds")

    @classmethod
    def _validate_update_journal(cls, journal: object) -> None:
        if (
            not isinstance(journal, dict)
            or len(journal) != 7
            or set(journal)
            != {
                "version",
                "binding_sha256",
                "table_id",
                "phase",
                "failure",
                "attempts",
                "entries",
            }
        ):
            raise ValueError("DynamoDB update journal has an invalid shape")
        if type(journal["version"]) is not int or journal["version"] != 1:
            raise ValueError("DynamoDB update journal has an unsupported contract")
        if not isinstance(journal["phase"], str) or journal["phase"] not in {
            "forward",
            "rollback",
        }:
            raise ValueError("DynamoDB update journal has an unsupported phase")
        if (
            not isinstance(journal["binding_sha256"], str)
            or len(journal["binding_sha256"]) != 71
            or not journal["binding_sha256"].startswith("sha256:")
        ):
            raise ValueError("DynamoDB update journal binding is invalid")
        try:
            int(journal["binding_sha256"][7:], 16)
        except ValueError as error:
            raise ValueError("DynamoDB update journal binding is invalid") from error
        if (
            not isinstance(journal["table_id"], str)
            or not journal["table_id"]
            or len(journal["table_id"]) > MAX_UPDATE_JOURNAL_STRING_BYTES
            or len(journal["table_id"].encode("utf-8")) > MAX_UPDATE_JOURNAL_STRING_BYTES
        ):
            raise ValueError("DynamoDB update journal table identity is invalid")
        failure = journal["failure"]
        if failure is not None and (
            not isinstance(failure, str)
            or not failure
            or len(failure) > MAX_UPDATE_JOURNAL_FAILURE_BYTES
            or len(failure.encode("utf-8")) > MAX_UPDATE_JOURNAL_FAILURE_BYTES
        ):
            raise ValueError("DynamoDB update journal failure is invalid")
        if (
            type(journal["attempts"]) is not int
            or not 0 <= journal["attempts"] <= MAX_UPDATE_JOURNAL_ATTEMPTS
        ):
            raise ValueError("DynamoDB update journal attempt count is invalid")
        entries = journal["entries"]
        if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_UPDATE_JOURNAL_ENTRIES:
            raise ValueError("DynamoDB update journal entry count is invalid")
        total_tag_keys = 0
        for seq, entry in enumerate(entries):
            if (
                not isinstance(entry, dict)
                or len(entry) != 6
                or set(entry)
                != {
                    "seq",
                    "kind",
                    "state",
                    "before",
                    "after",
                    "owned_keys",
                }
            ):
                raise ValueError("DynamoDB update journal entry has an invalid shape")
            if type(entry["seq"]) is not int or entry["seq"] != seq:
                raise ValueError("DynamoDB update journal entry sequence is invalid")
            if not isinstance(entry["kind"], str) or entry["kind"] not in _JOURNALED_UPDATE_KINDS:
                raise ValueError("DynamoDB update journal entry contract is invalid")
            if not isinstance(entry["state"], str) or entry["state"] not in {
                "prepared",
                "applying",
                "applied",
                "rolling_back",
                "rolled_back",
                "skipped",
                "conflicted",
            }:
                raise ValueError("DynamoDB update journal entry state is invalid")
            if (
                not isinstance(entry["owned_keys"], list)
                or len(entry["owned_keys"]) > 50
                or any(
                    not isinstance(key, str)
                    or not key
                    or len(key) > MAX_UPDATE_JOURNAL_STRING_BYTES
                    or len(key.encode("utf-8")) > MAX_UPDATE_JOURNAL_STRING_BYTES
                    for key in entry["owned_keys"]
                )
                or len(set(entry["owned_keys"])) != len(entry["owned_keys"])
            ):
                raise ValueError("DynamoDB update journal ownership is invalid")
            if entry["state"] in {"applied", "rolling_back"} and not entry["owned_keys"]:
                raise ValueError("DynamoDB applied journal entry has no ownership")
            if (
                entry["state"]
                in {
                    "prepared",
                    "skipped",
                    "conflicted",
                    "rolled_back",
                }
                and entry["owned_keys"]
            ):
                raise ValueError("DynamoDB journal state cannot own resource fields")
            before, after = entry["before"], entry["after"]
            if entry["kind"] == "deletion_protection":
                if not isinstance(before, bool) or not isinstance(after, bool) or before == after:
                    raise ValueError("DynamoDB deletion protection journal entry is invalid")
                if entry["owned_keys"] not in ([], ["DeletionProtectionEnabled"]):
                    raise ValueError("DynamoDB deletion protection ownership is invalid")
                continue
            cls._validate_tag_projection(before, allow_empty=entry["kind"] == "tag_create")
            cls._validate_tag_projection(after, allow_empty=entry["kind"] == "tag_remove")
            if entry["kind"] == "tag_remove" and after:
                raise ValueError("DynamoDB tag removal journal entry is invalid")
            if entry["kind"] == "tag_create" and before:
                raise ValueError("DynamoDB tag creation journal entry is invalid")
            if entry["kind"] == "tag_upsert" and set(before) != set(after):
                raise ValueError("DynamoDB tag update journal entry is invalid")
            if not set(entry["owned_keys"]).issubset(set(before) | set(after)):
                raise ValueError("DynamoDB update journal owns an unknown tag key")
            total_tag_keys += len(set(before) | set(after))
        if total_tag_keys > MAX_UPDATE_JOURNAL_TAGS:
            raise ValueError("DynamoDB update journal has too many tag keys")
        if len(_canonical_json_bytes(journal)) > MAX_UPDATE_JOURNAL_BYTES:
            raise ValueError("DynamoDB update journal exceeds the accepted size")

    @staticmethod
    def _validate_update_journal_plan(journal: dict, desired: dict, previous: dict) -> None:
        desired_tags = {tag["Key"]: tag["Value"] for tag in desired.get("Tags", [])}
        previous_tag_keys = {tag["Key"] for tag in previous.get("Tags", [])}
        seen_tag_keys = set()
        seen_kinds = set()
        seen_deletion_protection = False
        last_order = -1
        kind_order = {
            "tag_remove": 0,
            "tag_upsert": 1,
            "tag_create": 2,
            "deletion_protection": 3,
        }
        for entry in journal["entries"]:
            order = kind_order[entry["kind"]]
            if order < last_order or entry["kind"] in seen_kinds:
                raise ValueError("DynamoDB update journal plan order is invalid")
            last_order = order
            seen_kinds.add(entry["kind"])
            if entry["kind"] == "deletion_protection":
                if seen_deletion_protection or entry["after"] != bool(
                    desired.get("DeletionProtectionEnabled", False)
                ):
                    raise ValueError("DynamoDB update journal deletion plan is invalid")
                seen_deletion_protection = True
                continue
            keys = set(entry["before"]) | set(entry["after"])
            if not keys or seen_tag_keys.intersection(keys):
                raise ValueError("DynamoDB update journal tag plan is not disjoint")
            seen_tag_keys.update(keys)
            if entry["kind"] == "tag_remove":
                if not keys.issubset(previous_tag_keys) or keys.intersection(desired_tags):
                    raise ValueError("DynamoDB update journal tag removal was not requested")
            elif entry["kind"] == "tag_upsert":
                if not keys.issubset(desired_tags) or entry["after"] != {
                    key: desired_tags[key] for key in keys
                }:
                    raise ValueError("DynamoDB update journal tag update was not requested")
            elif not keys.issubset(desired_tags) or entry["after"] != {
                key: desired_tags[key] for key in keys
            }:
                raise ValueError("DynamoDB update journal tag creation was not requested")

    def _journal_projection(self, dynamodb, table_name: str, table_id: str, entry: dict):
        description = dynamodb.describe_table(TableName=table_name)
        table = description["Table"]
        if table.get("TableId") != table_id:
            raise ValueError(f"DynamoDB table identity changed during update for {table_name}")
        if table.get("TableStatus") != "ACTIVE":
            return None, None
        if entry["kind"] == "deletion_protection":
            return bool(table.get("DeletionProtectionEnabled", False)), None
        table_arn = table["TableArn"]
        keys = set(entry["before"]) | set(entry["after"])
        tags = {tag["Key"]: tag["Value"] for tag in self._list_tags(dynamodb, table_arn)}
        projection = {key: tags[key] for key in sorted(keys) if key in tags}
        post_read = dynamodb.describe_table(TableName=table_name)
        if post_read["Table"].get("TableId") != table_id:
            raise ValueError(f"DynamoDB table identity changed during update for {table_name}")
        return projection, table_arn

    @staticmethod
    def _journal_entry_keys(entry: dict) -> list[str]:
        if entry["kind"] == "deletion_protection":
            return ["DeletionProtectionEnabled"]
        return sorted(set(entry["before"]) | set(entry["after"]))

    @staticmethod
    def _projection_matches_key(projection: dict, target: dict, key: str) -> bool:
        return (key in projection) == (key in target) and (
            key not in target or projection[key] == target[key]
        )

    @classmethod
    def _matching_journal_keys(cls, projection, entry: dict, target_name: str) -> list[str]:
        if entry["kind"] == "deletion_protection":
            return ["DeletionProtectionEnabled"] if projection == entry[target_name] else []
        target = entry[target_name]
        return [
            key
            for key in cls._journal_entry_keys(entry)
            if cls._projection_matches_key(projection, target, key)
        ]

    @staticmethod
    def _journal_entry_subset(entry: dict, keys: list[str]) -> dict:
        if entry["kind"] == "deletion_protection":
            return entry
        selected = set(keys)
        return {
            "kind": entry["kind"],
            "before": {key: value for key, value in entry["before"].items() if key in selected},
            "after": {key: value for key, value in entry["after"].items() if key in selected},
        }

    @staticmethod
    def _set_journal_failure(journal: dict, message: str) -> None:
        combined = f"{journal['failure']}; {message}" if journal["failure"] else message
        journal["failure"] = _bounded_failure_message(RuntimeError(combined))

    @staticmethod
    def _start_journal_rollback(journal: dict) -> None:
        if journal["phase"] != "rollback":
            journal["attempts"] = 0
        journal["phase"] = "rollback"

    @staticmethod
    def _apply_journal_entry(dynamodb, table_name: str, table_arn: str | None, entry: dict):
        kind = entry["kind"]
        if kind == "tag_remove":
            return dynamodb.untag_resource(ResourceArn=table_arn, TagKeys=sorted(entry["before"]))
        if kind in {"tag_upsert", "tag_create"}:
            return dynamodb.tag_resource(
                ResourceArn=table_arn,
                Tags=[
                    {"Key": key, "Value": value} for key, value in sorted(entry["after"].items())
                ],
            )
        return dynamodb.update_table(TableName=table_name, DeletionProtectionEnabled=entry["after"])

    @staticmethod
    def _rollback_journal_entry(dynamodb, table_name: str, table_arn: str | None, entry: dict):
        kind = entry["kind"]
        if kind in {"tag_remove", "tag_upsert"}:
            return dynamodb.tag_resource(
                ResourceArn=table_arn,
                Tags=[
                    {"Key": key, "Value": value} for key, value in sorted(entry["before"].items())
                ],
            )
        if kind == "tag_create":
            return dynamodb.untag_resource(ResourceArn=table_arn, TagKeys=sorted(entry["after"]))
        return dynamodb.update_table(
            TableName=table_name, DeletionProtectionEnabled=entry["before"]
        )

    @staticmethod
    def _journal_progress(desired: dict, context: dict, journal: dict) -> ProgressEvent:
        journal["attempts"] += 1
        next_context = copy.deepcopy(context)
        next_context[DDB_UPDATE_JOURNAL] = copy.deepcopy(journal)
        return ProgressEvent(
            status=OperationStatus.IN_PROGRESS,
            resource_model=desired,
            custom_context=next_context,
        )

    def _advance_update_journal(
        self,
        *,
        request,
        dynamodb,
        desired: dict,
        previous: dict,
        live: dict,
        journal: dict,
    ) -> ProgressEvent:
        self._validate_update_journal(journal)
        self._validate_update_journal_plan(journal, desired, previous)
        if journal["binding_sha256"] != self._journal_binding(
            request, desired, previous, journal["entries"]
        ):
            return _failed("DynamoDB update journal does not match this resource update")
        table_name = desired["TableName"]
        table_id = journal["table_id"]

        if (
            journal["phase"] == "forward"
            and journal["attempts"] >= MAX_UPDATE_JOURNAL_FORWARD_ATTEMPTS
        ):
            self._set_journal_failure(journal, "forward callback attempt limit exceeded")
            self._start_journal_rollback(journal)
            return self._journal_progress(desired, request.custom_context, journal)
        if journal["phase"] == "rollback" and journal["attempts"] >= MAX_UPDATE_JOURNAL_ATTEMPTS:
            return _failed(
                f"{journal['failure'] or 'DynamoDB update failed'}; "
                "compensation callback attempt limit exceeded"
            )

        if journal["phase"] == "forward":
            entry = next(
                (
                    entry
                    for entry in journal["entries"]
                    if entry["state"] in {"prepared", "applying"}
                ),
                None,
            )
            if entry is None:
                for completed_entry in journal["entries"]:
                    try:
                        projection, _ = self._journal_projection(
                            dynamodb, table_name, table_id, completed_entry
                        )
                    except Exception as error:
                        self._set_journal_failure(
                            journal,
                            "final journal verification failed: " + _bounded_failure_message(error),
                        )
                        self._start_journal_rollback(journal)
                        return self._journal_progress(desired, request.custom_context, journal)
                    if projection is None:
                        return self._journal_progress(desired, request.custom_context, journal)
                    if projection != completed_entry["after"]:
                        journal["failure"] = (
                            "DynamoDB update changed before final journal verification"
                        )
                        self._start_journal_rollback(journal)
                        return self._journal_progress(desired, request.custom_context, journal)
                result = copy.deepcopy(desired)
                result["Arn"] = live["Arn"]
                if live.get("StreamArn"):
                    result["StreamArn"] = live["StreamArn"]
                return ProgressEvent(
                    status=OperationStatus.SUCCESS,
                    resource_model=result,
                    custom_context=copy.deepcopy(request.custom_context),
                )
            try:
                projection, table_arn = self._journal_projection(
                    dynamodb, table_name, table_id, entry
                )
            except Exception as error:
                self._set_journal_failure(journal, _bounded_failure_message(error))
                if entry["state"] == "prepared":
                    entry["state"] = "conflicted"
                    entry["owned_keys"] = []
                self._start_journal_rollback(journal)
                return self._journal_progress(desired, request.custom_context, journal)
            if projection is None:
                return self._journal_progress(desired, request.custom_context, journal)
            if projection == entry["after"]:
                entry["state"] = "applied" if entry["state"] == "applying" else "skipped"
                entry["owned_keys"] = (
                    self._journal_entry_keys(entry) if entry["state"] == "applied" else []
                )
                if journal["failure"] is not None:
                    self._start_journal_rollback(journal)
                return self._journal_progress(desired, request.custom_context, journal)
            if entry["state"] == "applying" and projection == entry["before"]:
                journal["failure"] = journal["failure"] or (
                    "DynamoDB update did not converge to the planned state"
                )
                entry["state"] = "rolled_back"
                entry["owned_keys"] = []
                self._start_journal_rollback(journal)
                return self._journal_progress(desired, request.custom_context, journal)
            if projection != entry["before"]:
                journal["failure"] = "DynamoDB update encountered concurrent external drift"
                entry["state"] = "conflicted"
                entry["owned_keys"] = []
                self._start_journal_rollback(journal)
                return self._journal_progress(desired, request.custom_context, journal)

            write_error = None
            try:
                self._apply_journal_entry(dynamodb, table_name, table_arn, entry)
            except Exception as error:
                write_error = error
            try:
                observed, _ = self._journal_projection(dynamodb, table_name, table_id, entry)
            except Exception as error:
                journal["failure"] = _bounded_failure_message(write_error or error)
                entry["state"] = "applying"
                self._start_journal_rollback(journal)
                return self._journal_progress(desired, request.custom_context, journal)
            if observed is None:
                entry["state"] = "applying"
                if write_error is not None:
                    journal["failure"] = _bounded_failure_message(write_error)
                return self._journal_progress(desired, request.custom_context, journal)
            if observed == entry["after"]:
                entry["state"] = "applied"
                entry["owned_keys"] = self._journal_entry_keys(entry)
                if write_error is not None:
                    journal["failure"] = _bounded_failure_message(write_error)
                    self._start_journal_rollback(journal)
                return self._journal_progress(desired, request.custom_context, journal)
            after_keys = self._matching_journal_keys(observed, entry, "after")
            before_keys = self._matching_journal_keys(observed, entry, "before")
            entry["owned_keys"] = after_keys
            entry["state"] = "applied" if after_keys else "rolled_back"
            unknown_keys = set(self._journal_entry_keys(entry)) - set(after_keys) - set(before_keys)
            message = _bounded_failure_message(
                write_error or RuntimeError("DynamoDB update did not converge to the planned state")
            )
            if unknown_keys:
                message = f"{message}; concurrent drift affected {len(unknown_keys)} key(s)"
            journal["failure"] = _bounded_failure_message(RuntimeError(message))
            self._start_journal_rollback(journal)
            return self._journal_progress(desired, request.custom_context, journal)

        entry = next(
            (
                entry
                for entry in reversed(journal["entries"])
                if entry["state"] in {"applying", "applied", "rolling_back"}
            ),
            None,
        )
        if entry is None:
            event = _failed(journal["failure"] or "DynamoDB update compensation failed")
            event.custom_context = copy.deepcopy(request.custom_context)
            return event
        try:
            projection, table_arn = self._journal_projection(dynamodb, table_name, table_id, entry)
        except Exception as error:
            self._set_journal_failure(
                journal, "compensation read failed: " + _bounded_failure_message(error)
            )
            return self._journal_progress(desired, request.custom_context, journal)
        if projection is None:
            return self._journal_progress(desired, request.custom_context, journal)
        if entry["state"] == "applying":
            after_keys = self._matching_journal_keys(projection, entry, "after")
            before_keys = self._matching_journal_keys(projection, entry, "before")
            entry["owned_keys"] = after_keys
            unknown_keys = set(self._journal_entry_keys(entry)) - set(after_keys) - set(before_keys)
            if unknown_keys:
                self._set_journal_failure(
                    journal,
                    f"compensation preserved concurrent drift on {len(unknown_keys)} key(s)",
                )
            if not after_keys:
                entry["state"] = "conflicted" if unknown_keys else "rolled_back"
                return self._journal_progress(desired, request.custom_context, journal)
            entry["state"] = "applied"
        owned_keys = entry["owned_keys"]
        rollback_entry = self._journal_entry_subset(entry, owned_keys)
        if entry["kind"] == "deletion_protection":
            owned_projection = projection
        else:
            owned_projection = {key: projection[key] for key in owned_keys if key in projection}
        if owned_projection == rollback_entry["before"]:
            entry["state"] = "rolled_back"
            entry["owned_keys"] = []
            return self._journal_progress(desired, request.custom_context, journal)
        if entry["state"] == "rolling_back" or owned_projection != rollback_entry["after"]:
            entry["state"] = "conflicted"
            entry["owned_keys"] = []
            self._set_journal_failure(
                journal, "compensation stopped to preserve concurrent external state"
            )
            return self._journal_progress(desired, request.custom_context, journal)

        rollback_error = None
        try:
            self._rollback_journal_entry(dynamodb, table_name, table_arn, rollback_entry)
        except Exception as error:
            rollback_error = error
        try:
            observed, _ = self._journal_projection(dynamodb, table_name, table_id, entry)
        except Exception as error:
            entry["state"] = "rolling_back"
            self._set_journal_failure(
                journal,
                "compensation confirmation was inconclusive: "
                + _bounded_failure_message(rollback_error or error),
            )
            return self._journal_progress(desired, request.custom_context, journal)
        if observed is None:
            entry["state"] = "rolling_back"
            return self._journal_progress(desired, request.custom_context, journal)
        if entry["kind"] == "deletion_protection":
            owned_observed = observed
        else:
            owned_observed = {key: observed[key] for key in owned_keys if key in observed}
        if owned_observed == rollback_entry["before"]:
            entry["state"] = "rolled_back"
            entry["owned_keys"] = []
            return self._journal_progress(desired, request.custom_context, journal)
        entry["state"] = "conflicted"
        entry["owned_keys"] = []
        self._set_journal_failure(
            journal,
            "compensation failed: "
            + _bounded_failure_message(rollback_error or RuntimeError("state did not converge")),
        )
        return self._journal_progress(desired, request.custom_context, journal)

    def update(
        self,
        request: ResourceRequest[DynamoDBTableProperties],
    ) -> ProgressEvent[DynamoDBTableProperties]:
        """
        Update a resource

        IAM permissions required:
          - dynamodb:UpdateTable
          - dynamodb:DescribeTable
          - dynamodb:DescribeTimeToLive
          - dynamodb:UpdateTimeToLive
          - dynamodb:UpdateContinuousBackups
          - dynamodb:UpdateContributorInsights
          - dynamodb:DescribeContinuousBackups
          - dynamodb:DescribeKinesisStreamingDestination
          - dynamodb:ListTagsOfResource
          - dynamodb:TagResource
          - dynamodb:UntagResource
          - dynamodb:DescribeContributorInsights
          - dynamodb:EnableKinesisStreamingDestination
          - dynamodb:DisableKinesisStreamingDestination
          - kinesis:DescribeStream
          - kinesis:PutRecords
          - iam:CreateServiceLinkedRole
          - kms:CreateGrant
          - kms:Describe*
          - kms:Get*
          - kms:List*
          - kms:RevokeGrant
        """
        dynamodb = request.aws_client_factory.dynamodb
        desired = copy.deepcopy(request.desired_state)
        previous = copy.deepcopy(request.previous_state or {})
        table_name = desired["TableName"]

        if DDB_UPDATE_JOURNAL in request.custom_context:
            raw_journal = request.custom_context[DDB_UPDATE_JOURNAL]
            try:
                self._validate_update_journal(raw_journal)
                self._validate_update_journal_plan(raw_journal, desired, previous)
                if raw_journal["binding_sha256"] != self._journal_binding(
                    request, desired, previous, raw_journal["entries"]
                ):
                    raise ValueError("DynamoDB update journal does not match this resource update")
            except ValueError as error:
                return _failed(str(error))

        for property_name in (
            "TableName",
            "ImportSourceSpecification",
            "KeySchema",
            "LocalSecondaryIndexes",
            "GlobalSecondaryIndexes",
            "AttributeDefinitions",
            "SSESpecification",
            "ContributorInsightsSpecification",
        ):
            if desired.get(property_name) != previous.get(property_name):
                return _failed(f"Updates to {property_name} are not supported by this provider")

        try:
            description = dynamodb.describe_table(TableName=table_name)
        except Exception as error:
            if _is_not_found(dynamodb, error):
                return _failed(
                    f"Resource of type '{self.TYPE}' with identifier '{table_name}' was not found.",
                    "NotFound",
                )
            if DDB_UPDATE_JOURNAL in request.custom_context:
                journal = copy.deepcopy(request.custom_context[DDB_UPDATE_JOURNAL])
                self._set_journal_failure(
                    journal, "table read failed: " + _bounded_failure_message(error)
                )
                if journal["phase"] == "forward":
                    self._start_journal_rollback(journal)
                elif journal["attempts"] >= MAX_UPDATE_JOURNAL_ATTEMPTS:
                    return _failed(
                        f"{journal['failure']}; compensation callback attempt limit exceeded"
                    )
                return self._journal_progress(desired, request.custom_context, journal)
            raise

        table = description["Table"]
        table_id = table.get("TableId")
        if not isinstance(table_id, str) or not table_id:
            return _failed(f"DynamoDB table {table_name} did not return a stable TableId")
        expected_table_id = request.custom_context.get(UPDATE_TABLE_ID)
        if expected_table_id is None:
            context = {**request.custom_context, UPDATE_TABLE_ID: table_id}
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=desired,
                custom_context=context,
            )
        if expected_table_id != table_id:
            return _failed(f"DynamoDB table identity changed during update for {table_name}")
        if table["TableStatus"] != "ACTIVE":
            if DDB_UPDATE_JOURNAL in request.custom_context:
                journal = copy.deepcopy(request.custom_context[DDB_UPDATE_JOURNAL])
                if (
                    journal["phase"] == "forward"
                    and journal["attempts"] >= MAX_UPDATE_JOURNAL_FORWARD_ATTEMPTS
                ):
                    self._set_journal_failure(journal, "forward callback attempt limit exceeded")
                    self._start_journal_rollback(journal)
                elif (
                    journal["phase"] == "rollback"
                    and journal["attempts"] >= MAX_UPDATE_JOURNAL_ATTEMPTS
                ):
                    return _failed(
                        f"{journal['failure'] or 'DynamoDB update failed'}; "
                        "compensation callback attempt limit exceeded"
                    )
                return self._journal_progress(desired, request.custom_context, journal)
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=desired,
                custom_context=request.custom_context,
            )

        if DDB_UPDATE_JOURNAL in request.custom_context:
            journal_value = request.custom_context[DDB_UPDATE_JOURNAL]
            try:
                return self._advance_update_journal(
                    request=request,
                    dynamodb=dynamodb,
                    desired=desired,
                    previous=previous,
                    live={
                        "Arn": table["TableArn"],
                        **(
                            {"StreamArn": table["LatestStreamArn"]}
                            if table.get("LatestStreamArn")
                            else {}
                        ),
                    },
                    journal=copy.deepcopy(journal_value),
                )
            except ValueError as error:
                return _failed(str(error))

        transitions = set()
        try:
            live = self._read_model(dynamodb, description, transitions=transitions)
        except Exception as error:
            if _is_not_found(dynamodb, error):
                return _failed(
                    f"Resource of type '{self.TYPE}' with identifier '{table_name}' was not found.",
                    "NotFound",
                )
            raise
        if transitions:
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=desired,
                custom_context=request.custom_context,
            )

        mutation = self._next_table_mutation(dynamodb, desired, previous, live)
        if mutation is None:
            mutation = self._next_auxiliary_mutation(
                dynamodb=dynamodb,
                desired=desired,
                previous=previous,
                live=live,
                create=False,
            )

        if self._uses_compensating_update_lane(desired, previous) and (
            mutation is None or mutation.descriptor["kind"] in _JOURNALED_UPDATE_KINDS
        ):
            try:
                journal = self._build_update_journal(
                    request=request,
                    desired=desired,
                    previous=previous,
                    live=live,
                    table_id=expected_table_id,
                )
            except ValueError as error:
                return _failed(str(error))
            if journal is not None:
                return self._journal_progress(desired, request.custom_context, journal)
        if mutation is None:
            result = copy.deepcopy(desired)
            result["Arn"] = live["Arn"]
            if live.get("StreamArn"):
                result["StreamArn"] = live["StreamArn"]
            return ProgressEvent(
                status=OperationStatus.SUCCESS,
                resource_model=result,
                custom_context=request.custom_context,
            )

        try:
            pre_write = dynamodb.describe_table(TableName=table_name)
        except Exception as error:
            if _is_not_found(dynamodb, error):
                return _failed(
                    f"Resource of type '{self.TYPE}' with identifier '{table_name}' was not found.",
                    "NotFound",
                )
            raise
        if pre_write["Table"].get("TableId") != expected_table_id:
            return _failed(f"DynamoDB table identity changed during update for {table_name}")
        try:
            mutation.apply()
        except Exception as error:
            if _is_not_found(dynamodb, error):
                return _failed(
                    f"Resource of type '{self.TYPE}' with identifier '{table_name}' was not found.",
                    "NotFound",
                )
            raise
        try:
            post_write = dynamodb.describe_table(TableName=table_name)
        except Exception as error:
            if _is_not_found(dynamodb, error):
                return _failed(f"DynamoDB table disappeared during update for {table_name}")
            raise
        if post_write["Table"].get("TableId") != expected_table_id:
            return _failed(f"DynamoDB table identity changed during update for {table_name}")
        return ProgressEvent(
            status=OperationStatus.IN_PROGRESS,
            resource_model=desired,
            custom_context=request.custom_context,
        )

    def _read_model(
        self, dynamodb, description: dict, *, transitions: set[str] | None = None
    ) -> DynamoDBTableProperties:
        table = description["Table"]
        table_name = table["TableName"]
        table_arn = table["TableArn"]
        billing_mode = (table.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED")
        model = DynamoDBTableProperties(
            TableName=table_name,
            Arn=table_arn,
            AttributeDefinitions=copy.deepcopy(table.get("AttributeDefinitions", [])),
            KeySchema=copy.deepcopy(table.get("KeySchema", [])),
            BillingMode=billing_mode,
            DeletionProtectionEnabled=bool(table.get("DeletionProtectionEnabled", False)),
            TableClass=(table.get("TableClassSummary") or {}).get("TableClass", "STANDARD"),
            Tags=self._list_tags(dynamodb, table_arn),
        )
        if billing_mode == "PROVISIONED" and table.get("ProvisionedThroughput"):
            model["ProvisionedThroughput"] = util.select_attributes(
                table["ProvisionedThroughput"], ("ReadCapacityUnits", "WriteCapacityUnits")
            )
        if table.get("LocalSecondaryIndexes"):
            model["LocalSecondaryIndexes"] = [
                util.select_attributes(index, ("IndexName", "KeySchema", "Projection"))
                for index in table["LocalSecondaryIndexes"]
            ]
        if table.get("GlobalSecondaryIndexes"):
            indexes = []
            for index in table["GlobalSecondaryIndexes"]:
                index_model = util.select_attributes(
                    index, ("IndexName", "KeySchema", "Projection")
                )
                if throughput := index.get("ProvisionedThroughput"):
                    index_model["ProvisionedThroughput"] = util.select_attributes(
                        throughput, ("ReadCapacityUnits", "WriteCapacityUnits")
                    )
                indexes.append(index_model)
            model["GlobalSecondaryIndexes"] = indexes
        if stream_specification := table.get("StreamSpecification"):
            if stream_specification.get("StreamEnabled"):
                model["StreamSpecification"] = {
                    "StreamViewType": stream_specification["StreamViewType"]
                }
        if table.get("LatestStreamArn"):
            model["StreamArn"] = table["LatestStreamArn"]
        if sse := table.get("SSEDescription"):
            model["SSESpecification"] = {
                "SSEEnabled": sse.get("Status") in {"ENABLED", "ENABLING"},
                **({"SSEType": sse["SSEType"]} if sse.get("SSEType") else {}),
                **(
                    {"KMSMasterKeyId": sse["KMSMasterKeyArn"]} if sse.get("KMSMasterKeyArn") else {}
                ),
            }

        pitr = dynamodb.describe_continuous_backups(TableName=table_name)
        pitr_status = pitr["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"].get(
            "PointInTimeRecoveryStatus", "DISABLED"
        )
        if transitions is not None and pitr_status in {"ENABLING", "DISABLING"}:
            transitions.add("PointInTimeRecoverySpecification")
        model["PointInTimeRecoverySpecification"] = {
            "PointInTimeRecoveryEnabled": pitr_status in {"ENABLED", "ENABLING"}
        }
        ttl = dynamodb.describe_time_to_live(TableName=table_name).get("TimeToLiveDescription", {})
        ttl_status = ttl.get("TimeToLiveStatus", "DISABLED")
        if transitions is not None and ttl_status in {"ENABLING", "DISABLING"}:
            transitions.add("TimeToLiveSpecification")
        ttl_model = {"Enabled": ttl_status in {"ENABLED", "ENABLING"}}
        if ttl.get("AttributeName"):
            ttl_model["AttributeName"] = ttl["AttributeName"]
        if ttl_model["Enabled"] or ttl_model.get("AttributeName"):
            model["TimeToLiveSpecification"] = ttl_model

        destinations = dynamodb.describe_kinesis_streaming_destination(TableName=table_name).get(
            "KinesisDataStreamDestinations", []
        )
        if transitions is not None and any(
            destination.get("DestinationStatus") in {"ENABLING", "DISABLING", "UPDATING"}
            for destination in destinations
        ):
            transitions.add("KinesisStreamSpecification")
        enabled_destinations = [
            destination
            for destination in destinations
            if destination.get("DestinationStatus") in {"ACTIVE", "ENABLING"}
        ]
        if len(enabled_destinations) > 1:
            raise ValueError(f"DynamoDB table {table_name} has multiple Kinesis destinations")
        if enabled_destinations:
            model["KinesisStreamSpecification"] = {
                "StreamArn": enabled_destinations[0]["StreamArn"]
            }
        return model

    def _read_create_auxiliary_model(
        self,
        dynamodb,
        description: dict,
        desired: dict,
        *,
        transitions: set[str] | None = None,
    ) -> DynamoDBTableProperties:
        """Read only the post-create settings that require separate DynamoDB APIs."""
        table = description["Table"]
        table_name = table["TableName"]
        model = DynamoDBTableProperties(TableName=table_name)
        if table.get("TableArn") or desired.get("Arn"):
            model["Arn"] = table.get("TableArn") or desired["Arn"]

        if "PointInTimeRecoverySpecification" in desired:
            pitr = dynamodb.describe_continuous_backups(TableName=table_name)
            status = pitr["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"].get(
                "PointInTimeRecoveryStatus", "DISABLED"
            )
            if transitions is not None and status in {"ENABLING", "DISABLING"}:
                transitions.add("PointInTimeRecoverySpecification")
            model["PointInTimeRecoverySpecification"] = {
                "PointInTimeRecoveryEnabled": status in {"ENABLED", "ENABLING"}
            }

        if "TimeToLiveSpecification" in desired:
            ttl = dynamodb.describe_time_to_live(TableName=table_name).get(
                "TimeToLiveDescription", {}
            )
            status = ttl.get("TimeToLiveStatus", "DISABLED")
            if transitions is not None and status in {"ENABLING", "DISABLING"}:
                transitions.add("TimeToLiveSpecification")
            ttl_model = {"Enabled": status in {"ENABLED", "ENABLING"}}
            if ttl.get("AttributeName"):
                ttl_model["AttributeName"] = ttl["AttributeName"]
            model["TimeToLiveSpecification"] = ttl_model

        if "KinesisStreamSpecification" in desired:
            destinations = dynamodb.describe_kinesis_streaming_destination(
                TableName=table_name
            ).get("KinesisDataStreamDestinations", [])
            if transitions is not None and any(
                destination.get("DestinationStatus") in {"ENABLING", "DISABLING", "UPDATING"}
                for destination in destinations
            ):
                transitions.add("KinesisStreamSpecification")
            active = [
                destination
                for destination in destinations
                if destination.get("DestinationStatus") in {"ACTIVE", "ENABLING"}
            ]
            if len(active) > 1:
                raise ValueError(f"DynamoDB table {table_name} has multiple Kinesis destinations")
            if active:
                model["KinesisStreamSpecification"] = {"StreamArn": active[0]["StreamArn"]}
        return model

    def _list_tags(self, dynamodb, table_arn: str) -> list[Tag]:
        tags = []
        token = None
        seen_tokens = set()
        for _ in range(MAX_TAG_PAGES):
            kwargs = {"ResourceArn": table_arn}
            if token:
                kwargs["NextToken"] = token
            response = dynamodb.list_tags_of_resource(**kwargs)
            page_tags = response.get("Tags", [])
            if not isinstance(page_tags, list) or len(tags) + len(page_tags) > MAX_TAG_ITEMS:
                raise ValueError("DynamoDB tag listing exceeded the accepted item limit")
            tags.extend(copy.deepcopy(page_tags))
            token = response.get("NextToken")
            if not token:
                return sorted(tags, key=lambda tag: (tag["Key"], tag["Value"]))
            if token in seen_tokens:
                raise ValueError("DynamoDB tag pagination repeated a token")
            seen_tokens.add(token)
        raise ValueError("DynamoDB tag pagination exceeded the accepted limit")

    def _next_table_mutation(self, dynamodb, desired: dict, previous: dict, live: dict):
        table_name = desired["TableName"]
        if any(
            property_name in desired or property_name in previous
            for property_name in ("BillingMode", "ProvisionedThroughput")
        ):
            target_billing = desired.get("BillingMode", "PROVISIONED")
            target_throughput = self.get_ddb_provisioned_throughput(copy.deepcopy(desired))
            if live.get("BillingMode") != target_billing or (
                target_billing == "PROVISIONED"
                and live.get("ProvisionedThroughput") != target_throughput
            ):
                params = {"TableName": table_name, "BillingMode": target_billing}
                if target_billing == "PROVISIONED":
                    params["ProvisionedThroughput"] = target_throughput
                before = {"BillingMode": live.get("BillingMode", "PROVISIONED")}
                if before["BillingMode"] == "PROVISIONED":
                    before["ProvisionedThroughput"] = copy.deepcopy(
                        live.get("ProvisionedThroughput")
                    )
                after = {"BillingMode": target_billing}
                if target_billing == "PROVISIONED":
                    after["ProvisionedThroughput"] = copy.deepcopy(target_throughput)
                return _mutation(
                    kind="capacity",
                    before=before,
                    after=after,
                    apply=lambda: dynamodb.update_table(**params),
                )

        if "StreamSpecification" in desired or "StreamSpecification" in previous:
            target_stream = desired.get("StreamSpecification")
            live_stream = live.get("StreamSpecification")
            if live_stream != target_stream:
                if live_stream:
                    return _mutation(
                        kind="stream",
                        before=live_stream,
                        after=None,
                        apply=lambda: dynamodb.update_table(
                            TableName=table_name,
                            StreamSpecification={"StreamEnabled": False},
                        ),
                    )
                return _mutation(
                    kind="stream",
                    before=None,
                    after=target_stream,
                    apply=lambda: dynamodb.update_table(
                        TableName=table_name,
                        StreamSpecification={"StreamEnabled": True, **target_stream},
                    ),
                )

        if "TableClass" in desired or "TableClass" in previous:
            target_class = desired.get("TableClass", "STANDARD")
            if live.get("TableClass") != target_class:
                return _mutation(
                    kind="table_class",
                    before=live.get("TableClass", "STANDARD"),
                    after=target_class,
                    apply=lambda: dynamodb.update_table(
                        TableName=table_name, TableClass=target_class
                    ),
                )
        return None

    def _next_auxiliary_mutation(
        self,
        *,
        dynamodb,
        desired: dict,
        previous: dict,
        live: dict,
        create: bool,
    ):
        table_name = desired["TableName"]
        if "PointInTimeRecoverySpecification" in desired or (
            not create and "PointInTimeRecoverySpecification" in previous
        ):
            target_pitr = desired.get(
                "PointInTimeRecoverySpecification",
                {"PointInTimeRecoveryEnabled": False},
            )
            if live.get("PointInTimeRecoverySpecification") != target_pitr:
                return _mutation(
                    kind="pitr",
                    before=live.get(
                        "PointInTimeRecoverySpecification",
                        {"PointInTimeRecoveryEnabled": False},
                    ),
                    after=target_pitr,
                    apply=lambda: dynamodb.update_continuous_backups(
                        TableName=table_name,
                        PointInTimeRecoverySpecification=target_pitr,
                    ),
                )

        if "TimeToLiveSpecification" in desired or (
            not create and "TimeToLiveSpecification" in previous
        ):
            target_ttl = desired.get("TimeToLiveSpecification")
            live_ttl = live.get("TimeToLiveSpecification", {"Enabled": False})
            if target_ttl is None:
                target_ttl = {
                    "Enabled": False,
                    "AttributeName": live_ttl.get("AttributeName")
                    or previous.get("TimeToLiveSpecification", {}).get("AttributeName"),
                }
            ttl_matches = live_ttl.get("Enabled") == target_ttl.get("Enabled") and (
                not target_ttl.get("Enabled")
                or live_ttl.get("AttributeName") == target_ttl.get("AttributeName")
            )
            if not ttl_matches:
                if live_ttl.get("Enabled") and (
                    not target_ttl.get("Enabled")
                    or live_ttl.get("AttributeName") != target_ttl.get("AttributeName")
                ):
                    specification = {
                        "Enabled": False,
                        "AttributeName": live_ttl["AttributeName"],
                    }
                else:
                    specification = target_ttl
                after_ttl = (
                    copy.deepcopy(specification)
                    if specification.get("Enabled")
                    else {"Enabled": False}
                )
                return _mutation(
                    kind="ttl",
                    before=live_ttl,
                    after=after_ttl,
                    apply=lambda: dynamodb.update_time_to_live(
                        TableName=table_name, TimeToLiveSpecification=specification
                    ),
                )

        if "KinesisStreamSpecification" in desired or (
            not create and "KinesisStreamSpecification" in previous
        ):
            target_kinesis = desired.get("KinesisStreamSpecification")
            live_kinesis = live.get("KinesisStreamSpecification")
            if live_kinesis != target_kinesis:
                if live_kinesis:
                    return _mutation(
                        kind="kinesis",
                        before=live_kinesis,
                        after=None,
                        apply=lambda: dynamodb.disable_kinesis_streaming_destination(
                            TableName=table_name, StreamArn=live_kinesis["StreamArn"]
                        ),
                    )
                return _mutation(
                    kind="kinesis",
                    before=None,
                    after=target_kinesis,
                    apply=lambda: dynamodb.enable_kinesis_streaming_destination(
                        TableName=table_name, StreamArn=target_kinesis["StreamArn"]
                    ),
                )

        if not create and ("Tags" in desired or "Tags" in previous):
            desired_tags = {tag["Key"]: tag["Value"] for tag in desired.get("Tags", [])}
            previous_tag_keys = {tag["Key"] for tag in previous.get("Tags", [])}
            live_tags = {tag["Key"]: tag["Value"] for tag in live.get("Tags", [])}
            remove = sorted((previous_tag_keys - set(desired_tags)) & set(live_tags))
            if remove:
                before = {key: live_tags[key] for key in remove}
                return _mutation(
                    kind="tag_remove",
                    before=before,
                    after={},
                    apply=lambda: dynamodb.untag_resource(ResourceArn=live["Arn"], TagKeys=remove),
                )
            updates = [
                {"Key": key, "Value": value}
                for key, value in sorted(desired_tags.items())
                if live_tags.get(key) != value
            ]
            if updates:
                keys = [tag["Key"] for tag in updates]
                return _mutation(
                    kind="tag_upsert",
                    before={key: live_tags.get(key) for key in keys},
                    after={tag["Key"]: tag["Value"] for tag in updates},
                    apply=lambda: dynamodb.tag_resource(ResourceArn=live["Arn"], Tags=updates),
                )

        if not create and (
            "DeletionProtectionEnabled" in desired or "DeletionProtectionEnabled" in previous
        ):
            target_deletion_protection = bool(desired.get("DeletionProtectionEnabled", False))
            if live.get("DeletionProtectionEnabled") != target_deletion_protection:
                return _mutation(
                    kind="deletion_protection",
                    before=bool(live.get("DeletionProtectionEnabled", False)),
                    after=target_deletion_protection,
                    apply=lambda: dynamodb.update_table(
                        TableName=table_name,
                        DeletionProtectionEnabled=target_deletion_protection,
                    ),
                )
        return None

    def get_ddb_provisioned_throughput(
        self,
        properties: dict,
    ) -> dict | None:
        # see https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html#cfn-dynamodb-table-provisionedthroughput
        args = copy.deepcopy(properties.get("ProvisionedThroughput"))
        if args == "AWS::NoValue":
            return None
        is_ondemand = properties.get("BillingMode") == "PAY_PER_REQUEST"
        # if the BillingMode is set to PAY_PER_REQUEST, you cannot specify ProvisionedThroughput
        # if the BillingMode is set to PROVISIONED (default), you have to specify ProvisionedThroughput

        if args is None:
            if is_ondemand:
                # do not return default value if it's on demand
                return

            # return default values if it's not on demand
            return {
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            }

        if isinstance(args["ReadCapacityUnits"], str):
            args["ReadCapacityUnits"] = int(args["ReadCapacityUnits"])
        if isinstance(args["WriteCapacityUnits"], str):
            args["WriteCapacityUnits"] = int(args["WriteCapacityUnits"])

        return args

    def get_ddb_global_sec_indexes(
        self,
        properties: dict,
    ) -> list | None:
        args: list = copy.deepcopy(properties.get("GlobalSecondaryIndexes"))
        is_ondemand = properties.get("BillingMode") == "PAY_PER_REQUEST"
        if not args:
            return

        for index in args:
            # we ignore ContributorInsightsSpecification as not supported yet in DynamoDB and CloudWatch
            index.pop("ContributorInsightsSpecification", None)
            provisioned_throughput = index.get("ProvisionedThroughput")
            if is_ondemand and provisioned_throughput is None:
                pass  # optional for API calls
            elif provisioned_throughput is not None:
                # convert types
                if isinstance((read_units := provisioned_throughput["ReadCapacityUnits"]), str):
                    provisioned_throughput["ReadCapacityUnits"] = int(read_units)
                if isinstance((write_units := provisioned_throughput["WriteCapacityUnits"]), str):
                    provisioned_throughput["WriteCapacityUnits"] = int(write_units)
            else:
                raise Exception("Can't specify ProvisionedThroughput with PAY_PER_REQUEST")
        return args

    def get_ddb_kinesis_stream_specification(
        self,
        properties: dict,
    ) -> dict:
        args = copy.deepcopy(properties.get("KinesisStreamSpecification"))
        if args:
            args["TableName"] = properties["TableName"]
        return args

    def list(
        self,
        request: ResourceRequest[DynamoDBTableProperties],
    ) -> ProgressEvent[DynamoDBTableProperties]:
        dynamodb = request.aws_client_factory.dynamodb
        table_names = []
        marker = None
        seen_markers = set()
        for _ in range(MAX_TABLE_PAGES):
            kwargs = {"ExclusiveStartTableName": marker} if marker else {}
            response = dynamodb.list_tables(**kwargs)
            table_names.extend(response.get("TableNames", []))
            marker = response.get("LastEvaluatedTableName")
            if not marker:
                break
            if marker in seen_markers:
                raise ValueError("DynamoDB table pagination repeated a marker")
            seen_markers.add(marker)
        else:
            raise ValueError("DynamoDB table pagination exceeded the accepted limit")
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=[
                DynamoDBTableProperties(TableName=table_name) for table_name in table_names
            ],
        )
