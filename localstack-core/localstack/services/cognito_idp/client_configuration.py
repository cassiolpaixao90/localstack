from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import unquote


class ClientConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class ClientScope:
    partition: str
    region: str
    account_id: str


@dataclass(frozen=True)
class ProjectSnapshot:
    application_arn: str
    application_id: str


@dataclass(frozen=True)
class RoleSnapshot:
    assume_role_policy: Mapping[str, Any]
    permission_policies: tuple[Mapping[str, Any], ...]
    role_arn: str
    role_id: str


ProjectResolver = Callable[[str], ProjectSnapshot]
RoleResolver = Callable[[str], RoleSnapshot]


@dataclass(frozen=True)
class AnalyticsConfiguration:
    application_arn: str | None
    application_id: str
    external_id: str | None
    role_arn: str | None
    user_data_shared: bool
    resource_snapshot: str

    def to_api(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "UserDataShared": self.user_data_shared,
        }
        if self.application_arn is not None:
            result["ApplicationArn"] = self.application_arn
        else:
            result["ApplicationId"] = self.application_id
            result["ExternalId"] = self.external_id
            result["RoleArn"] = self.role_arn
        return result


_DEFAULT_AUTH_FLOWS = (
    "ALLOW_CUSTOM_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
)
_AUTH_FLOW_ALIASES = {
    "ADMIN_NO_SRP_AUTH": "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "CUSTOM_AUTH_FLOW_ONLY": "ALLOW_CUSTOM_AUTH",
    "USER_PASSWORD_AUTH": "ALLOW_USER_PASSWORD_AUTH",
}
_AUTH_FLOWS = {
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_CUSTOM_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
}
_ANALYTICS_FIELDS = {
    "ApplicationArn",
    "ApplicationId",
    "ExternalId",
    "RoleArn",
    "UserDataShared",
}
_APPLICATION_ID = re.compile(r"^[0-9a-fA-F]{1,64}$")
_MAX_IAM_PAGES = 100
_MAX_ROLE_POLICIES = 1_000


def normalize_explicit_auth_flows(value: Any) -> tuple[str, ...]:
    if value is None:
        return _DEFAULT_AUTH_FLOWS
    if (
        not isinstance(value, list)
        or not value
        or len(value) > len(_AUTH_FLOWS) + len(_AUTH_FLOW_ALIASES)
        or not all(isinstance(item, str) for item in value)
    ):
        _invalid("ExplicitAuthFlows must be a bounded non-empty list")
    normalized = tuple(dict.fromkeys(_AUTH_FLOW_ALIASES.get(item, item) for item in value))
    if unknown := set(normalized) - _AUTH_FLOWS:
        _invalid(f"Unsupported ExplicitAuthFlows: {sorted(unknown)}")
    return normalized


def validate_propagate_additional_context(value: Any, *, has_client_secret: bool) -> bool:
    if value is None:
        return False
    if not isinstance(value, bool):
        _invalid("EnablePropagateAdditionalUserContextData must be a boolean")
    if value and not has_client_secret:
        _invalid("EnablePropagateAdditionalUserContextData requires a client secret")
    return value


def parse_analytics_configuration(
    value: Any,
    *,
    scope: ClientScope,
    project_resolver: ProjectResolver,
    role_resolver: RoleResolver,
) -> AnalyticsConfiguration:
    _validate_scope(scope)
    if not isinstance(value, Mapping) or not value or set(value) - _ANALYTICS_FIELDS:
        _invalid("Invalid AnalyticsConfiguration")
    application_arn = value.get("ApplicationArn")
    application_id = value.get("ApplicationId")
    role_arn = value.get("RoleArn")
    external_id = value.get("ExternalId")
    shared = value.get("UserDataShared", False)
    if not isinstance(shared, bool):
        _invalid("UserDataShared must be a boolean")

    if application_arn is not None:
        if application_id is not None or role_arn is not None or external_id is not None:
            _invalid("ApplicationArn cannot be combined with legacy analytics role fields")
        app_id = _project_id_from_arn(application_arn, scope)
        project = _resolve_project(project_resolver, application_arn)
        _assert_project(project, scope, app_id)
        role = None
    else:
        if not isinstance(application_id, str) or not _APPLICATION_ID.fullmatch(application_id):
            _invalid("ApplicationId must be a hexadecimal Pinpoint project ID")
        if not isinstance(role_arn, str) or not isinstance(external_id, str):
            _invalid("ApplicationId analytics requires RoleArn and ExternalId")
        if len(external_id) > 131_072 or "\x00" in external_id:
            _invalid("Invalid analytics ExternalId")
        _assert_role_arn(role_arn, scope)
        project = _resolve_project(project_resolver, application_id)
        _assert_project(project, scope, application_id)
        role = _resolve_role(role_resolver, role_arn)
        _assert_role(role, scope, external_id, project.application_arn)
        app_id = application_id

    return AnalyticsConfiguration(
        application_arn=application_arn,
        application_id=app_id,
        external_id=external_id,
        role_arn=role_arn,
        user_data_shared=shared,
        resource_snapshot=_snapshot(project, role),
    )


def revalidate_analytics_configuration(
    configuration: AnalyticsConfiguration,
    *,
    project_resolver: ProjectResolver,
    role_resolver: RoleResolver,
) -> None:
    reference = configuration.application_arn or configuration.application_id
    project = _resolve_project(project_resolver, reference)
    role = (
        _resolve_role(role_resolver, configuration.role_arn)
        if configuration.role_arn is not None
        else None
    )
    if not _constant_time_equal(configuration.resource_snapshot, _snapshot(project, role)):
        _invalid("Analytics resources changed during client mutation")


def analytics_resolvers(client_factory) -> tuple[ProjectResolver, RoleResolver]:
    def project_resolver(reference: str) -> ProjectSnapshot:
        application_id = reference.rsplit("/", 1)[-1]
        response = client_factory.pinpoint.get_app(ApplicationId=application_id)
        project = response.get("ApplicationResponse")
        if not isinstance(project, dict):
            raise ValueError("Pinpoint GetApp returned no application")
        return ProjectSnapshot(
            application_arn=project.get("Arn"),
            application_id=project.get("Id"),
        )

    def role_resolver(role_arn: str) -> RoleSnapshot:
        iam = client_factory.iam
        role_name = role_arn.rsplit("/", 1)[-1]
        role = iam.get_role(RoleName=role_name).get("Role")
        if not isinstance(role, dict):
            raise ValueError("IAM GetRole returned no role")
        policies = []
        inline = _paginated_iam_items(
            iam.list_role_policies,
            "PolicyNames",
            RoleName=role_name,
        )
        attached = _paginated_iam_items(
            iam.list_attached_role_policies,
            "AttachedPolicies",
            RoleName=role_name,
        )
        if len(inline) + len(attached) > _MAX_ROLE_POLICIES:
            raise ValueError("IAM role policy limit exceeded")
        for policy_name in sorted(inline):
            response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            policies.append(_policy_document(response.get("PolicyDocument")))
        for attached_policy in sorted(attached, key=lambda item: item.get("PolicyArn", "")):
            policy_arn = attached_policy.get("PolicyArn")
            if not isinstance(policy_arn, str) or not policy_arn:
                raise ValueError("Invalid attached IAM policy")
            policy = iam.get_policy(PolicyArn=policy_arn).get("Policy")
            if not isinstance(policy, dict) or not isinstance(policy.get("DefaultVersionId"), str):
                raise ValueError("Invalid attached IAM policy metadata")
            version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy["DefaultVersionId"],
            ).get("PolicyVersion")
            if not isinstance(version, dict):
                raise ValueError("Invalid attached IAM policy version")
            policies.append(_policy_document(version.get("Document")))
        return RoleSnapshot(
            assume_role_policy=_policy_document(role.get("AssumeRolePolicyDocument")),
            permission_policies=tuple(policies),
            role_arn=role.get("Arn"),
            role_id=role.get("RoleId"),
        )

    return project_resolver, role_resolver


def _assert_project(project: ProjectSnapshot, scope: ClientScope, expected_id: str) -> None:
    if project.application_id != expected_id:
        _invalid("Pinpoint project identity does not match AnalyticsConfiguration")
    if _project_id_from_arn(project.application_arn, scope) != expected_id:
        _invalid("Pinpoint project is outside the user-pool account or region scope")


def _assert_role(
    role: RoleSnapshot,
    scope: ClientScope,
    external_id: str,
    project_arn: str,
) -> None:
    _assert_role_arn(role.role_arn, scope)
    if not isinstance(role.role_id, str) or not 1 <= len(role.role_id) <= 128:
        _invalid("Invalid IAM role identity")
    if not _trusts_cognito(role.assume_role_policy, external_id):
        _invalid("Analytics role trust policy does not authorize Cognito with the ExternalId")
    required = {
        "mobiletargeting:PutEvents": project_arn,
        "mobiletargeting:UpdateEndpoint": project_arn,
        "cognito-idp:Describe*": "*",
    }
    for action, resource in required.items():
        if not _policies_allow(role.permission_policies, action, resource):
            _invalid(f"Analytics role does not allow {action} for the required resource")


def _trusts_cognito(policy: Mapping[str, Any], external_id: str) -> bool:
    for statement in _statements(policy):
        if statement.get("Effect") != "Allow":
            continue
        if set(_strings(statement.get("Action"))) != {"sts:AssumeRole"}:
            continue
        principal = statement.get("Principal")
        if not isinstance(principal, Mapping) or set(_strings(principal.get("Service"))) != {
            "cognito-idp.amazonaws.com"
        }:
            continue
        if statement.get("Resource") not in (None, "*"):
            continue
        condition = statement.get("Condition")
        if condition != {"StringEquals": {"sts:ExternalId": external_id}}:
            continue
        return True
    return False


def _policies_allow(
    policies: Sequence[Mapping[str, Any]], requested_action: str, requested_resource: str
) -> bool:
    allowed = False
    for policy in policies:
        for statement in _statements(policy):
            actions = _strings(statement.get("Action"))
            resources = _strings(statement.get("Resource"))
            matches_action = any(
                fnmatch.fnmatchcase(requested_action.lower(), pattern.lower())
                for pattern in actions
            )
            matches_resource = any(
                _resource_matches(pattern, requested_resource) for pattern in resources
            )
            if not matches_action or not matches_resource or statement.get("Condition") is not None:
                continue
            if statement.get("Effect") == "Deny":
                return False
            if statement.get("Effect") == "Allow":
                allowed = True
    return allowed


def _resource_matches(pattern: str, requested: str) -> bool:
    if requested == "*":
        return pattern == "*"
    return pattern in {requested, f"{requested}/*"}


def _statements(policy: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if not isinstance(policy, Mapping) or set(policy) - {"Statement", "Version"}:
        return []
    raw = policy.get("Statement", [])
    values = raw if isinstance(raw, list) else [raw]
    return [value for value in values if isinstance(value, Mapping)]


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    return ()


def _project_id_from_arn(value: Any, scope: ClientScope) -> str:
    if not isinstance(value, str) or not 20 <= len(value) <= 2048:
        _invalid("Invalid Pinpoint ApplicationArn")
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[:2] != ["arn", scope.partition]:
        _invalid("Pinpoint ApplicationArn is outside the configured partition scope")
    _, _, service, region, account_id, resource = parts
    if service != "mobiletargeting" or region != scope.region or account_id != scope.account_id:
        _invalid("Pinpoint ApplicationArn is outside the configured account or region scope")
    prefix = "apps/"
    application_id = resource.removeprefix(prefix)
    if resource == application_id or not _APPLICATION_ID.fullmatch(application_id):
        _invalid("Invalid Pinpoint ApplicationArn resource")
    return application_id


def _assert_role_arn(value: str, scope: ClientScope) -> None:
    parts = value.split(":", 5)
    if (
        len(parts) != 6
        or parts[:3] != ["arn", scope.partition, "iam"]
        or parts[3] != ""
        or parts[4] != scope.account_id
        or not parts[5].startswith("role/")
        or len(parts[5]) <= len("role/")
    ):
        _invalid("Analytics RoleArn is outside the configured account scope")


def _resolve_project(resolver: ProjectResolver, reference: str) -> ProjectSnapshot:
    try:
        project = resolver(reference)
    except Exception as error:
        raise ClientConfigurationError("Pinpoint project could not be validated locally") from error
    if not isinstance(project, ProjectSnapshot):
        _invalid("Invalid Pinpoint project snapshot")
    return project


def _resolve_role(resolver: RoleResolver, role_arn: str) -> RoleSnapshot:
    try:
        role = resolver(role_arn)
    except Exception as error:
        raise ClientConfigurationError("IAM role could not be validated locally") from error
    if not isinstance(role, RoleSnapshot):
        _invalid("Invalid IAM role snapshot")
    return role


def _paginated_iam_items(operation, result_key: str, **params):
    items = []
    marker = None
    seen = set()
    for _ in range(_MAX_IAM_PAGES):
        request = dict(params)
        if marker is not None:
            request["Marker"] = marker
        response = operation(**request)
        page = response.get(result_key, [])
        if not isinstance(page, list):
            raise ValueError(f"IAM {result_key} response is invalid")
        items.extend(page)
        if not response.get("IsTruncated"):
            return items
        marker = response.get("Marker")
        if not isinstance(marker, str) or not marker or marker in seen:
            raise ValueError("IAM pagination returned an invalid marker")
        seen.add(marker)
    raise ValueError("IAM pagination limit exceeded")


def _policy_document(value: object) -> dict:
    if isinstance(value, dict):
        return copy.deepcopy(value)
    if isinstance(value, str):
        try:
            result = json.loads(unquote(value))
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            raise ValueError("Invalid IAM policy document") from error
        if isinstance(result, dict):
            return result
    raise ValueError("Invalid IAM policy document")


def _snapshot(project: ProjectSnapshot, role: RoleSnapshot | None) -> str:
    payload = {
        "project": asdict(project),
        "role": asdict(role) if role is not None else None,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=list)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def _validate_scope(scope: ClientScope) -> None:
    if (
        not isinstance(scope.partition, str)
        or not scope.partition
        or not isinstance(scope.region, str)
        or not scope.region
        or not isinstance(scope.account_id, str)
        or not re.fullmatch(r"[0-9]{12}", scope.account_id)
    ):
        _invalid("Invalid client account or region scope")


def _invalid(message: str) -> None:
    raise ClientConfigurationError(message)
