import copy
import logging
import re
from urllib.parse import urlsplit

from moto.iam.models import iam_backends

from localstack.aws.api import CommonServiceException, RequestContext, ServiceException
from localstack.aws.api.sts import (
    AssumedRoleUser,
    AssumeRoleResponse,
    AssumeRoleWithWebIdentityResponse,
    Credentials,
    GetCallerIdentityResponse,
    InvalidIdentityTokenException,
    ProvidedContextsListType,
    StsApi,
    arnType,
    clientTokenType,
    externalIdType,
    policyDescriptorListType,
    roleDurationSecondsType,
    roleSessionNameType,
    serialNumberType,
    sessionPolicyDocumentType,
    sourceIdentityType,
    tagKeyListType,
    tagListType,
    tokenCodeType,
    unrestrictedSessionPolicyDocumentType,
    urlType,
)
from localstack.services.iam.iam_patches import apply_iam_patches
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.sts.credentials import (
    DEFAULT_DURATION_SECONDS,
    CredentialIssueError,
    _assert_same_role,
    _resolve_role,
    _validate_trust_policy,
    issue_role_session,
    resolve_session,
    revoke_role_session,
    verify_web_identity_token,
)
from localstack.services.sts.models import SessionConfig, sts_stores
from localstack.state import StateVisitor
from localstack.utils.aws.arns import extract_account_id_from_arn
from localstack.utils.aws.request_context import extract_access_key_id_from_auth_header

LOG = logging.getLogger(__name__)


class InvalidParameterValueError(ServiceException):
    code = "InvalidParameterValue"
    status_code = 400
    sender_fault = True


# allows for arn:a:a:::aaaaaaaaaa which would pass the check
ROLE_ARN_REGEX = re.compile(r"^arn:[^:]+:[^:]+:[^:]*:[^:]*:[^:]+$")
# Session name regex as specified in the error response from AWS
SESSION_NAME_REGEX = re.compile(r"^[\w+=,.@-]*$")


class ValidationError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


class StsProvider(StsApi, ServiceLifecycleHook):
    def __init__(self):
        apply_iam_patches()

    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.sts.models import sts_backends

        visitor.visit(sts_backends)
        visitor.visit(sts_stores)

    def get_caller_identity(self, context: RequestContext, **kwargs) -> GetCallerIdentityResponse:
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        session = resolve_session(
            access_key_id, account_id=context.account_id, region=context.region
        )
        if session is not None:
            return GetCallerIdentityResponse(
                UserId=session.assumed_role_id,
                Account=session.account_id,
                Arn=session.assumed_role_arn,
            )
        response = call_moto(context)
        if "user/moto" in response["Arn"] and "sts" in response["Arn"]:
            response["Arn"] = f"arn:{context.partition}:iam::{response['Account']}:root"
        return response

    def assume_role_with_web_identity(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        web_identity_token: clientTokenType,
        provider_id: urlType = None,
        policy_arns: policyDescriptorListType = None,
        policy: sessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
        **kwargs,
    ) -> AssumeRoleWithWebIdentityResponse:
        if not ROLE_ARN_REGEX.match(role_arn):
            raise ValidationError(f"{role_arn} is invalid")
        if not SESSION_NAME_REGEX.match(role_session_name) or not 2 <= len(role_session_name) <= 64:
            raise ValidationError(
                f"1 validation error detected: Value '{role_session_name}' at 'roleSessionName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]{{2,64}}"
            )
        if duration_seconds is None:
            duration_seconds = DEFAULT_DURATION_SECONDS
        elif (
            not isinstance(duration_seconds, int)
            or isinstance(duration_seconds, bool)
            or not 900 <= duration_seconds <= 43200
        ):
            raise ValidationError(
                f"1 validation error detected: Value '{duration_seconds}' at 'durationSeconds' failed to satisfy constraint: Member must have value between 900 and 43200"
            )
        if provider_id is not None:
            raise InvalidIdentityTokenException(
                "Only OpenID tokens issued by a local Cognito Identity pool are accepted"
            )
        if not isinstance(web_identity_token, str) or not web_identity_token:
            raise ValidationError(
                "1 validation error detected: Value at 'webIdentityToken' failed to satisfy constraint: Member must not be null"
            )

        try:
            claims = verify_web_identity_token(web_identity_token, partition=context.partition)
        except CredentialIssueError as error:
            raise InvalidIdentityTokenException(str(error)) from error

        role_account_id = extract_account_id_from_arn(role_arn)
        if not role_account_id:
            raise ValidationError(f"{role_arn} is invalid")
        amr = "authenticated" if claims.authenticated else "unauthenticated"
        try:
            iam_backend = iam_backends[role_account_id][context.partition]
            role = _resolve_role(iam_backend, role_arn, role_account_id, context.partition)
            role_id = role.id
            policy_document = copy.deepcopy(role.assume_role_policy_document)
            _validate_trust_policy(policy_document, claims.pool_id, amr)
            _assert_same_role(
                iam_backend, role_arn=role_arn, role_id=role_id, policy_document=policy_document
            )
            session = issue_role_session(
                account_id=role_account_id,
                region=context.region,
                partition=context.partition,
                role_arn=role_arn,
                role_session_name=role_session_name,
                duration_seconds=duration_seconds,
                principal_tags=claims.principal_tags,
                provider_name=claims.issuer,
                subject=claims.subject,
            )
            try:
                _assert_same_role(
                    iam_backend,
                    role_arn=role_arn,
                    role_id=role_id,
                    policy_document=policy_document,
                )
            except CredentialIssueError:
                revoke_role_session(session.access_key_id, account_id=role_account_id)
                raise
        except CredentialIssueError as error:
            raise CommonServiceException(
                "AccessDenied", str(error), 403, sender_fault=True
            ) from error

        return AssumeRoleWithWebIdentityResponse(
            Credentials=Credentials(
                AccessKeyId=session.access_key_id,
                SecretAccessKey=session.secret_access_key,
                SessionToken=session.session_token,
                Expiration=session.expiration,
            ),
            SubjectFromWebIdentityToken=claims.subject,
            AssumedRoleUser=AssumedRoleUser(
                AssumedRoleId=session.assumed_role_id,
                Arn=session.assumed_role_arn,
            ),
            # AWS reports the bare provider host (e.g. "cognito-identity.amazonaws.com")
            Provider=urlsplit(claims.issuer).hostname or claims.issuer,
            Audience=claims.pool_id,
        )

    def assume_role(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        policy_arns: policyDescriptorListType = None,
        policy: unrestrictedSessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
        tags: tagListType = None,
        transitive_tag_keys: tagKeyListType = None,
        external_id: externalIdType = None,
        serial_number: serialNumberType = None,
        token_code: tokenCodeType = None,
        source_identity: sourceIdentityType = None,
        provided_contexts: ProvidedContextsListType = None,
        **kwargs,
    ) -> AssumeRoleResponse:
        # verify role arn
        if not ROLE_ARN_REGEX.match(role_arn):
            raise ValidationError(f"{role_arn} is invalid")

        if not SESSION_NAME_REGEX.match(role_session_name):
            raise ValidationError(
                f"1 validation error detected: Value '{role_session_name}' at 'roleSessionName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*"
            )

        target_account_id = extract_account_id_from_arn(role_arn) or context.account_id
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        store = sts_stores[target_account_id]["us-east-1"]
        existing_session_config = store.sessions.get(access_key_id, {})

        if tags:
            tag_keys = {tag["Key"].lower() for tag in tags}
            # if the lower-cased set is smaller than the number of keys, there have to be some duplicates.
            if len(tag_keys) < len(tags):
                raise InvalidParameterValueError(
                    "Duplicate tag keys found. Please note that Tag keys are case insensitive."
                )

            # prevent transitive tags from being overridden
            if existing_session_config:
                if set(existing_session_config["transitive_tags"]).intersection(tag_keys):
                    raise InvalidParameterValueError(
                        "One of the specified transitive tag keys can't be set because it conflicts with a transitive tag key from the calling session."
                    )
            if transitive_tag_keys:
                transitive_tag_key_set = {key.lower() for key in transitive_tag_keys}
                if not transitive_tag_key_set <= tag_keys:
                    raise InvalidParameterValueError(
                        "The specified transitive tag key must be included in the requested tags."
                    )

        response: AssumeRoleResponse = call_moto(context)

        transitive_tag_keys = transitive_tag_keys or []
        tags = tags or []
        transformed_tags = {tag["Key"].lower(): tag for tag in tags}
        # propagate transitive tags
        if existing_session_config:
            for tag in existing_session_config["transitive_tags"]:
                transformed_tags[tag] = existing_session_config["tags"][tag]
            transitive_tag_keys += existing_session_config["transitive_tags"]
        if transformed_tags:
            # store session tagging config
            access_key_id = response["Credentials"]["AccessKeyId"]
            store.sessions[access_key_id] = SessionConfig(
                tags=transformed_tags,
                transitive_tags=[key.lower() for key in transitive_tag_keys],
                iam_context={},
            )
        return response
