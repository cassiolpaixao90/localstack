import json
from types import SimpleNamespace

import pytest
from moto.iam.exceptions import MalformedPolicyDocument
from moto.iam.models import IAMBackend
from moto.iam.policy_validation import IAMTrustPolicyDocumentValidator

from localstack.services.iam.iam_patches import apply_iam_patches


def _trust_policy(version=...):
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ]
    }
    if version is not ...:
        policy["Version"] = version
    return policy


@pytest.mark.parametrize("version", [..., "2008-10-17", "2012-10-17"])
def test_trust_policy_validator_accepts_all_aws_version_forms_without_mutation(version):
    apply_iam_patches()
    policy = _trust_policy(version)

    IAMTrustPolicyDocumentValidator(json.dumps(policy)).validate()

    if version is ...:
        assert "Version" not in policy
    else:
        assert policy["Version"] == version


@pytest.mark.parametrize("version", [None, "", "2015-01-01"])
def test_trust_policy_validator_rejects_invalid_explicit_versions(version):
    apply_iam_patches()

    with pytest.raises(MalformedPolicyDocument):
        IAMTrustPolicyDocumentValidator(json.dumps(_trust_policy(version))).validate()


def test_moto_backend_updates_and_preserves_trust_policy_without_version():
    apply_iam_patches()
    policy = _trust_policy()
    role = SimpleNamespace(assume_role_policy_document=None)
    backend = SimpleNamespace(get_role=lambda role_name: role)

    IAMBackend.update_assume_role_policy(backend, "role", json.dumps(policy))

    assert json.loads(role.assume_role_policy_document) == policy
