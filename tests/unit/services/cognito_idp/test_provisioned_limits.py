import pickle
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from localstack.services.cognito_idp.provisioned_limits import (
    DEFAULT_API_CATEGORY_LIMITS,
    ProvisionedLimitError,
    ProvisionedLimitState,
    get_provisioned_limit,
    update_provisioned_limit,
)

DEFINITION = {
    "Attributes": {"Category": "UserAuthentication"},
    "LimitClass": "API_CATEGORY",
}


def test_only_official_adjustable_api_categories_are_provisionable():
    assert DEFAULT_API_CATEGORY_LIMITS == {
        "UserAuthentication": 120,
        "UserCreation": 50,
        "UserFederation": 25,
        "UserRead": 120,
        "UserResourceRead": 50,
        "UserToken": 120,
    }
    state = ProvisionedLimitState()
    for non_adjustable in ("UserUpdate", "UserResourceUpdate"):
        with pytest.raises(ProvisionedLimitError) as raised:
            get_provisioned_limit(
                state,
                account_id="123456789012",
                region="us-east-1",
                definition={
                    "Attributes": {"Category": non_adjustable},
                    "LimitClass": "API_CATEGORY",
                },
            )
        assert raised.value.code == "ResourceNotFoundException"


def test_get_and_update_provisioned_limit_are_account_region_scoped_and_persistent():
    state = ProvisionedLimitState()
    initial = get_provisioned_limit(
        state,
        account_id="123456789012",
        region="us-east-1",
        definition=DEFINITION,
    )["Limit"]
    assert initial == {
        "FreeLimitValue": 120,
        "LimitDefinition": DEFINITION,
        "ProvisionedLimitValue": 120,
    }
    updated = update_provisioned_limit(
        state,
        account_id="123456789012",
        region="us-east-1",
        definition=DEFINITION,
        requested_value=300,
        account_maxima={"UserAuthentication": 500},
    )
    restored = pickle.loads(pickle.dumps(state))
    assert updated["Limit"]["ProvisionedLimitValue"] == 300
    assert (
        get_provisioned_limit(
            restored,
            account_id="123456789012",
            region="us-east-1",
            definition=DEFINITION,
        )
        == updated
    )
    assert (
        get_provisioned_limit(
            restored,
            account_id="123456789012",
            region="eu-west-1",
            definition=DEFINITION,
        )["Limit"]["ProvisionedLimitValue"]
        == 120
    )


def test_provisioned_limit_bounds_and_definition_are_fail_closed():
    state = ProvisionedLimitState()
    for value, code in ((119, "InvalidParameterException"), (501, "ServiceQuotaExceededException")):
        with pytest.raises(ProvisionedLimitError) as invalid:
            update_provisioned_limit(
                state,
                account_id="123456789012",
                region="us-east-1",
                definition=DEFINITION,
                requested_value=value,
                account_maxima={"UserAuthentication": 500},
            )
        assert invalid.value.code == code
    for definition in (
        {"LimitClass": "API_CATEGORY"},
        {"Attributes": {"Category": "Unknown"}, "LimitClass": "API_CATEGORY"},
        {"Attributes": {"Category": "UserAuthentication"}, "LimitClass": "OTHER"},
    ):
        with pytest.raises(ProvisionedLimitError):
            get_provisioned_limit(
                state,
                account_id="123456789012",
                region="us-east-1",
                definition=definition,
            )


def test_provisioned_limit_updates_are_atomic_under_caller_lock():
    state = ProvisionedLimitState()
    lock = threading.Lock()

    def update(value):
        with lock:
            return update_provisioned_limit(
                state,
                account_id="123456789012",
                region="us-east-1",
                definition=DEFINITION,
                requested_value=value,
                account_maxima={"UserAuthentication": 500},
            )["Limit"]["ProvisionedLimitValue"]

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert sorted(executor.map(update, (200, 300, 400, 500))) == [200, 300, 400, 500]
    assert get_provisioned_limit(
        state,
        account_id="123456789012",
        region="us-east-1",
        definition=DEFINITION,
    )["Limit"]["ProvisionedLimitValue"] in {200, 300, 400, 500}
