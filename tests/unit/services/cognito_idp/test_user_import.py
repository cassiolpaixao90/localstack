import base64
import hashlib
import io
import json
import pickle
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from localstack.http import Request, Router
from localstack.http.dispatcher import handler_dispatcher
from localstack.services.cognito_idp.user_import import (
    MAX_IMPORT_BYTES,
    ImportJobError,
    UserImportJobs,
    user_import_state,
)
from localstack.services.cognito_idp.user_import_endpoint import (
    CognitoIdpUserImportUploadEndpoint,
)
from localstack.services.plugins import Service
from localstack.utils.aws.arns import get_partition
from localstack.utils.aws.aws_stack import get_valid_regions_for_service


@pytest.fixture
def import_topology(tmp_path):
    account_id = "".join(str(byte % 10) for byte in __import__("secrets").token_bytes(12))
    region = next(
        candidate
        for candidate in sorted(get_valid_regions_for_service("cognito-idp"))
        if get_partition(candidate) == "aws"
    )
    pool_id = f"{region}_{__import__('secrets').token_hex(5)}"
    role_arn = f"arn:aws:iam::{account_id}:role/cognito-import"
    pool = SimpleNamespace(
        pool_id=pool_id,
        name="customer-pool",
        schema_attributes=[
            {"Name": "tenant", "AttributeDataType": "String"},
            {"Name": "age", "AttributeDataType": "Number"},
            {"Name": "sub", "AttributeDataType": "String"},
        ],
        auto_verified_attributes=["email"],
        mfa_configuration="OFF",
        users={},
        updated_at=datetime.now(UTC),
    )
    store = SimpleNamespace(user_pools={pool_id: pool})
    pool_lock = threading.RLock()

    @contextmanager
    def pool_transaction(candidate):
        with pool_lock:
            if candidate != pool_id:
                raise ImportJobError("ResourceNotFoundException", "pool not found")
            yield pool

    clock = [datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)]
    emitted_logs = []
    jobs = UserImportJobs(
        store=store,
        account_id=account_id,
        region=region,
        partition="aws",
        storage_root=tmp_path,
        endpoint_url="http://localhost.localstack.cloud:4566",
        pool_transaction=pool_transaction,
        now=lambda: clock[0],
        role_validator=lambda *_: "role-id",
        log_emitter=lambda job, events: emitted_logs.extend(events),
    )
    yield SimpleNamespace(
        account_id=account_id,
        region=region,
        pool_id=pool_id,
        role_arn=role_arn,
        pool=pool,
        store=store,
        jobs=jobs,
        clock=clock,
        tmp_path=tmp_path,
        emitted_logs=emitted_logs,
    )
    jobs.shutdown()


@pytest.fixture
def local_logging_role(import_topology):
    from moto.iam.models import iam_backends
    from moto.logs.models import logs_backends

    backend = iam_backends[import_topology.account_id]["aws"]
    role_name = f"cognito-import-{__import__('secrets').token_hex(6)}"
    role = backend.create_role(
        role_name=role_name,
        assume_role_policy_document=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"Service": "cognito-idp.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
            }
        ),
        path="/",
        permissions_boundary="",
        description="",
        tags=[],
        max_session_duration=3600,
    )
    role.put_policy(
        "cognito-import-logs",
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:DescribeLogStreams",
                        "logs:PutLogEvents",
                    ],
                    "Resource": f"arn:aws:logs:{import_topology.region}:{import_topology.account_id}:log-group:/aws/cognito/*",
                },
            }
        ),
    )
    logs = logs_backends[import_topology.account_id][import_topology.region]
    log_group = f"/aws/cognito/userpools/{import_topology.pool_id}/{import_topology.pool.name}"
    yield SimpleNamespace(role=role, logs=logs, log_group=log_group)
    if log_group in logs.groups:
        logs.delete_log_group(log_group)
    role.delete_policy("cognito-import-logs")
    backend.delete_role(role_name)


def _create(topology, name="customer-import"):
    return topology.jobs.create_job(topology.pool_id, name, topology.role_arn)


def _upload(topology, job, body: bytes, *, url=None, content_length=None):
    url = url or job["PreSignedUrl"]
    parsed = urlsplit(url)
    return topology.jobs.upload(
        path=parsed.path,
        query={key: values[-1] for key, values in parse_qs(parsed.query).items()},
        stream=io.BytesIO(body),
        content_length=len(body) if content_length is None else content_length,
        headers={"x-amz-server-side-encryption": "aws:kms"},
    )


def _csv(topology, *rows):
    header = topology.jobs.get_csv_header(topology.pool_id)
    return (",".join(header) + "\n" + "\n".join(rows) + "\n").encode()


def _row(topology, username, **values):
    values.setdefault("email", f"{username}@example.test")
    values.setdefault("email_verified", "true")
    values["cognito:username"] = username
    return ",".join(values.get(name, "") for name in topology.jobs.get_csv_header(topology.pool_id))


def test_csv_header_derives_custom_pool_schema(import_topology):
    header = import_topology.jobs.get_csv_header(import_topology.pool_id)

    assert header[-3:] == ["cognito:username", "custom:tenant", "custom:age"]
    assert len(header) == len(set(header))
    assert {"email", "email_verified", "cognito:mfa_enabled"} <= set(header)
    assert "custom:sub" not in header


def test_create_uses_local_bound_fifteen_minute_signed_url(import_topology):
    created = _create(import_topology)
    parsed = urlsplit(created["PreSignedUrl"])
    query = parse_qs(parsed.query)

    assert parsed.hostname == "localhost.localstack.cloud"
    assert "example.com" not in created["PreSignedUrl"]
    assert int(query["expires"][0]) == int(
        (import_topology.clock[0] + timedelta(minutes=15)).timestamp()
    )
    assert import_topology.account_id in parsed.path
    assert import_topology.region in parsed.path
    assert created["Status"] == "Created"
    assert created["ImportedUsers"] == 0


def test_password_hash_job_imports_confirmed_user_and_reports_algorithm(import_topology):
    password = "ImportedPass9!"
    salt = b"independent-import-salt"
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 12_345, dklen=32)
    encoded = (
        f"$pbkdf2-sha256$12345$"
        f"{base64.b64encode(salt).decode().rstrip('=')}$"
        f"{base64.b64encode(digest).decode().rstrip('=')}"
    )
    created = import_topology.jobs.create_job(
        import_topology.pool_id,
        "password-hash-import",
        import_topology.role_arn,
        "PBKDF2_SHA256",
    )
    _upload(
        import_topology,
        created,
        _csv(
            import_topology,
            _row(import_topology, "alice", password_hash=encoded),
        ),
    )

    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)
    user = import_topology.pool.users["alice"]

    assert completed["PasswordHashingAlgorithm"] == "PBKDF2_SHA256"
    assert user.status == "CONFIRMED"
    assert user.password.algorithm == "imported:PBKDF2_SHA256"
    assert user.password.verify(password)
    assert not user.password.verify("wrong")


def test_malformed_password_hash_fails_only_its_row(import_topology):
    created = import_topology.jobs.create_job(
        import_topology.pool_id,
        "bad-password-hash",
        import_topology.role_arn,
        "SCRYPT",
    )
    _upload(
        import_topology,
        created,
        _csv(
            import_topology,
            _row(import_topology, "alice", password_hash="131072$8$1$00$00"),
            _row(import_topology, "bob", password_hash=""),
        ),
    )

    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)

    assert completed["FailedUsers"] == 1
    assert "alice" not in import_topology.pool.users
    assert import_topology.pool.users["bob"].status == "RESET_REQUIRED"


def test_create_rejects_role_from_wrong_account(import_topology):
    other = str((int(import_topology.account_id) + 1) % 10**12).zfill(12)
    with pytest.raises(ImportJobError, match="same account") as exc:
        import_topology.jobs.create_job(
            import_topology.pool_id,
            "customer-import",
            f"arn:aws:iam::{other}:role/cognito-import",
        )

    assert exc.value.code == "InvalidParameterException"


def test_upload_is_streamed_bounded_and_not_serialized_in_state(import_topology):
    created = _create(import_topology)
    body = _csv(import_topology, _row(import_topology, "alice", email="alice@example.test"))

    result = _upload(import_topology, created, body)
    persisted = pickle.dumps(user_import_state(import_topology.store))

    assert result == {"size": len(body)}
    assert body not in persisted
    described = import_topology.jobs.describe_job(import_topology.pool_id, created["JobId"])
    assert "UploadPath" not in described
    assert "UploadDigest" not in described


def test_upload_rejects_expired_or_tampered_signature_without_writing(import_topology):
    created = _create(import_topology)
    parsed = urlsplit(created["PreSignedUrl"])
    query = parse_qs(parsed.query)
    query["signature"] = ["0" * 64]

    with pytest.raises(ImportJobError) as tampered:
        import_topology.jobs.upload(
            path=parsed.path,
            query={key: values[-1] for key, values in query.items()},
            stream=io.BytesIO(b"do-not-write"),
            content_length=12,
            headers={"x-amz-server-side-encryption": "aws:kms"},
        )
    assert tampered.value.http_status == 403

    import_topology.clock[0] += timedelta(minutes=16)
    with pytest.raises(ImportJobError) as expired:
        _upload(import_topology, created, b"do-not-write")
    assert expired.value.http_status == 403
    assert not list(import_topology.tmp_path.rglob("*.csv"))


def test_upload_rejects_declared_and_streamed_size_over_limit(import_topology, monkeypatch):
    monkeypatch.setattr("localstack.services.cognito_idp.user_import.MAX_IMPORT_BYTES", 32)
    created = _create(import_topology)

    with pytest.raises(ImportJobError) as declared:
        _upload(import_topology, created, b"x", content_length=MAX_IMPORT_BYTES + 1)
    assert declared.value.http_status == 413

    with pytest.raises(ImportJobError) as streamed:
        _upload(import_topology, created, b"x" * 33, content_length=None)
    assert streamed.value.http_status == 413
    assert not list(import_topology.tmp_path.rglob("*.csv"))


def test_start_imports_valid_users_atomically_as_reset_required(import_topology):
    created = _create(import_topology)
    _upload(
        import_topology,
        created,
        _csv(
            import_topology,
            _row(
                import_topology,
                "alice",
                email="alice@example.test",
                email_verified="true",
                **{"custom:tenant": "one", "custom:age": "42"},
            ),
            _row(import_topology, "bob", email="bob@example.test", **{"custom:age": "7"}),
        ),
    )

    started = import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)

    assert started["Status"] in {"Pending", "InProgress", "Succeeded"}
    assert completed["Status"] == "Succeeded"
    assert completed["ImportedUsers"] == 2
    assert completed["SkippedUsers"] == 0
    assert completed["FailedUsers"] == 0
    assert set(import_topology.pool.users) == {"alice", "bob"}
    assert {user.status for user in import_topology.pool.users.values()} == {"RESET_REQUIRED"}
    assert import_topology.pool.users["alice"].attributes == {
        "custom:age": "42",
        "custom:tenant": "one",
        "email": "alice@example.test",
        "email_verified": "true",
    }
    assert len(import_topology.emitted_logs) == 2
    assert {event["result"] for event in import_topology.emitted_logs} == {"Succeeded"}
    assert not list(import_topology.tmp_path.rglob("*.csv"))


def test_fatal_header_validation_leaves_pool_unchanged(import_topology):
    import_topology.pool.users["existing"] = object()
    created = _create(import_topology)
    _upload(import_topology, created, b"cognito:username,email\nalice,a@example.test\n")

    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)

    assert completed["Status"] == "Failed"
    assert set(import_topology.pool.users) == {"existing"}
    assert "header" in completed["CompletionMessage"].lower()


def test_row_failures_duplicates_and_existing_users_have_bounded_counters(import_topology):
    import_topology.pool.users["existing"] = object()
    created = _create(import_topology)
    _upload(
        import_topology,
        created,
        _csv(
            import_topology,
            _row(import_topology, "existing"),
            _row(import_topology, "alice", **{"custom:age": "not-a-number"}),
            _row(import_topology, "bob", email_verified="not-a-bool"),
            _row(import_topology, "carol"),
            _row(import_topology, "carol"),
        ),
    )

    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)

    assert completed["Status"] == "Succeeded"
    assert completed["ImportedUsers"] == 1
    assert completed["SkippedUsers"] == 1
    assert completed["FailedUsers"] == 3
    assert set(import_topology.pool.users) == {"existing", "carol"}


def test_list_is_newest_first_hmac_paginated_and_pool_bound(import_topology):
    first = _create(import_topology, "first")
    import_topology.clock[0] += timedelta(seconds=1)
    second = _create(import_topology, "second")

    page = import_topology.jobs.list_jobs(import_topology.pool_id, max_results=1)
    assert [job["JobId"] for job in page["UserImportJobs"]] == [second["JobId"]]
    assert page["PaginationToken"]
    tail = import_topology.jobs.list_jobs(
        import_topology.pool_id,
        max_results=1,
        pagination_token=page["PaginationToken"],
    )
    assert [job["JobId"] for job in tail["UserImportJobs"]] == [first["JobId"]]
    assert "PaginationToken" not in tail

    with pytest.raises(ImportJobError, match="pagination"):
        import_topology.jobs.list_jobs(
            import_topology.pool_id,
            max_results=1,
            pagination_token=page["PaginationToken"] + "x",
        )


def test_stop_is_cooperative_and_never_commits_partial_users(import_topology):
    entered = threading.Event()
    release = threading.Event()

    def before_commit():
        entered.set()
        release.wait(5)

    import_topology.jobs.before_commit = before_commit
    created = _create(import_topology)
    _upload(
        import_topology,
        created,
        _csv(import_topology, _row(import_topology, "alice"), _row(import_topology, "bob")),
    )
    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    assert entered.wait(5)

    stopping = import_topology.jobs.stop_job(import_topology.pool_id, created["JobId"])
    release.set()
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)

    assert stopping["Status"] in {"Stopping", "Stopped"}
    assert completed["Status"] == "Stopped"
    assert import_topology.pool.users == {}


def test_job_state_is_account_region_local_and_restart_recovers_orphan(import_topology):
    created = _create(import_topology)
    state = user_import_state(import_topology.store)
    state.jobs[created["JobId"]].status = "InProgress"

    restored = pickle.loads(pickle.dumps(state))
    other_store = SimpleNamespace(user_pools={import_topology.pool_id: import_topology.pool})
    other_store.attr_user_import_jobs = restored
    restarted = UserImportJobs(
        store=other_store,
        account_id=import_topology.account_id,
        region=import_topology.region,
        partition="aws",
        storage_root=import_topology.tmp_path,
        endpoint_url="http://localhost.localstack.cloud:4566",
        pool_transaction=import_topology.jobs.pool_transaction,
        now=lambda: import_topology.clock[0],
        role_validator=lambda *_: "role-id",
        log_emitter=lambda _job, _events: None,
    )
    try:
        result = restarted.describe_job(import_topology.pool_id, created["JobId"])
        assert result["Status"] == "Failed"
        assert "restart" in result["CompletionMessage"].lower()
    finally:
        restarted.shutdown()


def test_start_requires_pool_auto_verified_attributes(import_topology):
    import_topology.pool.auto_verified_attributes = None
    created = _create(import_topology)
    _upload(import_topology, created, _csv(import_topology, _row(import_topology, "alice")))

    with pytest.raises(ImportJobError, match="AutoVerifiedAttributes"):
        import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])

    assert (
        import_topology.jobs.describe_job(import_topology.pool_id, created["JobId"])["Status"]
        == "Created"
    )


def test_each_row_requires_one_verified_auto_verified_attribute(import_topology):
    created = _create(import_topology)
    _upload(
        import_topology,
        created,
        _csv(
            import_topology,
            _row(import_topology, "unverified", email_verified="false"),
            _row(import_topology, "verified"),
        ),
    )

    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)

    assert completed["Status"] == "Succeeded"
    assert completed["ImportedUsers"] == 1
    assert completed["FailedUsers"] == 1
    assert set(import_topology.pool.users) == {"verified"}


def test_csv_rejects_bom_username_whitespace_and_wrong_birthdate(import_topology):
    bom_job = _create(import_topology, "bom")
    _upload(
        import_topology,
        bom_job,
        b"\xef\xbb\xbf" + _csv(import_topology, _row(import_topology, "alice")),
    )
    import_topology.jobs.start_job(import_topology.pool_id, bom_job["JobId"])
    assert import_topology.jobs.wait(bom_job["JobId"], timeout=5)["Status"] == "Failed"

    rows_job = _create(import_topology, "row-validation")
    _upload(
        import_topology,
        rows_job,
        _csv(
            import_topology,
            _row(import_topology, "has space"),
            _row(import_topology, "wrong-date", birthdate="2026-01-01"),
            _row(import_topology, "valid", birthdate="01/31/2026"),
        ),
    )
    import_topology.jobs.start_job(import_topology.pool_id, rows_job["JobId"])
    completed = import_topology.jobs.wait(rows_job["JobId"], timeout=5)
    assert completed["ImportedUsers"] == 1
    assert completed["FailedUsers"] == 2


def test_csv_backslash_escaped_comma_and_formula_are_plain_text(import_topology):
    created = _create(import_topology)
    header = import_topology.jobs.get_csv_header(import_topology.pool_id)
    values = dict.fromkeys(header, "")
    values.update(
        {
            "cognito:username": "alice",
            "email": "alice@example.test",
            "email_verified": "true",
            "name": "Doe\\, Alice",
            "custom:tenant": "=1+1",
        }
    )
    body = (",".join(header) + "\n" + ",".join(values[name] for name in header) + "\n").encode()
    _upload(import_topology, created, body)

    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)

    assert completed["Status"] == "Succeeded"
    assert import_topology.pool.users["alice"].attributes["name"] == "Doe, Alice"
    assert import_topology.pool.users["alice"].attributes["custom:tenant"] == "=1+1"


def test_mfa_column_respects_pool_configuration(import_topology):
    off_job = _create(import_topology, "mfa-off")
    _upload(
        import_topology,
        off_job,
        _csv(import_topology, _row(import_topology, "alice", **{"cognito:mfa_enabled": "true"})),
    )
    import_topology.jobs.start_job(import_topology.pool_id, off_job["JobId"])
    assert import_topology.jobs.wait(off_job["JobId"], timeout=5)["FailedUsers"] == 1
    assert import_topology.emitted_logs[-1]["reason"] == "SMS_MFA_import_not_supported"

    import_topology.pool.mfa_configuration = "ON"
    import_topology.emitted_logs.clear()
    on_job = _create(import_topology, "mfa-on")
    _upload(
        import_topology,
        on_job,
        _csv(
            import_topology,
            _row(import_topology, "bob", **{"cognito:mfa_enabled": "false"}),
            _row(
                import_topology,
                "carol",
                phone_number="+15555550100",
                phone_number_verified="true",
                **{"cognito:mfa_enabled": "true"},
            ),
        ),
    )
    import_topology.jobs.start_job(import_topology.pool_id, on_job["JobId"])
    completed = import_topology.jobs.wait(on_job["JobId"], timeout=5)
    assert completed["ImportedUsers"] == 0
    assert completed["FailedUsers"] == 2
    assert {event["reason"] for event in import_topology.emitted_logs} == {
        "MFA_required_for_pool",
        "SMS_MFA_import_not_supported",
    }


def test_only_one_import_can_be_active_and_role_is_revalidated(import_topology):
    entered = threading.Event()
    release = threading.Event()
    import_topology.jobs.role_validator = lambda *_: "role-id"

    def before_commit():
        entered.set()
        release.wait(5)

    import_topology.jobs.before_commit = before_commit
    first = _create(import_topology, "first")
    second = _create(import_topology, "second")
    _upload(import_topology, first, _csv(import_topology, _row(import_topology, "alice")))
    _upload(import_topology, second, _csv(import_topology, _row(import_topology, "bob")))
    import_topology.jobs.start_job(import_topology.pool_id, first["JobId"])
    assert entered.wait(5)

    with pytest.raises(ImportJobError, match="active"):
        import_topology.jobs.start_job(import_topology.pool_id, second["JobId"])
    release.set()
    assert import_topology.jobs.wait(first["JobId"], timeout=5)["Status"] == "Succeeded"

    changed = _create(import_topology, "changed-role")
    _upload(import_topology, changed, _csv(import_topology, _row(import_topology, "carol")))
    import_topology.jobs.role_validator = lambda *_: "different-role-id"
    with pytest.raises(ImportJobError, match="changed"):
        import_topology.jobs.start_job(import_topology.pool_id, changed["JobId"])


def test_upload_requires_signed_encryption_header_and_exact_content_length(import_topology):
    created = _create(import_topology)
    parsed = urlsplit(created["PreSignedUrl"])
    query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}

    with pytest.raises(ImportJobError) as missing:
        import_topology.jobs.upload(
            path=parsed.path,
            query=query,
            stream=io.BytesIO(b"abc"),
            content_length=3,
            headers={},
        )
    assert missing.value.http_status == 403

    with pytest.raises(ImportJobError, match="Content-Length"):
        import_topology.jobs.upload(
            path=parsed.path,
            query=query,
            stream=io.BytesIO(b"abc"),
            content_length=2,
            headers={"x-amz-server-side-encryption": "aws:kms"},
        )
    assert not list(import_topology.tmp_path.rglob("*.csv"))


def test_storage_root_symlink_is_rejected(import_topology, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(ImportJobError, match="Unsafe"):
        UserImportJobs(
            store=SimpleNamespace(user_pools={import_topology.pool_id: import_topology.pool}),
            account_id=import_topology.account_id,
            region=import_topology.region,
            partition="aws",
            storage_root=linked,
            endpoint_url="http://localhost.localstack.cloud:4566",
            pool_transaction=import_topology.jobs.pool_transaction,
            role_validator=lambda *_: "role-id",
            log_emitter=lambda _job, _events: None,
        )


def test_upload_endpoint_dispatches_put_and_rejects_missing_signed_header(
    import_topology, monkeypatch
):
    monkeypatch.setattr(
        "localstack.services.cognito_idp.user_import_endpoint.get_user_import_jobs",
        lambda _account, _region: import_topology.jobs,
    )
    router = Router(dispatcher=handler_dispatcher())
    router.add(CognitoIdpUserImportUploadEndpoint())
    first = _create(import_topology, "endpoint-first")
    parsed = urlsplit(first["PreSignedUrl"])
    body = _csv(import_topology, _row(import_topology, "alice"))

    forbidden = router.dispatch(Request("PUT", parsed.path, body=body, query_string=parsed.query))
    assert forbidden.status_code == 403

    second = _create(import_topology, "endpoint-second")
    parsed = urlsplit(second["PreSignedUrl"])
    uploaded = router.dispatch(
        Request(
            "PUT",
            parsed.path,
            body=body,
            query_string=parsed.query,
            headers={"x-amz-server-side-encryption": "aws:kms"},
        )
    )
    assert uploaded.status_code == 200


def test_account_coordinator_blocks_cross_region_import(import_topology, tmp_path):
    entered = threading.Event()
    release = threading.Event()
    import_topology.jobs.before_commit = lambda: (entered.set(), release.wait(5))
    first = _create(import_topology, "first")
    _upload(import_topology, first, _csv(import_topology, _row(import_topology, "alice")))
    import_topology.jobs.start_job(import_topology.pool_id, first["JobId"])
    assert entered.wait(5)

    other_region = next(
        candidate
        for candidate in sorted(get_valid_regions_for_service("cognito-idp"))
        if get_partition(candidate) == "aws" and candidate != import_topology.region
    )
    other_pool_id = f"{other_region}_{__import__('secrets').token_hex(5)}"
    other_pool = SimpleNamespace(
        pool_id=other_pool_id,
        name="other-pool",
        schema_attributes=[],
        auto_verified_attributes=["email"],
        mfa_configuration="OFF",
        users={},
        updated_at=import_topology.clock[0],
    )
    other_store = SimpleNamespace(user_pools={other_pool_id: other_pool})

    @contextmanager
    def other_transaction(candidate):
        if candidate != other_pool_id:
            raise ImportJobError("ResourceNotFoundException", "pool not found")
        yield other_pool

    other = UserImportJobs(
        store=other_store,
        account_id=import_topology.account_id,
        region=other_region,
        partition="aws",
        storage_root=tmp_path / "other",
        endpoint_url="http://localhost.localstack.cloud:4566",
        pool_transaction=other_transaction,
        now=lambda: import_topology.clock[0],
        role_validator=lambda *_: "role-id",
        log_emitter=lambda _job, _events: None,
    )
    try:
        role = f"arn:aws:iam::{import_topology.account_id}:role/cognito-import"
        second = other.create_job(other_pool_id, "second", role)
        body = (
            ",".join(other.get_csv_header(other_pool_id))
            + "\n"
            + _row_for_header(other.get_csv_header(other_pool_id), "bob")
            + "\n"
        ).encode()
        parsed = urlsplit(second["PreSignedUrl"])
        other.upload(
            path=parsed.path,
            query={key: values[-1] for key, values in parse_qs(parsed.query).items()},
            stream=io.BytesIO(body),
            content_length=len(body),
            headers={"x-amz-server-side-encryption": "aws:kms"},
        )
        with pytest.raises(ImportJobError, match="active"):
            other.start_job(other_pool_id, second["JobId"])
    finally:
        release.set()
        import_topology.jobs.wait(first["JobId"], timeout=5)
        other.shutdown()


def test_failure_log_truncation_is_explicit(import_topology, monkeypatch):
    monkeypatch.setattr("localstack.services.cognito_idp.user_import.MAX_IMPORT_LOG_EVENTS", 1)
    created = _create(import_topology)
    _upload(
        import_topology,
        created,
        _csv(
            import_topology,
            _row(import_topology, "one", email_verified="invalid"),
            _row(import_topology, "two", email_verified="invalid"),
            _row(import_topology, "three", email_verified="invalid"),
            _row(import_topology, "valid"),
        ),
    )
    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)

    assert completed["FailedUsers"] == 3
    truncated = [event for event in import_topology.emitted_logs if event["result"] == "Truncated"]
    assert truncated == [{"line": 0, "result": "Truncated", "reason": "2_failure_events_omitted"}]


def test_outcome_logs_are_bounded_and_truncation_includes_skips(import_topology, monkeypatch):
    initial = _create(import_topology, "initial")
    _upload(
        import_topology,
        initial,
        _csv(import_topology, _row(import_topology, "existing")),
    )
    import_topology.jobs.start_job(import_topology.pool_id, initial["JobId"])
    assert import_topology.jobs.wait(initial["JobId"], timeout=5)["Status"] == "Succeeded"

    import_topology.emitted_logs.clear()
    monkeypatch.setattr("localstack.services.cognito_idp.user_import.MAX_IMPORT_LOG_EVENTS", 1)
    created = _create(import_topology, "bounded-outcomes")
    _upload(
        import_topology,
        created,
        _csv(
            import_topology,
            _row(import_topology, "existing"),
            _row(import_topology, "fresh-one"),
            _row(import_topology, "fresh-two"),
        ),
    )
    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    completed = import_topology.jobs.wait(created["JobId"], timeout=5)

    assert completed["ImportedUsers"] == 2
    assert completed["SkippedUsers"] == 1
    assert import_topology.emitted_logs == [
        {"line": 2, "result": "Skipped", "reason": "User_already_exists"},
        {"line": 0, "result": "Truncated", "reason": "2_outcome_events_omitted"},
    ]


def test_native_dispatch_registers_all_six_import_operations():
    from localstack.services.cognito_idp.provider import CognitoIdpProvider

    dispatch = Service.for_provider(CognitoIdpProvider()).skeleton.dispatch_table
    assert {
        "CreateUserImportJob",
        "DescribeUserImportJob",
        "GetCSVHeader",
        "ListUserImportJobs",
        "StartUserImportJob",
        "StopUserImportJob",
    } <= dispatch.keys()


def test_local_iam_boundary_and_cloudwatch_log_delivery(import_topology, local_logging_role):
    import_topology.clock[0] = datetime.now(UTC)
    import_topology.jobs.role_validator = import_topology.jobs._validate_local_role
    import_topology.jobs.log_emitter = import_topology.jobs._emit_cloudwatch_logs
    created = import_topology.jobs.create_job(
        import_topology.pool_id, "cloudwatch", local_logging_role.role.arn
    )
    _upload(
        import_topology,
        created,
        _csv(import_topology, _row(import_topology, "alice")),
    )
    import_topology.jobs.start_job(import_topology.pool_id, created["JobId"])
    assert import_topology.jobs.wait(created["JobId"], timeout=5)["Status"] == "Succeeded"

    stream = local_logging_role.logs.groups[local_logging_role.log_group].streams[
        f"{created['JobId']}/cloudwatch"
    ]
    messages = [event.message for event in stream.events]
    assert len(messages) == 1
    assert '"result":"Succeeded"' in messages[0]
    assert "alice" not in messages[0]


def _row_for_header(header, username):
    values = {
        "cognito:username": username,
        "email": f"{username}@example.test",
        "email_verified": "true",
    }
    return ",".join(values.get(name, "") for name in header)
