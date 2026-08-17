from datetime import UTC, datetime, timedelta

import pytest

from localstack.services.cognito_idp.list_users_query import (
    ListUsersQueryError,
    ListUsersQueryPager,
    compile_user_filter,
)

USERS = [
    {
        "Username": "Zulu",
        "Enabled": True,
        "UserStatus": "CONFIRMED",
        "Attributes": {"email": "zulu@example.com", "given_name": "Zed", "sub": "3"},
    },
    {
        "Username": "alpha",
        "Enabled": False,
        "UserStatus": "UNCONFIRMED",
        "Attributes": {"email": "Alpha@example.com", "given_name": "Alice", "sub": "1"},
    },
    {
        "Username": "beta",
        "Enabled": True,
        "UserStatus": "CONFIRMED",
        "Attributes": {"email": "alpine@example.com", "given_name": "ALAN", "sub": "2"},
    },
]


def test_official_filter_parser_exact_prefix_escaping_and_case_rules():
    email = compile_user_filter('email ^= "AL"')
    assert [item["Username"] for item in email.apply(USERS)] == ["alpha", "beta"]
    username = compile_user_filter('username = "Alpha"')
    assert username.apply(USERS) == []
    status = compile_user_filter('cognito:user_status = "confirmed"')
    assert [item["Username"] for item in status.apply(USERS)] == ["beta", "Zulu"]
    escaped = compile_user_filter('given_name = "A\\"lice"')
    assert escaped.value == 'A"lice'


@pytest.mark.parametrize(
    "raw",
    [
        'custom:tenant = "one"',
        'email != "a"',
        'email = "unterminated',
        'email = "bad\\nescape"',
        'email = "a" and name = "b"',
        '"email = "a"',
        'email" = "a"',
        "x" * 257,
    ],
)
def test_filter_parser_rejects_unsupported_or_ambiguous_expressions(raw):
    with pytest.raises(ListUsersQueryError):
        compile_user_filter(raw)


def test_paging_is_sorted_by_filter_attribute_bound_to_query_and_has_no_duplicates():
    now = datetime(2026, 8, 10, tzinfo=UTC)
    pager = ListUsersQueryPager(secret=b"s" * 32, now=lambda: now)

    first, token = pager.page(USERS, scope="pool-1", filter_text='email ^= "al"', limit=1)
    second, final_token = pager.page(
        USERS,
        scope="pool-1",
        filter_text='email ^= "al"',
        limit=1,
        pagination_token=token,
    )

    assert [first[0]["Username"], second[0]["Username"]] == ["alpha", "beta"]
    assert final_token is None

    with pytest.raises(ListUsersQueryError):
        pager.page(
            USERS,
            scope="pool-1",
            filter_text='email = "Alpha@example.com"',
            limit=1,
            pagination_token=token,
        )
    with pytest.raises(ListUsersQueryError):
        pager.page(
            USERS,
            scope="pool-2",
            filter_text='email ^= "al"',
            limit=1,
            pagination_token=token,
        )


def test_pagination_token_is_tamper_evident_and_expires_after_one_hour():
    clock = [datetime(2026, 8, 10, tzinfo=UTC)]
    pager = ListUsersQueryPager(secret=b"p" * 32, now=lambda: clock[0])
    _, token = pager.page(USERS, scope="pool", filter_text=None, limit=1)

    with pytest.raises(ListUsersQueryError):
        pager.page(USERS, scope="pool", filter_text=None, limit=1, pagination_token=token + "x")

    clock[0] += timedelta(hours=1, microseconds=1)
    with pytest.raises(ListUsersQueryError):
        pager.page(USERS, scope="pool", filter_text=None, limit=1, pagination_token=token)


@pytest.mark.parametrize("limit", [-1, 61, True])
def test_limit_uses_official_zero_to_sixty_bounds(limit):
    pager = ListUsersQueryPager(secret=b"p" * 32)
    with pytest.raises(ListUsersQueryError):
        pager.page(USERS, scope="pool", filter_text=None, limit=limit)


def test_zero_limit_is_accepted_without_creating_an_unusable_token_chain():
    pager = ListUsersQueryPager(secret=b"p" * 32)
    assert pager.page(USERS, scope="pool", filter_text=None, limit=0) == ([], None)
