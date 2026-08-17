import logging

import pytest

from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)


class CognitoIdpResourceFactory:
    def __init__(self, client):
        self.client = client
        self.domains: list[tuple[str, str]] = []
        self.pool_ids: list[str] = []
        self.resource_servers: list[tuple[str, str]] = []

    def create_user_pool(self, **kwargs):
        kwargs.setdefault("PoolName", f"pool-{short_uid()}")
        response = self.client.create_user_pool(**kwargs)
        self.pool_ids.append(response["UserPool"]["Id"])
        return response

    def create_user_pool_client(self, user_pool_id: str, **kwargs):
        kwargs.setdefault("ClientName", f"client-{short_uid()}")
        return self.client.create_user_pool_client(UserPoolId=user_pool_id, **kwargs)

    def create_user_pool_domain(self, user_pool_id: str, **kwargs):
        kwargs.setdefault("Domain", f"domain-{short_uid()}")
        response = self.client.create_user_pool_domain(UserPoolId=user_pool_id, **kwargs)
        self.domains.append((user_pool_id, kwargs["Domain"]))
        return response

    def create_resource_server(self, user_pool_id: str, **kwargs):
        response = self.client.create_resource_server(UserPoolId=user_pool_id, **kwargs)
        self.resource_servers.append((user_pool_id, kwargs["Identifier"]))
        return response

    def update_resource_server(self, user_pool_id: str, **kwargs):
        return self.client.update_resource_server(UserPoolId=user_pool_id, **kwargs)

    def create_confirmed_user(self, user_pool_id: str, username: str, password: str):
        response = self.client.admin_create_user(
            UserPoolId=user_pool_id,
            Username=username,
            TemporaryPassword=password,
        )
        self.client.admin_set_user_password(
            UserPoolId=user_pool_id,
            Username=username,
            Password=password,
            Permanent=True,
        )
        return response

    def cleanup(self):
        for pool_id, identifier in reversed(self.resource_servers):
            try:
                self.client.delete_resource_server(UserPoolId=pool_id, Identifier=identifier)
            except Exception as error:
                LOG.debug(
                    "Failed to delete Cognito resource server %s from %s: %s",
                    identifier,
                    pool_id,
                    error,
                )
        for pool_id, domain in reversed(self.domains):
            try:
                self.client.delete_user_pool_domain(UserPoolId=pool_id, Domain=domain)
            except Exception as error:
                LOG.debug("Failed to delete Cognito domain %s from %s: %s", domain, pool_id, error)
        for pool_id in reversed(self.pool_ids):
            try:
                self.client.delete_user_pool(UserPoolId=pool_id)
            except Exception as error:
                LOG.debug("Failed to delete Cognito user pool %s: %s", pool_id, error)


@pytest.fixture
def cognito_idp_resources(aws_client):
    factory = CognitoIdpResourceFactory(aws_client.cognito_idp)
    yield factory
    factory.cleanup()
