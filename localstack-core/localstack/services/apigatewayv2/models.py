import copy
import dataclasses
from datetime import datetime
from typing import Any

from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


@dataclasses.dataclass
class ApiGatewayV2Authorizer:
    authorizer_id: str
    arn: str
    properties: dict[str, Any]

    def to_response(self) -> dict[str, Any]:
        return copy.deepcopy(self.properties)


@dataclasses.dataclass
class ApiGatewayV2Integration:
    integration_id: str
    properties: dict[str, Any]

    def to_response(self) -> dict[str, Any]:
        return copy.deepcopy(self.properties)


@dataclasses.dataclass
class ApiGatewayV2Route:
    route_id: str
    properties: dict[str, Any]

    def to_response(self) -> dict[str, Any]:
        return copy.deepcopy(self.properties)


@dataclasses.dataclass
class ApiGatewayV2DeploymentSnapshot:
    authorizers: dict[str, ApiGatewayV2Authorizer]
    integrations: dict[str, ApiGatewayV2Integration]
    routes: dict[str, ApiGatewayV2Route]


@dataclasses.dataclass
class ApiGatewayV2Deployment:
    deployment_id: str
    properties: dict[str, Any]
    snapshot: ApiGatewayV2DeploymentSnapshot

    def to_response(self) -> dict[str, Any]:
        return copy.deepcopy(self.properties)


@dataclasses.dataclass
class ApiGatewayV2Stage:
    stage_name: str
    properties: dict[str, Any]

    def to_response(self) -> dict[str, Any]:
        return copy.deepcopy(self.properties)


@dataclasses.dataclass
class ApiGatewayV2ApiMapping:
    api_mapping_id: str
    properties: dict[str, Any]

    def to_response(self) -> dict[str, Any]:
        return copy.deepcopy(self.properties)


@dataclasses.dataclass
class ApiGatewayV2DomainName:
    domain_name: str
    arn: str
    properties: dict[str, Any]
    api_mappings: dict[str, ApiGatewayV2ApiMapping] = dataclasses.field(default_factory=dict)

    def to_response(self) -> dict[str, Any]:
        return copy.deepcopy(self.properties)


@dataclasses.dataclass
class ApiGatewayV2Api:
    api_id: str
    arn: str
    created_at: datetime
    properties: dict[str, Any]
    authorizers: dict[str, ApiGatewayV2Authorizer] = dataclasses.field(default_factory=dict)
    integrations: dict[str, ApiGatewayV2Integration] = dataclasses.field(default_factory=dict)
    routes: dict[str, ApiGatewayV2Route] = dataclasses.field(default_factory=dict)
    deployments: dict[str, ApiGatewayV2Deployment] = dataclasses.field(default_factory=dict)
    stages: dict[str, ApiGatewayV2Stage] = dataclasses.field(default_factory=dict)

    def to_response(self) -> dict[str, Any]:
        return copy.deepcopy(self.properties)


class ApiGatewayV2Store(BaseStore):
    apis: dict[str, ApiGatewayV2Api] = LocalAttribute(default=dict)
    domain_names: dict[str, ApiGatewayV2DomainName] = LocalAttribute(default=dict)
    pagination_secret: bytes = LocalAttribute(default=b"")


apigatewayv2_stores = AccountRegionBundle("apigatewayv2", ApiGatewayV2Store)
