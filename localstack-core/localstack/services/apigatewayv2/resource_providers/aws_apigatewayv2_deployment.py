from .base import ApiGatewayV2ResourceProvider, ResourceConfig, schema_path


class ApiGatewayV2DeploymentProvider(ApiGatewayV2ResourceProvider):
    TYPE = "AWS::ApiGatewayV2::Deployment"
    SCHEMA = schema_path(__file__)
    CONFIG = ResourceConfig(
        create="create_deployment",
        read="get_deployment",
        list_operation="get_deployments",
        update=None,
        delete="delete_deployment",
        identifier="DeploymentId",
        parent="ApiId",
        create_fields=("ApiId", "Description"),
        update_fields=(),
        response_fields=(
            "ApiId",
            "AutoDeployed",
            "CreatedDate",
            "DeploymentId",
            "DeploymentStatus",
            "DeploymentStatusMessage",
            "Description",
        ),
    )
