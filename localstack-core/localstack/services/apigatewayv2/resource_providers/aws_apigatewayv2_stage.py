from .base import ApiGatewayV2ResourceProvider, ResourceConfig, schema_path


class ApiGatewayV2StageProvider(ApiGatewayV2ResourceProvider):
    TYPE = "AWS::ApiGatewayV2::Stage"
    SCHEMA = schema_path(__file__)
    CONFIG = ResourceConfig(
        create="create_stage",
        read="get_stage",
        list_operation="get_stages",
        update="update_stage",
        delete="delete_stage",
        identifier="StageName",
        parent="ApiId",
        create_fields=(
            "AccessLogSettings",
            "ApiId",
            "AutoDeploy",
            "DefaultRouteSettings",
            "DeploymentId",
            "Description",
            "StageName",
            "StageVariables",
            "Tags",
        ),
        update_fields=(
            "AccessLogSettings",
            "AutoDeploy",
            "DefaultRouteSettings",
            "DeploymentId",
            "Description",
            "StageVariables",
        ),
        response_fields=(
            "AccessLogSettings",
            "ApiGatewayManaged",
            "ApiId",
            "AutoDeploy",
            "CreatedDate",
            "DefaultRouteSettings",
            "DeploymentId",
            "Description",
            "LastUpdatedDate",
            "StageName",
            "StageVariables",
            "Tags",
        ),
        reset_fields=(
            ("AccessLogSettings", None),
            ("DefaultRouteSettings", None),
            ("Description", None),
            ("StageVariables", {}),
        ),
        tag_path="/stages/{StageName}",
    )
