from werkzeug.routing import Rule

from localstack.runtime import hooks
from localstack.services.cognito_idp.endpoints import (
    register_cognito_idp_jwks_endpoint,
    register_cognito_idp_oauth_endpoint,
)
from localstack.services.cognito_idp.user_import import shutdown_user_import_jobs
from localstack.services.cognito_idp.user_import_endpoint import (
    register_cognito_idp_user_import_upload_endpoint,
)
from localstack.services.edge import ROUTER

COGNITO_IDP_JWKS_RULES: list[Rule] = []
COGNITO_IDP_OAUTH_RULES: list[Rule] = []
COGNITO_IDP_USER_IMPORT_RULES: list[Rule] = []


@hooks.on_infra_start()
def register_cognito_idp_jwks() -> None:
    global COGNITO_IDP_JWKS_RULES
    if not COGNITO_IDP_JWKS_RULES:
        COGNITO_IDP_JWKS_RULES = register_cognito_idp_jwks_endpoint(ROUTER)


@hooks.on_infra_shutdown()
def remove_cognito_idp_jwks() -> None:
    global COGNITO_IDP_JWKS_RULES
    if COGNITO_IDP_JWKS_RULES:
        ROUTER.remove(COGNITO_IDP_JWKS_RULES)
        COGNITO_IDP_JWKS_RULES = []


@hooks.on_infra_start()
def register_cognito_idp_oauth() -> None:
    global COGNITO_IDP_OAUTH_RULES
    if not COGNITO_IDP_OAUTH_RULES:
        COGNITO_IDP_OAUTH_RULES = register_cognito_idp_oauth_endpoint(ROUTER)


@hooks.on_infra_shutdown()
def remove_cognito_idp_oauth() -> None:
    global COGNITO_IDP_OAUTH_RULES
    if COGNITO_IDP_OAUTH_RULES:
        ROUTER.remove(COGNITO_IDP_OAUTH_RULES)
        COGNITO_IDP_OAUTH_RULES = []


@hooks.on_infra_start()
def register_cognito_idp_user_import() -> None:
    global COGNITO_IDP_USER_IMPORT_RULES
    if not COGNITO_IDP_USER_IMPORT_RULES:
        COGNITO_IDP_USER_IMPORT_RULES = register_cognito_idp_user_import_upload_endpoint(ROUTER)


@hooks.on_infra_shutdown()
def remove_cognito_idp_user_import() -> None:
    global COGNITO_IDP_USER_IMPORT_RULES
    shutdown_user_import_jobs()
    if COGNITO_IDP_USER_IMPORT_RULES:
        ROUTER.remove(COGNITO_IDP_USER_IMPORT_RULES)
        COGNITO_IDP_USER_IMPORT_RULES = []
