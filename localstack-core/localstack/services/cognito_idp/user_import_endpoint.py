from urllib.parse import parse_qs

from rolo import Request, Response, route
from rolo.routing import Router

from localstack.services.cognito_idp.user_import import (
    ImportJobError,
    get_user_import_jobs,
)

_UPLOAD_PATH = (
    "/_aws/cognito-idp/user-import/"
    "<regex('[0-9]{12}'):account_id>/"
    "<regex('[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+'):region>/"
    "<regex('[\\w-]+_[0-9A-Za-z]+'):pool_id>/"
    "<regex('import-[0-9a-f-]{36}'):job_id>"
)


class CognitoIdpUserImportUploadEndpoint:
    @route(_UPLOAD_PATH, methods=["PUT"])
    def upload(
        self,
        request: Request,
        account_id: str,
        region: str,
        pool_id: str,
        job_id: str,
    ) -> Response:
        try:
            query_values = parse_qs(request.query_string.decode("ascii"), strict_parsing=True)
            if any(len(values) != 1 for values in query_values.values()):
                raise ImportJobError("AccessDenied", "Invalid upload signature", http_status=403)
            query = {name: values[0] for name, values in query_values.items()}
            path = request.path
            jobs = get_user_import_jobs(account_id, region)
            jobs.upload(
                path=path,
                query=query,
                stream=request.stream,
                content_length=request.content_length,
                headers=request.headers,
            )
            return Response(status=200)
        except (UnicodeDecodeError, ValueError):
            return _upload_error(
                ImportJobError("AccessDenied", "Invalid upload signature", http_status=403)
            )
        except ImportJobError as error:
            return _upload_error(error)


def register_cognito_idp_user_import_upload_endpoint(router: Router) -> list:
    return router.add(CognitoIdpUserImportUploadEndpoint())


def _upload_error(error: ImportJobError) -> Response:
    response = Response(error.message, status=error.http_status, mimetype="text/plain")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
