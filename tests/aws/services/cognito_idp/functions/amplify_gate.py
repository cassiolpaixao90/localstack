import json


def handler(event, _context):
    claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
    groups = claims.get("cognito:groups")
    if groups != "[trainer]":
        return {"statusCode": 403, "body": json.dumps({"message": "forbidden"})}
    path = event["rawPath"]
    if path == "/v1/workout-plans" or path == "/v1/workout-sessions":
        body = []
    elif path == "/v1/profile":
        body = {
            "email": claims.get("email"),
            "group": "trainer",
            "id": claims.get("sub"),
            "path": path,
            "role": "trainer",
            "tenantId": claims.get("custom:tenantId"),
        }
    else:
        return {"statusCode": 404, "body": json.dumps({"message": "not found"})}
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }
