"""Isolated stdlib-only health probe for the CDK launcher."""

import sys
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_RESPONSE_BYTES = 64 * 1024
SOCKET_TIMEOUT_SECONDS = 10


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def main(endpoint_url: str) -> int:
    request = Request(
        f"{endpoint_url.rstrip('/')}/_localstack/health",
        headers={"Accept": "application/json"},
        method="GET",
    )
    opener = build_opener(ProxyHandler({}), RejectRedirects())
    try:
        with opener.open(request, timeout=SOCKET_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        message = f"HTTP {error.code}: {error.reason}"
        error.close()
        sys.stdout.buffer.write(b"E" + message.encode(errors="replace"))
        return 0
    except (TimeoutError, OSError) as error:
        sys.stdout.buffer.write(b"E" + str(error).encode(errors="replace"))
        return 0

    sys.stdout.buffer.write(b"O" + body)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
