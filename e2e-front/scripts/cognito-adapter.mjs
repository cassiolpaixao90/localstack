// Test-owned transport adapter (per docs/cognito-compatibility-roadmap.md).
//
// Amplify v6 has no supported endpoint override for the direct User Pool client, so
// the browser must still dial https://cognito-idp.<region>.amazonaws.com. This
// adapter terminates TLS for that single origin on 127.0.0.1:443 and forwards to the
// local LocalStack gateway. Everything else is denied — no real AWS egress.
//
// Setup:
//   1. /etc/hosts:            127.0.0.1 cognito-idp.us-east-1.amazonaws.com
//   2. cert for that hostname (e.g. `mkcert cognito-idp.us-east-1.amazonaws.com`)
//   3. ADAPTER_CERT=./cert.pem ADAPTER_KEY=./key.pem node scripts/cognito-adapter.mjs
//      (port 443 needs sudo or `sudo setcap` on the node binary)
import { createServer } from "node:https";
import { request } from "node:http";
import { readFileSync } from "node:fs";

const ALLOWED_HOST = process.env.COGNITO_ORIGIN || "cognito-idp.us-east-1.amazonaws.com";
const UPSTREAM = { host: "localhost.localstack.cloud", port: 4566 };

const server = createServer(
  { cert: readFileSync(process.env.ADAPTER_CERT), key: readFileSync(process.env.ADAPTER_KEY) },
  (req, res) => {
    if ((req.headers.host || "").split(":")[0] !== ALLOWED_HOST) {
      res.writeHead(403).end("adapter denies non-Cognito egress");
      return;
    }
    const proxy = request(
      { ...UPSTREAM, path: req.url, method: req.method, headers: { ...req.headers, host: UPSTREAM.host } },
      (up) => {
        res.writeHead(up.statusCode, up.headers);
        up.pipe(res);
      },
    );
    proxy.on("error", (err) => res.writeHead(502).end(String(err)));
    req.pipe(proxy);
  },
);
server.listen(443, "127.0.0.1", () =>
  console.log(`cognito adapter: https://${ALLOWED_HOST} -> http://${UPSTREAM.host}:${UPSTREAM.port}`),
);
