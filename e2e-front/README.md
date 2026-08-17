# e2e-front — Next.js + Amplify against the local LocalStack fork

Front end for the Cognito compatibility E2E: sign in with the official Amplify UI
(`<Authenticator>` from `@aws-amplify/ui-react`, `USER_SRP_AUTH`) against the
CDK-deployed user pool, then call the JWT-protected HTTP API (`GET /private/{id}`).

## Prerequisites

1. LocalStack fork running in host mode from the repo root:

   ```bash
   .venv/bin/python -m localstack.runtime.main
   ```

2. CDK stack deployed (real `cdk` CLI, writes `e2e-front/cdk-outputs.json`):

   ```bash
   .venv/bin/python scripts/e2e_cdk_deploy.py
   ```

3. Demo user (already created during the E2E run): `demo@example.test` /
   `EnterprisePass9!`, member of group `member`.

## Wiring

- `lib/localstack-config.ts` — generated from `cdk-outputs.json`:

  ```bash
  node scripts/gen-config.mjs
  ```

- `next.config.ts` — same-origin rewrites proxy `/ls-cognito/*` → LocalStack Cognito
  and `/ls-api/*` → the HTTP API (path-based invoke URL). The browser only talks to
  the dev server's own origin, so **CORS never applies and any dev port works** —
  no `EXTRA_CORS_ALLOWED_ORIGINS`, no DNS/TLS adapter.

- `lib/amplify.ts` — `Amplify.configure` with the deployed pool/client and
  `userPoolEndpoint` (supported since aws-amplify v6.20) pointed at the same-origin
  `/ls-cognito` prefix.

  If you ever pin an older Amplify without `userPoolEndpoint`, fall back to the
  test-owned transport adapter (`scripts/cognito-adapter.mjs` + `/etc/hosts` +
  mkcert) that rewrites the Cognito origin and denies all other egress:

  ```bash
  # one-time: echo "127.0.0.1 cognito-idp.us-east-1.amazonaws.com" | sudo tee -a /etc/hosts
  # one-time: mkcert cognito-idp.us-east-1.amazonaws.com
  ADAPTER_CERT=./cert.pem ADAPTER_KEY=./key.pem node scripts/cognito-adapter.mjs
  ```

## Run

```bash
npx next dev -p 3100   # http://localhost:3100 (3000 is used by another project here)
```

Sign in, then "GET /private/exercise-1" calls the HTTP API with the ID token.

## Caveats

- Through the `/ls-api` proxy the API call is same-origin, so the fixture's pinned
  CORS origin (`https://app.example.test`) no longer matters for the browser. The
  direct API path is also verified outside the browser (401 without token, 200 with
  a valid JWT through to the Lambda).
- LocalStack state is in-memory: after a restart, re-run
  `scripts/e2e_cdk_deploy.py`, `scripts/e2e_seed_demo_user.py`, and
  `node scripts/gen-config.mjs` (in `e2e-front`), then restart the dev server so
  `next.config.ts` picks up the new API id.
