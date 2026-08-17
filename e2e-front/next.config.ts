import { readFileSync } from "node:fs";
import type { NextConfig } from "next";

// Same-origin proxy to the local LocalStack gateway: the browser only ever talks to
// the Next dev server's own origin, so CORS never applies and any dev port works.
const outputs = JSON.parse(readFileSync(`${__dirname}/cdk-outputs.json`, "utf8"));
const stackOutputs = Object.values(outputs)[0] as { ApiId: string; StageName: string };
const gateway = "http://localhost.localstack.cloud:4566";

const nextConfig: NextConfig = {
  // The Amplify Cognito client POSTs to "/ls-cognito/" — don't 308 it away.
  skipTrailingSlashRedirect: true,
  async rewrites() {
    return [
      // Cognito IDP (Amplify userPoolEndpoint -> /ls-cognito); explicit root rule
      // avoids Next's 308 trailing-slash redirect on POST /ls-cognito/
      { source: "/ls-cognito/", destination: `${gateway}/` },
      { source: "/ls-cognito/:path*", destination: `${gateway}/:path*` },
      // HTTP API via LocalStack path-based invoke URL (avoids Host-header routing)
      {
        source: "/ls-api/:path*",
        destination: `${gateway}/_aws/execute-api/${stackOutputs.ApiId}/${stackOutputs.StageName}/:path*`,
      },
    ];
  },
};

export default nextConfig;
