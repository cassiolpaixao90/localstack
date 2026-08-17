"use client";

import "@/lib/amplify";
import { Authenticator } from "@aws-amplify/ui-react";
import "@aws-amplify/ui-react/styles.css";
import { fetchAuthSession } from "aws-amplify/auth";
import { useState } from "react";
import { localstackConfig } from "@/lib/localstack-config";

function PrivateApiCall() {
  const [apiResult, setApiResult] = useState<string>("");

  async function callPrivateApi() {
    setApiResult("calling…");
    try {
      const session = await fetchAuthSession();
      const token = session.tokens?.idToken?.toString();
      if (!token) throw new Error("no ID token in session");
      const response = await fetch(`${localstackConfig.apiPrefix}/private/exercise-1`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setApiResult(`${response.status} ${await response.text()}`);
    } catch (error) {
      setApiResult(`call failed: ${String(error)}`);
    }
  }

  return (
    <>
      <button onClick={callPrivateApi}>GET /private/exercise-1</button>
      <pre style={{ whiteSpace: "pre-wrap" }}>{apiResult}</pre>
    </>
  );
}

export default function Home() {
  return (
    <main style={{ maxWidth: 480, margin: "4rem auto" }}>
      {/* hideSignUp: the pool is admin-only (self_sign_up_enabled=False) */}
      <Authenticator hideSignUp>
        {({ signOut, user }) => (
          <div style={{ fontFamily: "monospace" }}>
            <p>
              signed in as <code>{user?.signInDetails?.loginId}</code>
            </p>
            <PrivateApiCall />
            <button onClick={signOut}>Sign out</button>
          </div>
        )}
      </Authenticator>
    </main>
  );
}
