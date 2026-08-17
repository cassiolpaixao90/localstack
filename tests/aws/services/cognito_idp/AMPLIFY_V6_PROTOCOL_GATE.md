# Amplify v6 protocol gate

`test_amplify_v6_runtime.py` executes the `aws-amplify` 6.20.0 installation from the
Billgym mobile checkout without changing Billgym or installing dependencies. A
content-addressed Node 22.23.2 container mounts both checkouts read-only. The
test-owned `fetch` adapter rewrites only the canonical regional Cognito origin to
the configured loopback LocalStack endpoint and rejects every unknown origin.

The gate covers direct `USER_SRP_AUTH`, `NEW_PASSWORD_REQUIRED`, TOTP setup and
challenge, forced refresh, local revoke/sign-out, global sign-out, group and
`custom:tenantId` claims, and an Amplify REST call through an HTTP API Cognito JWT
authorizer to a Lambda proxy.

This is protocol evidence, not UI or native-runtime evidence. It does not execute
`@aws-amplify/ui-react-native`'s `Authenticator`, an Expo Web browser, an iOS
simulator/device, or an Android emulator/device. Expo Web browser E2E is the next
qualification layer. iOS and Android remain unqualified until the same flows run
on their real SDK/runtime surfaces.
