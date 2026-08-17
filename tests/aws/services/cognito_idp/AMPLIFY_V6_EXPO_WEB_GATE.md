# Amplify v6 Expo Web UI gate

`test_amplify_v6_expo_web.py` exports an isolated copy of Billgym's real Expo
mobile application and drives its real `@aws-amplify/ui-react-native`
`Authenticator` in Chrome for Testing. It does not replace Authenticator with a
test UI and it does not edit the Billgym checkout.

The qualified browser flow is `USER_SRP_AUTH` with a temporary password,
`NEW_PASSWORD_REQUIRED`, visual TOTP enrollment and confirmation, Billgym home
and JWT-protected HTTP API invocation, sign-out, permanent-password sign-in,
visual TOTP challenge, home, and final sign-out. The pool is switched from the
Billgym fixture's optional MFA setting to required software-token MFA inside the
test so both visual TOTP states are exercised.

The test uses the installed Billgym packages, an official Darwin arm64 Node
22.23.2 archive pinned by SHA-256, and Chrome for Testing 151.0.7922.77 pinned by
SHA-256. Chrome runs sandboxed with a fresh temporary profile. A test-owned CDP
adapter accepts only the regional Cognito JSON-RPC origin, `POST`/`OPTIONS`, the
observed Amplify request-header set, and the exact temporary app origin. It
forwards only to an explicit loopback LocalStack endpoint, does not follow
redirects, and Chrome DNS rules deny other destinations. Network and runtime
events are bounded and checked after the flow.

This is an Expo Web browser qualification. It is not evidence for Amplify Swift,
Amplify Android, iOS Simulator, Android Emulator, or physical devices. On the
current host Xcode 26.4.1 is present but `simctl` reports zero available iOS
devices and zero installed simulator runtimes. The Android command-line SDK has
platform/build tools and `adb`, but there is no connected device, emulator,
system image, Gradle executable, or cached Amplify Android artifact. The Billgym
checkout is Expo-managed and contains neither an Xcode project nor an Android
Gradle project.

The next native protocol gates are pinned to the current official releases
[Amplify Swift 2.60.1](https://github.com/aws-amplify/amplify-swift/releases/tag/2.60.1)
and [Amplify Android 2.39.0](https://github.com/aws-amplify/amplify-android/releases/tag/release_v2.39.0).
Their UI phases are pinned separately to
[Amplify UI Swift Authenticator 1.3.1](https://github.com/aws-amplify/amplify-ui-swift-authenticator/releases/tag/1.3.1)
and [Amplify UI Android Authenticator 1.10.0](https://github.com/aws-amplify/amplify-ui-android/releases/tag/release_authenticator_v1.10.0).
They must first exercise the real native Auth libraries against an isolated
LocalStack endpoint, then drive the native Authenticator UI through the same
password, new-password, TOTP enrollment/challenge, API, and sign-out states.
Native endpoint redirection must be owned by the test, deny AWS egress, and
preserve each SDK's wire protocol. No JavaScript wrapper may be counted as
Swift/Kotlin or simulator/device evidence. Installing the missing simulator
runtime, Android emulator/system image, Gradle toolchain, and native SDK
dependencies is outside this gate's no-new-dependencies authorization.
