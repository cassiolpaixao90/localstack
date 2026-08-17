import Amplify
import AWSAPIPlugin
import AWSCognitoAuthPlugin
import AWSPluginsCore
import CryptoKit
import Foundation
import Security

private struct Input: Decodable {
    let apiEndpoint: String
    let configurationFile: String
    let newPassword: String
    let tenantId: String
    let userPoolClientId: String
    let username: String
    let temporaryPassword: String
}

private struct Evidence: Encodable {
    let apiStatus: String
    let globalSignOut: Bool
    let groups: [String]
    let keychainItemsAfterSignOut: Int
    let newPassword: Bool
    let refresh: Bool
    let sdk: String
    let tenantId: String
    let totp: Bool
}

private enum GateError: Error, CustomStringConvertible {
    case failed(String)

    var description: String {
        switch self {
        case .failed(let message): message
        }
    }
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else { throw GateError.failed(message) }
}

private func base32(_ value: String) throws -> Data {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var accumulator = 0
    var bits = 0
    var output = Data()
    for scalar in value.uppercased() where scalar != "=" {
        guard let index = alphabet.firstIndex(of: scalar) else {
            throw GateError.failed("invalid TOTP secret")
        }
        accumulator = (accumulator << 5) | index
        bits += 5
        if bits >= 8 {
            bits -= 8
            output.append(UInt8((accumulator >> bits) & 0xff))
        }
    }
    return output
}

private func totp(_ secret: String, at date: Date = Date()) throws -> String {
    var counter = UInt64(floor(date.timeIntervalSince1970 / 30)).bigEndian
    let message = Data(bytes: &counter, count: MemoryLayout<UInt64>.size)
    let key = SymmetricKey(data: try base32(secret))
    let digest = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
    let offset = Int(digest.last! & 0x0f)
    let number = digest[offset ..< offset + 4].reduce(0) { ($0 << 8) | UInt32($1) }
    return String(format: "%06d", (number & 0x7fff_ffff) % 1_000_000)
}

private func claims(_ token: String) throws -> [String: Any] {
    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    try require(parts.count == 3, "invalid JWT shape")
    var encoded = String(parts[1]).replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
    guard
        let data = Data(base64Encoded: encoded),
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { throw GateError.failed("invalid JWT payload") }
    return object
}

private func tokens(forceRefresh: Bool = false) async throws -> AuthCognitoTokens {
    let session = try await Amplify.Auth.fetchAuthSession(
        options: .init(forceRefresh: forceRefresh)
    )
    guard let provider = session as? AuthCognitoTokensProvider else {
        throw GateError.failed("Amplify session is not a Cognito token provider")
    }
    return try provider.getCognitoTokens().get()
}

private func keychainItemCount() throws -> Int {
    let query: [String: Any] = [
        String(kSecClass): kSecClassGenericPassword,
        String(kSecMatchLimit): kSecMatchLimitAll,
        String(kSecReturnAttributes): true,
        String(kSecUseDataProtectionKeychain): true,
    ]
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return 0 }
    try require(status == errSecSuccess, "unable to inventory the isolated keychain")
    return (result as? [[String: Any]])?.count ?? 0
}

@main
private enum Main {
    static func main() async {
        do {
            let inputData = FileHandle.standardInput.readDataToEndOfFile()
            try require(inputData.count <= 32 * 1024, "input exceeds bound")
            let input = try JSONDecoder().decode(Input.self, from: inputData)
            try require(input.configurationFile.hasPrefix("/"), "configuration path must be absolute")
            let endpoint = try XCTUnwrap(URL(string: input.apiEndpoint))
            try require(endpoint.host?.hasSuffix(".localhost.localstack.cloud") == true, "API endpoint is not local")
            try require(endpoint.port != nil, "API endpoint must include a port")

            let authPlugin = AWSCognitoAuthPlugin()
            try Amplify.add(plugin: authPlugin)
            try Amplify.add(plugin: AWSAPIPlugin())
            let configuration = try AmplifyConfiguration(
                configurationFile: URL(fileURLWithPath: input.configurationFile)
            )
            try Amplify.configure(configuration)

            let started = try await Amplify.Auth.signIn(
                username: input.username,
                password: input.temporaryPassword
            )
            guard case .confirmSignInWithNewPassword = started.nextStep else {
                throw GateError.failed("expected NEW_PASSWORD_REQUIRED")
            }
            let confirmed = try await Amplify.Auth.confirmSignIn(
                challengeResponse: input.newPassword
            )
            try require(confirmed.isSignedIn, "new password confirmation did not sign in")

            let details = try await Amplify.Auth.setUpTOTP()
            try await Amplify.Auth.verifyTOTPSetup(code: try totp(details.sharedSecret))
            try await authPlugin.updateMFAPreference(totp: .preferred)

            let initial = try await tokens()
            let initialClaims = try claims(initial.idToken)
            try require(initialClaims["aud"] as? String == input.userPoolClientId, "ID token audience mismatch")
            try require(initialClaims["custom:tenantId"] as? String == input.tenantId, "tenant claim mismatch")
            let groups = initialClaims["cognito:groups"] as? [String] ?? []
            try require(groups == ["trainer"], "group claim mismatch")

            let refreshed = try await tokens(forceRefresh: true)
            try require(refreshed.accessToken != initial.accessToken, "force refresh reused access token")
            let request = RESTRequest(
                apiName: "billgym",
                path: "/v1/profile",
                headers: ["Authorization": "Bearer \(refreshed.idToken)"]
            )
            let response = try await Amplify.API.get(request: request)
            let api = try JSONSerialization.jsonObject(with: response) as? [String: Any]
            guard let apiStatus = api?["status"] as? String else {
                throw GateError.failed("HTTP API response omitted status")
            }
            try require(apiStatus == "ok", "HTTP API response mismatch")

            let firstSignOut = await Amplify.Auth.signOut(options: .init(globalSignOut: true))
            guard
                let cognitoSignOut = firstSignOut as? AWSCognitoSignOutResult,
                case .complete = cognitoSignOut
            else { throw GateError.failed("Amplify global sign-out was not complete") }
            let signedOut = try await Amplify.Auth.fetchAuthSession()
            try require(!signedOut.isSignedIn, "global sign-out retained local session")

            let second = try await Amplify.Auth.signIn(
                username: input.username,
                password: input.newPassword
            )
            guard case .confirmSignInWithTOTPCode = second.nextStep else {
                throw GateError.failed("expected SOFTWARE_TOKEN_MFA")
            }
            let mfa = try await Amplify.Auth.confirmSignIn(
                challengeResponse: try totp(details.sharedSecret)
            )
            try require(mfa.isSignedIn, "TOTP challenge did not sign in")
            let secondSignOut = await Amplify.Auth.signOut(options: .init(globalSignOut: true))
            guard
                let cognitoSignOut = secondSignOut as? AWSCognitoSignOutResult,
                case .complete = cognitoSignOut
            else { throw GateError.failed("second Amplify global sign-out was not complete") }
            let finalSession = try await Amplify.Auth.fetchAuthSession()
            try require(!finalSession.isSignedIn, "second global sign-out retained local session")
            let keychainItemsAfterSignOut = try keychainItemCount()
            try require(keychainItemsAfterSignOut == 0, "Amplify left items in the isolated keychain")

            let evidence = Evidence(
                apiStatus: apiStatus,
                globalSignOut: true,
                groups: groups,
                keychainItemsAfterSignOut: keychainItemsAfterSignOut,
                newPassword: true,
                refresh: true,
                sdk: "Amplify Swift 2.60.1",
                tenantId: input.tenantId,
                totp: true
            )
            FileHandle.standardOutput.write(try JSONEncoder().encode(evidence))
        } catch {
            FileHandle.standardError.write(Data("Amplify Swift gate failed: \(error)\n".utf8))
            exit(1)
        }
    }
}

private func XCTUnwrap<T>(_ value: T?) throws -> T {
    guard let value else { throw GateError.failed("required value is absent") }
    return value
}
