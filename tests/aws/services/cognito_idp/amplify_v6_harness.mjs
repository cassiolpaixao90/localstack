import { createHmac } from 'node:crypto';
import { readFile, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { isAbsolute, join, relative, resolve } from 'node:path';

const MAX_INPUT_BYTES = 32 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 5_000;
const EXPECTED_AMPLIFY_VERSION = '6.20.0';
const EXPECTED_NODE_VERSION = 'v22.23.2';
const COGNITO_HOST = /^cognito-idp\.([a-z]{2}(?:-[a-z0-9]+)+-[0-9])\.amazonaws\.com$/;

function fail(message) {
  throw new Error(message);
}

async function readInput() {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > MAX_INPUT_BYTES) fail('Amplify harness input exceeds its bound');
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const expectedKeys = new Set([
    'apiEndpoint',
    'billgymCheckout',
    'localstackEndpoint',
    'newPassword',
    'region',
    'temporaryPassword',
    'tenantId',
    'userPoolClientId',
    'userPoolId',
    'username',
  ]);
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    Object.keys(input).some(key => !expectedKeys.has(key)) ||
    Object.keys(input).length !== expectedKeys.size
  ) {
    fail('Amplify harness input does not match the closed contract');
  }
  for (const [key, value] of Object.entries(input)) {
    if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 2048) {
      fail(`Amplify harness input ${key} is invalid`);
    }
  }
  return input;
}

function validateLocalOrigin(value, name) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.port) {
    fail(`${name} must be an explicit bounded local origin`);
  }
  const local =
    url.hostname === '127.0.0.1' ||
    url.hostname === 'localhost' ||
    url.hostname.endsWith('.localhost.localstack.cloud');
  if (!local) fail(`${name} must not target external DNS`);
  return url;
}

function requestUrl(input) {
  if (typeof input === 'string' || input instanceof URL) return new URL(input);
  if (input && typeof input.url === 'string') return new URL(input.url);
  fail('Amplify issued an invalid fetch request');
}

function safeProtocolTrace(headers, body) {
  const target = headers.get('x-amz-target') ?? '';
  const trace = { target };
  if (typeof body !== 'string' || Buffer.byteLength(body) > MAX_INPUT_BYTES) return trace;
  try {
    const value = JSON.parse(body);
    if (typeof value.AuthFlow === 'string') trace.authFlow = value.AuthFlow;
    if (typeof value.ChallengeName === 'string') trace.challengeName = value.ChallengeName;
  } catch {
    // The request body remains opaque; secrets and SRP material are never recorded.
  }
  return trace;
}

function installLocalTransport({ apiEndpoint, localstackEndpoint, region }) {
  const nativeFetch = globalThis.fetch;
  if (typeof nativeFetch !== 'function') fail('Node fetch is unavailable');
  const localstack = validateLocalOrigin(localstackEndpoint, 'localstackEndpoint');
  const api = validateLocalOrigin(apiEndpoint, 'apiEndpoint');
  const trace = [];

  globalThis.fetch = async (input, init = {}) => {
    const original = requestUrl(input);
    const cognito = COGNITO_HOST.exec(original.hostname);
    const headers = new Headers(init.headers ?? input?.headers);
    let destination;
    let kind;
    if (cognito) {
      if (cognito[1] !== region || original.protocol !== 'https:' || original.pathname !== '/') {
        fail('Cognito request escaped the configured regional protocol contract');
      }
      destination = new URL(`${original.pathname}${original.search}`, localstack);
      headers.set('host', original.host);
      kind = 'cognito';
    } else if (original.origin === api.origin && original.pathname.startsWith(api.pathname)) {
      destination = original;
      kind = 'api';
    } else {
      fail(`Network egress denied for origin ${original.origin}`);
    }

    const record = {
      kind,
      originalOrigin: original.origin,
      rewritten: destination.origin !== original.origin,
      ...safeProtocolTrace(headers, init.body),
    };
    trace.push(record);
    const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
    const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    const response = await nativeFetch(destination, { ...init, headers, signal });
    record.status = response.status;
    return response;
  };
  return trace;
}

function decodeBase32(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const character of value.toUpperCase().replace(/=+$/u, '')) {
    const index = alphabet.indexOf(character);
    if (index < 0) fail('Amplify returned an invalid TOTP shared secret');
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(bytes);
}

function totp(secret, now = Date.now()) {
  const counter = BigInt(Math.floor(now / 30_000));
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  const digest = createHmac('sha1', decodeBase32(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, '0');
}

async function loadAmplify(checkout) {
  if (!isAbsolute(checkout)) fail('Billgym checkout must be absolute');
  const checkoutPath = await realpath(checkout);
  const mobileRoot = join(checkoutPath, 'apps', 'mobile');
  const mobilePackage = JSON.parse(await readFile(join(mobileRoot, 'package.json'), 'utf8'));
  if (mobilePackage.dependencies?.['aws-amplify'] !== '^6.20.0') {
    fail('Billgym mobile aws-amplify declaration changed');
  }
  const require = createRequire(join(mobileRoot, 'package.json'));
  const amplifyPackagePath = await realpath(require.resolve('aws-amplify/package.json'));
  if (relative(checkoutPath, amplifyPackagePath).startsWith('..')) {
    fail('Resolved Amplify package escaped the Billgym checkout');
  }
  const amplifyPackage = JSON.parse(await readFile(amplifyPackagePath, 'utf8'));
  if (amplifyPackage.version !== EXPECTED_AMPLIFY_VERSION) {
    fail('Resolved Billgym Amplify package version is not pinned to 6.20.0');
  }
  const [{ Amplify }, auth, api] = await Promise.all([
    import(require.resolve('aws-amplify')),
    import(require.resolve('aws-amplify/auth')),
    import(require.resolve('aws-amplify/api')),
  ]);
  return { Amplify, api, auth, version: amplifyPackage.version };
}

function assertStep(output, expected) {
  if (output?.isSignedIn !== false || output?.nextStep?.signInStep !== expected) {
    fail(`Amplify sign-in step mismatch: expected ${expected}`);
  }
}

function assertClaims(tokens, input) {
  const claims = tokens?.idToken?.payload;
  if (!claims || claims['custom:tenantId'] !== input.tenantId) {
    fail('Amplify ID token is missing the Billgym tenant claim');
  }
  const groups = claims['cognito:groups'];
  if (!Array.isArray(groups) || groups.length !== 1 || groups[0] !== 'trainer') {
    fail('Amplify ID token is missing the exact trainer group claim');
  }
  if (claims.aud !== input.userPoolClientId || claims.token_use !== 'id') {
    fail('Amplify ID token audience/token_use does not match BillgymAuth');
  }
  return { groups, tenantId: claims['custom:tenantId'], tokenUse: claims.token_use };
}

async function main() {
  if (process.version !== EXPECTED_NODE_VERSION) {
    fail(`Amplify harness requires ${EXPECTED_NODE_VERSION}, got ${process.version}`);
  }
  const input = await readInput();
  const trace = installLocalTransport(input);
  const { Amplify, api, auth, version } = await loadAmplify(resolve(input.billgymCheckout));
  Amplify.configure({
    Auth: {
      Cognito: {
        userPoolId: input.userPoolId,
        userPoolClientId: input.userPoolClientId,
        loginWith: { email: true },
      },
    },
    API: { REST: { billgym: { endpoint: input.apiEndpoint, region: input.region } } },
  });

  const started = await auth.signIn({
    username: input.username,
    password: input.temporaryPassword,
    options: { authFlowType: 'USER_SRP_AUTH' },
  });
  assertStep(started, 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED');
  const confirmed = await auth.confirmSignIn({ challengeResponse: input.newPassword });
  if (!confirmed.isSignedIn || confirmed.nextStep?.signInStep !== 'DONE') {
    fail('Amplify did not complete NEW_PASSWORD_REQUIRED');
  }

  const setup = await auth.setUpTOTP();
  await auth.verifyTOTPSetup({ code: totp(setup.sharedSecret, Date.now() - 30_000) });
  await auth.updateMFAPreference({ totp: 'PREFERRED' });
  const initialSession = await auth.fetchAuthSession();
  const claims = assertClaims(initialSession.tokens, input);
  await auth.fetchAuthSession({ forceRefresh: true });
  await auth.signOut();
  if ((await auth.fetchAuthSession()).tokens) fail('Amplify local sign-out retained tokens');

  const secondSignIn = await auth.signIn({
    username: input.username,
    password: input.newPassword,
    options: { authFlowType: 'USER_SRP_AUTH' },
  });
  assertStep(secondSignIn, 'CONFIRM_SIGN_IN_WITH_TOTP_CODE');
  const mfa = await auth.confirmSignIn({ challengeResponse: totp(setup.sharedSecret) });
  if (!mfa.isSignedIn || mfa.nextStep?.signInStep !== 'DONE') {
    fail('Amplify did not complete SOFTWARE_TOKEN_MFA');
  }
  const authenticated = await auth.fetchAuthSession();
  assertClaims(authenticated.tokens, input);
  const idToken = authenticated.tokens?.idToken?.toString();
  if (!idToken) fail('Amplify did not persist the ID token');
  const operation = api.get({
    apiName: 'billgym',
    path: '/v1/profile',
    options: { headers: { Authorization: `Bearer ${idToken}` } },
  });
  const response = await operation.response;
  const body = await response.body.json();
  if (response.statusCode !== 200 || body.tenantId !== input.tenantId || body.group !== 'trainer') {
    fail('Billgym-like JWT to Lambda response did not preserve claims');
  }
  await auth.signOut({ global: true });
  if ((await auth.fetchAuthSession()).tokens) fail('Amplify global sign-out retained tokens');

  const targets = trace.filter(item => item.kind === 'cognito').map(item => item.target);
  for (const expected of [
    'AWSCognitoIdentityProviderService.GetTokensFromRefreshToken',
    'AWSCognitoIdentityProviderService.RevokeToken',
    'AWSCognitoIdentityProviderService.GlobalSignOut',
  ]) {
    if (!targets.includes(expected)) fail(`Amplify did not issue ${expected}`);
  }
  if (trace.some(item => item.status < 200 || item.status >= 300)) {
    fail('Amplify transport observed a non-success response');
  }
  const result = {
    amplifyVersion: version,
    api: { group: body.group, path: body.path, tenantId: body.tenantId },
    claims,
    nodeVersion: process.version,
    trace,
  };
  const encoded = JSON.stringify(result);
  if (Buffer.byteLength(encoded) > MAX_RESPONSE_BYTES) fail('Amplify harness output exceeds its bound');
  process.stdout.write(encoded);
}

main().catch(error => {
  process.stderr.write(`${error?.name ?? 'Error'}: ${error?.message ?? 'unknown failure'}\n`);
  process.exitCode = 1;
});
