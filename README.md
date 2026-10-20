# Licensebox for JavaScript and TypeScript

One Node.js SDK, written in TypeScript and shipped as JavaScript with type
declarations. Email sign-in, native machine-bound licences, silent renewal and
signed offline access for desktop and command-line applications. No runtime npm
dependencies; cryptography uses Node's built-in Ed25519 and ML-DSA-65. Protocol v3
signs every licence and request with both, and both must verify.

```sh
git clone https://github.com/licensebox/javascript.git
cd javascript
npm ci
npm pack
# Install the resulting .tgz in your application.
```

```typescript
import {Client, LicenseboxError} from '@licensebox/client';

const lic = new Client({
  product: 'myapp', keys: {'myapp-k1': 'YOUR_PUBLIC_VERIFICATION_KEY'}, version: '1.0',
});
try {
  await lic.require('export');
} catch (error) {
  if (error instanceof LicenseboxError) console.error(error.message);
  throw error;
}
// Read/process user files only after require succeeds.
```

Get product IDs, module names and public verification keys from the product
administrator. Never embed private signing keys or admin tokens. Keep one client
per process. `onSignIn(url, code)` displays/opens the sign-in instructions (stderr
by default). `directory` overrides the credential folder; `signal` supports
cancellation. `caBundle` can supply trusted TLS roots while retaining hostname verification. HTTPS is required, except HTTP on loopback for development.

All operations are asynchronous: `require(module)`, `lease()`, `status()` (local
only), `signIn(timeoutSeconds)`, `logout()`, `modules()`,
`requestAccess(['export'], 'why')`, `requests()`, `accessLink()`, and
`record('export', success, elapsedSeconds)`. Access links are private credentials.
Record only fixed command names, never filenames, arguments or user data.

`PolicyError.code` is `machine_changed`, `seat_transferred`, `location_denied` or
`location_unknown`; `ModuleError` means the module is missing. Other
`LicenseboxError.code` values include `offline`, `revoked`, `denied`,
`sign_in_expired`, `expired`, `identity_unavailable`. Refusals stop protected work
and persist across restarts/offline use. Explicit sign-in can transfer a seat.

## Runtime support

Node.js 24.6+ (the first with ML-DSA) on Linux is runtime-validated; older Node
throws `unsupported_runtime`. macOS native identity is implemented
but unvalidated. Windows currently requires a native SMBIOS `machineBinding`
adapter; absence fails closed. This provider seam is for trusted platform
integrations/testing, never an end-user-supplied identifier. Browser JavaScript,
browser WASM, Deno and Bun are not claimed as supported runtimes.

Raw native identifiers remain local. Machine recognition is not hardware
attestation: cloned/spoofed IDs or modified host software remain limitations.
Default offline access is 24 hours, refreshed silently per process. There is no
implicit background heartbeat. Payments and billing remain outside Licensebox.

See [protocol/conformance](https://github.com/licensebox/protocol),
[Node crypto documentation](https://nodejs.org/api/crypto.html)
and [Licensebox docs](https://licensebox.dev/docs). Administration stays in the
[Go CLI](https://github.com/licensebox/go).

MIT. Copyright © 2026 [Vijai Kumar](https://meshing.engineer).

## Optional monitoring

`await lic.heartbeat('export')` forces silent renewal with a three-second network
budget and returns `{lease, online}`. It never activates, transfers a seat or
creates a missing installation key. `online: false` is allowed only for an
eligible outage while the unchanged verified offline lease is valid. Explicit
refusals and removed module grants stop access immediately.

```typescript
// First sign in through the application's normal flow.
const monitor = await lic.watch('export', {signal: userCancellation.signal});
try {
  await runExport({signal: monitor.signal}); // your work honors this signal
} finally {
  monitor.stop();
}
const accessError = await monitor.done; // undefined for an explicit stop
if (accessError) showAccessError(accessError);
```

Monitoring starts only when requested. It uses the signed server interval, or
300 seconds for a legacy lease; `intervalSeconds` may request faster checks.
An independent monotonic expiry timer aborts `monitor.signal` at the last signed
deadline even while a renewal promise is pending. Offline checks cannot extend
that deadline. Explicit refusal and missing access also abort it. The SDK never
kills your application or deletes results: protected work must observe the
signal, and CPU-bound work must yield to the event loop or run in a worker.
`stop()` is idempotent, clears timers/listeners and aborts in-flight checks.
`latest` returns a copy of the last result; `done` resolves to the stop error
(or `undefined` for explicit stop). Optional `onStop(error)` notifications contain
thrown errors and rejected promises. Client construction and `require()` do not
schedule background checks.
