# Licensebox for JavaScript and TypeScript

One Node.js SDK, written in TypeScript and shipped as JavaScript with type
declarations. Email sign-in, native machine-bound licences, silent renewal and
signed offline access for desktop and command-line applications. No runtime npm
dependencies; cryptography uses Node's built-in Ed25519 implementation.

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
cancellation. HTTPS is required, except HTTP on loopback for development.

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

Node.js 22+ on Linux is runtime-validated. macOS native identity is implemented
but unvalidated. Windows currently requires a native SMBIOS `machineBinding`
adapter; absence fails closed. This provider seam is for trusted platform
integrations/testing, never an end-user-supplied identifier. Browser JavaScript,
browser WASM, Deno and Bun are not claimed as supported runtimes.

Raw native identifiers remain local. Machine recognition is not hardware
attestation: cloned/spoofed IDs or modified host software remain limitations.
Default offline access is 24 hours, refreshed silently per process. There is no
background heartbeat. Payments and billing remain outside Licensebox.

See [protocol/conformance](https://github.com/licensebox/protocol),
[Node crypto documentation](https://nodejs.org/download/release/v22.18.0/docs/api/crypto.html)
and [Licensebox docs](https://licensebox.dev/docs). Administration stays in the
[Go CLI](https://github.com/licensebox/go).

MIT. Copyright © 2026 [Vijai Kumar](https://meshing.engineer).
