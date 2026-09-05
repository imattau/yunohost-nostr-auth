# nostr-connect-vendor build recipe

Produces `src/yunohost_nostr_auth/web/static/nostr-connect-vendor.js`: a
single-file IIFE bundle of [`nostr-tools`](https://github.com/nbd-wtf/nostr-tools)'
NIP-46 client (`BunkerSigner`, `parseBunkerInput`, `createNostrConnectURI`)
plus [`qrcode`](https://github.com/soldair/node-qrcode) for rendering the
`nostrconnect://` connection URI as a scannable image.

## Why vendor instead of hand-rolling or loading from a CDN

- PLAN.md Phase 10 needs NIP-44 encryption and Nostr relay communication in
  the browser - real cryptography, not something to reimplement by hand.
  `nostr-tools` is the reference implementation the rest of the Nostr
  ecosystem already relies on for exactly this.
- `/nostr-login` and `/nostr-account`'s CSP is `script-src 'self'` (no
  external origins) - so the library has to be served from this app's own
  origin, not a CDN.

## Rebuilding

```bash
cd vendor/nostr-connect
npm install
npm run build
```

Bump the `nostr-tools`/`qrcode` versions in `package.json` deliberately
(security fixes, protocol updates) rather than tracking latest - rebuild
and re-run the verification below whenever they change.

## Verifying a rebuild

The build output is a minified blob; don't trust it on faith. Before
shipping a rebuilt bundle, confirm a real (unfaked) NIP-46 round trip still
works: a local NIP-01 relay, a small "fake remote signer" script using
`nostr-tools`' own primitives (`nip44` encrypt/decrypt, `finalizeEvent`) to
answer `connect`/`sign_event` requests, and a browser page loading the
*built* bundle to drive both the `bunker://` and `nostrconnect://` flows
against it - checking the signed event that comes back is genuinely
`verifyEvent()`-valid, not just that the promise resolved. This exact setup
(not shipped - it's throwaway verification tooling, not product code) is
what confirmed the current bundle before it was committed.
