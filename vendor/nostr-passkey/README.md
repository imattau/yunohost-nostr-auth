# nostr-passkey vendor build

Produces `src/yunohost_nostr_auth/web/static/nostr-passkey-vendor.js`, a
self-hosted IIFE bundle of [`nostr-passkey`](https://github.com/imattau/nostr-passkey)
and its `nostr-tools` peer dependency.

The app serves the bundle from its own origin because the login and account
pages use a self-hosted script policy. The library is used only as a browser
signer: passkey PRF encrypts the stored identity locally, the key is unlocked
in memory, and the resulting `signEvent()` surface feeds the existing Nostr
challenge flow.

## Rebuilding

```bash
cd vendor/nostr-passkey
npm install
npm run build
npm test
```

The dependency versions are intentionally pinned in `package.json`. Rebuild
and run the bundle smoke test when updating them. The smoke test uses a mocked
WebAuthn PRF response to verify the real bundle's encryption, unlock, event
signing, signature verification, destruction, and clear operations; actual
hardware/browser compatibility still needs a live browser check. The generated
bundle is checked in; `node_modules` and npm lockfiles are ignored.
