import * as passkey from "nostr-passkey";

// Keep the browser surface explicit. The package's public exports are
// intentionally exposed under one app-owned global because these pages are
// self-hosted static HTML rather than an ESM application.
window.NostrPasskey = passkey;
