import fs from "node:fs";
import vm from "node:vm";
import { webcrypto } from "node:crypto";
import { verifyEvent } from "nostr-tools/pure";

const bundlePath = new URL(
  "../../src/yunohost_nostr_auth/web/static/nostr-passkey-vendor.js",
  import.meta.url,
);
const source = fs.readFileSync(bundlePath, "utf8");
const values = new Map();
const storage = {
  getItem(key) {
    return values.has(key) ? values.get(key) : null;
  },
  setItem(key, value) {
    values.set(key, value);
  },
  removeItem(key) {
    values.delete(key);
  },
};
const prfKey = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const credentialId = Uint8Array.from({ length: 16 }, (_, index) => index + 10);
const credential = {
  rawId: credentialId.buffer,
  getClientExtensionResults() {
    return { prf: { results: { first: prfKey.buffer } } };
  },
};

const context = {
  window: { PublicKeyCredential: function PublicKeyCredential() {} },
  navigator: {
    credentials: {
      async create() {
        return credential;
      },
      async get() {
        return credential;
      },
    },
  },
  location: { hostname: "example.org" },
  localStorage: storage,
  crypto: webcrypto,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  ArrayBuffer,
  DataView,
  btoa(value) {
    return Buffer.from(value, "binary").toString("base64");
  },
  atob(value) {
    return Buffer.from(value, "base64").toString("binary");
  },
  console,
};
context.globalThis = context;
try {
  vm.runInNewContext(source, context, { filename: "nostr-passkey-vendor.js" });
} catch (error) {
  console.error(`bundle load failed: ${error.name}: ${error.message}`);
  process.exit(1);
}

const api = context.window.NostrPasskey;
const identity = await api.registerPasskeyIdentity({
  rpName: "Smoke test",
  userName: "smoke-test",
});
if (!api.hasStoredPasskeyIdentity()) throw new Error("identity was not stored");

const signer = api.buildPasskeySignerShim(identity.secretKey);
const eventTemplate = vm.runInNewContext(
  `({ kind: 1, created_at: ${Math.floor(Date.now() / 1000)}, tags: [], content: "passkey smoke test" })`,
  context,
);
const signed = await signer.signEvent(eventTemplate);
if (!verifyEvent(JSON.parse(JSON.stringify(signed)))) {
  throw new Error("bundle signer produced an invalid event");
}
signer.destroy();
try {
  await signer.signEvent({ kind: 1, created_at: 0, tags: [], content: "nope" });
  throw new Error("destroyed signer still signed");
} catch (error) {
  if (!String(error.message).includes("destroyed")) throw error;
}

const unlocked = await api.unlockPasskeyIdentity();
if (unlocked.pubkey !== identity.pubkey) throw new Error("unlock returned a different identity");
api.clearPasskeyIdentity();
if (api.hasStoredPasskeyIdentity()) throw new Error("identity was not cleared");
console.log("nostr-passkey bundle smoke test passed");
