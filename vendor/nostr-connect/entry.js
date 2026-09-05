import { generateSecretKey, getPublicKey, verifyEvent } from "nostr-tools/pure";
import { BunkerSigner, parseBunkerInput, createNostrConnectURI } from "nostr-tools/nip46";
import QRCode from "qrcode";

window.NostrConnectVendor = {
  generateSecretKey,
  getPublicKey,
  verifyEvent,
  BunkerSigner,
  parseBunkerInput,
  createNostrConnectURI,
  QRCode,
};
