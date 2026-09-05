import { generateSecretKey, getPublicKey, verifyEvent, finalizeEvent } from "nostr-tools/pure";
import { BunkerSigner, parseBunkerInput, createNostrConnectURI } from "nostr-tools/nip46";
import { nsecEncode, npubEncode } from "nostr-tools/nip19";
import QRCode from "qrcode";

window.NostrConnectVendor = {
  generateSecretKey,
  getPublicKey,
  verifyEvent,
  finalizeEvent,
  nsecEncode,
  npubEncode,
  BunkerSigner,
  parseBunkerInput,
  createNostrConnectURI,
  QRCode,
};
