/*
 * Shared NIP-46 ("Nostr Connect" remote signer) helpers for /nostr-login
 * and /nostr-account. Wraps window.NostrConnectVendor (the vendored
 * nostr-tools bundle - see vendor/nostr-connect/) with the two connection
 * flows PLAN.md Phase 10 asks for:
 *   - pasting a bunker:// link (or a NIP-05 signer address)
 *   - scanning a nostrconnect:// QR code
 * plus saving/restoring the resulting session in localStorage so a
 * returning visitor doesn't have to reconnect every time.
 *
 * Every flow here produces a `BunkerSigner` with the same `.signEvent()`
 * shape NIP-07's `window.nostr.signEvent()` has - the pages that use this
 * treat both the same way past that point (PLAN.md: "NIP-07 and NIP-46
 * should ultimately feed the same verification pipeline").
 */
window.NostrConnectUI = (function () {
  "use strict";

  var STORAGE_KEY = "nostrAuthSavedSigner";
  // Well-known public relays that support NIP-46 traffic, used only for
  // the nostrconnect:// (QR) flow, where this page - not the user's
  // signer - has to pick where to listen. The bunker:// flow doesn't need
  // this: the relay is already in the pasted URI.
  var DEFAULT_QR_RELAYS = ["wss://relay.nsec.app", "wss://relay.damus.io"];
  var CONNECT_TIMEOUT_MS = 120000;

  function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  function hexToBytes(hex) {
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function loadSaved() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function save(clientSecretKey, bunkerPointer) {
    try {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ clientSecretKeyHex: bytesToHex(clientSecretKey), bunkerPointer: bunkerPointer })
      );
    } catch (e) {
      // Storage unavailable/full - not fatal, just no "reconnect" convenience next time.
    }
  }

  function clearSaved() {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (e) {
      // ignore
    }
  }

  function hasSaved() {
    return !!loadSaved();
  }

  async function connectViaBunkerUri(bunkerUriOrNip05) {
    var vendor = window.NostrConnectVendor;
    var bp = await vendor.parseBunkerInput(bunkerUriOrNip05);
    if (!bp) {
      throw new Error("That doesn't look like a valid bunker:// link or NIP-05 signer address.");
    }
    var clientSecretKey = vendor.generateSecretKey();
    var signer = vendor.BunkerSigner.fromBunker(clientSecretKey, bp);
    await signer.connect();
    save(clientSecretKey, bp);
    return signer;
  }

  async function connectViaQr(onUriReady, abortSignal) {
    var vendor = window.NostrConnectVendor;
    var clientSecretKey = vendor.generateSecretKey();
    var clientPubkey = vendor.getPublicKey(clientSecretKey);
    var secret = bytesToHex(vendor.generateSecretKey()).slice(0, 16);
    var uri = vendor.createNostrConnectURI({
      clientPubkey: clientPubkey,
      relays: DEFAULT_QR_RELAYS,
      secret: secret,
      name: document.title,
    });
    var qrDataUrl = await vendor.QRCode.toDataURL(uri, { width: 240, margin: 1 });
    onUriReady(uri, qrDataUrl);
    // fromURI accepts either a timeout in ms or an AbortSignal - pass
    // whichever the caller gave us so cancelling (e.g. a "Cancel" button)
    // actually closes the relay subscription immediately, rather than
    // leaving it running until CONNECT_TIMEOUT_MS anyway.
    var signer = await vendor.BunkerSigner.fromURI(
      clientSecretKey,
      uri,
      {},
      abortSignal || CONNECT_TIMEOUT_MS
    );
    save(clientSecretKey, signer.bp);
    return signer;
  }

  async function reconnectSaved() {
    var saved = loadSaved();
    if (!saved) return null;
    var vendor = window.NostrConnectVendor;
    var clientSecretKey = hexToBytes(saved.clientSecretKeyHex);
    var signer = vendor.BunkerSigner.fromBunker(clientSecretKey, saved.bunkerPointer);
    await signer.connect();
    return signer;
  }

  return {
    hasSaved: hasSaved,
    reconnectSaved: reconnectSaved,
    connectViaBunkerUri: connectViaBunkerUri,
    connectViaQr: connectViaQr,
    clearSaved: clearSaved,
  };
})();
