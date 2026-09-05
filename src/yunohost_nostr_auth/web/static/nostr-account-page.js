(function () {
  "use strict";

  var app = document.getElementById("app");
  var subtitle = document.getElementById("subtitle");
  var signedOut = document.getElementById("signed-out");
  var signedIn = document.getElementById("signed-in");
  var linkedInfo = document.getElementById("linked-info");
  var unlinkedNote = document.getElementById("unlinked-note");
  var npubValue = document.getElementById("npub-value");
  var nip05Value = document.getElementById("nip05-value");
  var createdValue = document.getElementById("created-value");
  var lastUsedValue = document.getElementById("last-used-value");
  var linkBtn = document.getElementById("link-btn");
  var unlinkBtn = document.getElementById("unlink-btn");
  var goLoginBtn = document.getElementById("go-login-btn");
  var messageEl = document.getElementById("message");
  var bunkerInput = document.getElementById("bunker-input");
  var bunkerConnectBtn = document.getElementById("bunker-connect-btn");
  var qrShowBtn = document.getElementById("qr-show-btn");
  var qrBox = document.getElementById("qr-box");
  var qrImage = document.getElementById("qr-image");
  var qrUriText = document.getElementById("qr-uri-text");
  var qrCancelBtn = document.getElementById("qr-cancel-btn");
  var generateBtn = document.getElementById("generate-btn");
  var generatedKeyBox = document.getElementById("generated-key-box");
  var generatedNpub = document.getElementById("generated-npub");
  var generatedNsec = document.getElementById("generated-nsec");
  var revealNsecBtn = document.getElementById("reveal-nsec-btn");
  var copyNsecBtn = document.getElementById("copy-nsec-btn");
  var rememberKeyCheckbox = document.getElementById("remember-key-checkbox");
  var useGeneratedKeyBtn = document.getElementById("use-generated-key-btn");
  var savedSignersPanel = document.getElementById("saved-signers-panel");
  var savedBunkerRow = document.getElementById("saved-bunker-row");
  var savedBunkerRelay = document.getElementById("saved-bunker-relay");
  var savedLocalKeyRow = document.getElementById("saved-local-key-row");
  var forgetBunkerBtn = document.getElementById("forget-bunker-btn");
  var forgetLocalKeyBtn = document.getElementById("forget-local-key-btn");

  var NSEC_MASK = "•".repeat(63);
  var generatedKeypair = null;
  var nsecRevealed = false;

  function showMessage(text, kind) {
    messageEl.textContent = text;
    messageEl.className = "message " + kind;
  }

  function clearMessage() {
    messageEl.textContent = "";
    messageEl.className = "message";
  }

  function formatTimestamp(unixSeconds) {
    if (!unixSeconds) return "never";
    return new Date(unixSeconds * 1000).toLocaleString();
  }

  async function fetchJSON(url, options) {
    var response = await fetch(url, Object.assign({ credentials: "same-origin" }, options || {}));
    var body = null;
    try {
      body = await response.json();
    } catch (e) {
      // Non-JSON response - fall through with body = null.
    }
    return { ok: response.ok, status: response.status, body: body };
  }

  function renderSavedSigners() {
    var bunkerInfo = window.NostrConnectUI.getSavedInfo();
    var hasLocal = window.NostrConnectUI.hasLocalKey();
    savedSignersPanel.hidden = !bunkerInfo && !hasLocal;
    savedBunkerRow.hidden = !bunkerInfo;
    if (bunkerInfo) {
      savedBunkerRelay.textContent = bunkerInfo.relays.join(", ");
    }
    savedLocalKeyRow.hidden = !hasLocal;
  }

  function renderIdentity(identity) {
    signedOut.hidden = true;
    signedIn.hidden = false;

    if (identity.linked) {
      subtitle.textContent = "Your account has a linked Nostr identity.";
      linkedInfo.hidden = false;
      unlinkedNote.hidden = true;
      npubValue.textContent = identity.npub;
      nip05Value.textContent = identity.username + "@" + window.location.hostname;
      createdValue.textContent = formatTimestamp(identity.created_at);
      lastUsedValue.textContent = formatTimestamp(identity.last_used);
      linkBtn.textContent = "Replace identity";
      unlinkBtn.hidden = false;
    } else {
      subtitle.textContent = "Link a Nostr identity to sign in without your password.";
      linkedInfo.hidden = true;
      unlinkedNote.hidden = false;
      linkBtn.textContent = "Link identity";
      unlinkBtn.hidden = true;
    }
  }

  async function loadIdentity() {
    var result = await fetchJSON("/identity");
    if (result.status === 401) {
      subtitle.textContent = "";
      signedOut.hidden = false;
      signedIn.hidden = true;
      return;
    }
    if (!result.ok) {
      showMessage("Could not load your identity status - please reload the page.", "error");
      return;
    }
    renderIdentity(result.body);
    renderSavedSigners();
  }

  function setLinkButtonsDisabled(disabled) {
    linkBtn.disabled = disabled;
    bunkerConnectBtn.disabled = disabled;
    bunkerInput.disabled = disabled;
    qrShowBtn.disabled = disabled;
    generateBtn.disabled = disabled;
    useGeneratedKeyBtn.disabled = disabled;
  }

  // Shared by NIP-07 and every NIP-46/local-key connection path: once we
  // have a signEvent(unsignedEvent) function, the rest of the linking flow
  // is identical (PLAN.md: "NIP-07 and NIP-46 should ultimately feed the
  // same verification pipeline" - a locally-generated key is just another
  // kind of signer by the same logic).
  async function performLink(signEventFn) {
    clearMessage();
    setLinkButtonsDisabled(true);

    try {
      var challengeResult = await fetchJSON("/link/challenge", { method: "POST" });
      if (!challengeResult.ok) {
        showMessage("Could not start linking - please try again.", "error");
        return;
      }
      var challenge = challengeResult.body;

      var unsignedEvent = {
        kind: challenge.kind,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ["challenge", challenge.nonce],
          ["domain", challenge.domain],
          ["action", challenge.action]
        ],
        content: ""
      };

      var signedEvent;
      try {
        signedEvent = await signEventFn(unsignedEvent);
      } catch (signError) {
        showMessage(
          "Signature request was rejected, or your signer is unavailable.",
          "error"
        );
        return;
      }

      var linkResult = await fetchJSON("/link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: signedEvent })
      });

      if (linkResult.ok) {
        showMessage("Identity linked.", "success");
        generatedKeyBox.hidden = true;
        generatedKeypair = null;
        await loadIdentity();
        return;
      }

      var errorText = (linkResult.body && linkResult.body.error) || "Linking failed - please try again.";
      showMessage(errorText, "error");
    } catch (networkError) {
      showMessage("Could not reach the server. Check your connection and try again.", "error");
    } finally {
      setLinkButtonsDisabled(false);
      qrBox.hidden = true;
    }
  }

  function linkWithNip07() {
    if (!window.nostr || typeof window.nostr.signEvent !== "function") {
      showMessage(
        "No Nostr browser extension was found. Install one (e.g. Alby, nos2x), or use a remote signer below.",
        "error"
      );
      return;
    }
    return performLink(function (event) {
      return window.nostr.signEvent(event);
    });
  }

  async function linkWithSigner(signer) {
    try {
      await performLink(function (event) {
        return signer.signEvent(event);
      });
    } finally {
      signer.close();
      renderSavedSigners();
    }
  }

  async function unlinkIdentity() {
    clearMessage();
    if (!window.confirm("Unlink your Nostr identity? You can link a new one anytime.")) {
      return;
    }

    unlinkBtn.disabled = true;
    try {
      var result = await fetchJSON("/unlink", { method: "POST" });
      if (result.ok) {
        // A saved signer (NIP-46 or a locally-generated key) represents a
        // way to sign in/link as the identity we just unlinked - leaving
        // it behind would let "reconnect" on /nostr-login silently target
        // an account that no longer has this pubkey linked.
        window.NostrConnectUI.clearAllSaved();
        renderSavedSigners();
        showMessage("Identity unlinked.", "success");
        await loadIdentity();
        return;
      }
      var errorText = (result.body && result.body.error) || "Unlinking failed - please try again.";
      showMessage(errorText, "error");
    } catch (networkError) {
      showMessage("Could not reach the server. Check your connection and try again.", "error");
    } finally {
      unlinkBtn.disabled = false;
    }
  }

  linkBtn.addEventListener("click", linkWithNip07);
  unlinkBtn.addEventListener("click", unlinkIdentity);
  goLoginBtn.addEventListener("click", function () {
    window.location.href = "/yunohost/sso/";
  });

  bunkerConnectBtn.addEventListener("click", async function () {
    clearMessage();
    var value = bunkerInput.value.trim();
    if (!value) {
      showMessage("Paste a bunker:// link or NIP-05 signer address first.", "error");
      return;
    }
    setLinkButtonsDisabled(true);
    bunkerConnectBtn.textContent = "Connecting…";
    try {
      var signer = await window.NostrConnectUI.connectViaBunkerUri(value);
      await linkWithSigner(signer);
    } catch (e) {
      showMessage(e.message || "Could not connect to that signer.", "error");
    } finally {
      setLinkButtonsDisabled(false);
      bunkerConnectBtn.textContent = "Connect";
    }
  });

  var qrAbortController = null;

  qrShowBtn.addEventListener("click", async function () {
    clearMessage();
    qrAbortController = new AbortController();
    qrBox.hidden = false;
    setLinkButtonsDisabled(true);
    try {
      var signer = await window.NostrConnectUI.connectViaQr(function (uri, dataUrl) {
        qrImage.src = dataUrl;
        qrUriText.textContent = uri;
      }, qrAbortController.signal);
      qrBox.hidden = true;
      await linkWithSigner(signer);
    } catch (e) {
      if (!qrAbortController.signal.aborted) {
        showMessage("The connection request timed out or was not approved.", "error");
      }
    } finally {
      qrBox.hidden = true;
      setLinkButtonsDisabled(false);
      qrAbortController = null;
    }
  });

  qrCancelBtn.addEventListener("click", function () {
    if (qrAbortController) qrAbortController.abort();
    qrBox.hidden = true;
  });

  generateBtn.addEventListener("click", function () {
    clearMessage();
    generatedKeypair = window.NostrConnectUI.generateLocalKeypair();
    nsecRevealed = false;
    generatedNpub.textContent = generatedKeypair.npub;
    generatedNsec.textContent = NSEC_MASK;
    revealNsecBtn.textContent = "Reveal";
    rememberKeyCheckbox.checked = false;
    generatedKeyBox.hidden = false;
  });

  revealNsecBtn.addEventListener("click", function () {
    if (!generatedKeypair) return;
    nsecRevealed = !nsecRevealed;
    generatedNsec.textContent = nsecRevealed ? generatedKeypair.nsec : NSEC_MASK;
    revealNsecBtn.textContent = nsecRevealed ? "Hide" : "Reveal";
  });

  generatedNsec.addEventListener("click", function () {
    revealNsecBtn.click();
  });

  copyNsecBtn.addEventListener("click", async function () {
    if (!generatedKeypair) return;
    try {
      await navigator.clipboard.writeText(generatedKeypair.nsec);
      showMessage("Private key copied to clipboard.", "success");
    } catch (e) {
      showMessage("Could not copy automatically - click Reveal and copy it manually.", "error");
    }
  });

  useGeneratedKeyBtn.addEventListener("click", async function () {
    if (!generatedKeypair) return;
    if (rememberKeyCheckbox.checked) {
      window.NostrConnectUI.saveLocalKey(generatedKeypair.secretKeyHex);
    }
    var signer = window.NostrConnectUI.createLocalSigner(generatedKeypair.secretKeyHex);
    await linkWithSigner(signer);
  });

  forgetBunkerBtn.addEventListener("click", function () {
    window.NostrConnectUI.clearSaved();
    renderSavedSigners();
  });

  forgetLocalKeyBtn.addEventListener("click", function () {
    window.NostrConnectUI.clearLocalKey();
    renderSavedSigners();
  });

  loadIdentity().finally(function () {
    app.hidden = false;
  });
})();
