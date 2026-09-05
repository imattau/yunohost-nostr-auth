(function () {
  "use strict";

  var app = document.getElementById("app");
  var button = document.getElementById("signin-btn");
  var reconnectBtn = document.getElementById("reconnect-btn");
  var localKeyBtn = document.getElementById("local-key-btn");
  var subtitle = document.getElementById("subtitle");
  var messageEl = document.getElementById("message");
  var bunkerInput = document.getElementById("bunker-input");
  var bunkerConnectBtn = document.getElementById("bunker-connect-btn");
  var qrShowBtn = document.getElementById("qr-show-btn");
  var qrBox = document.getElementById("qr-box");
  var qrImage = document.getElementById("qr-image");
  var qrUriText = document.getElementById("qr-uri-text");
  var qrCancelBtn = document.getElementById("qr-cancel-btn");

  var activeSigner = null;

  function showMessage(text, kind) {
    messageEl.textContent = text;
    messageEl.className = "message " + kind;
  }

  function clearMessage() {
    messageEl.textContent = "";
    messageEl.className = "message";
  }

  function setAllButtonsDisabled(disabled) {
    button.disabled = disabled;
    reconnectBtn.disabled = disabled;
    localKeyBtn.disabled = disabled;
    bunkerConnectBtn.disabled = disabled;
    bunkerInput.disabled = disabled;
    qrShowBtn.disabled = disabled;
  }

  async function fetchJSON(url, options) {
    var response = await fetch(url, options);
    var body = null;
    try {
      body = await response.json();
    } catch (e) {
      // Non-JSON response - fall through with body = null.
    }
    return { ok: response.ok, status: response.status, body: body };
  }

  // Shared by NIP-07 and every NIP-46 connection path: once we have a
  // signEvent(unsignedEvent) function - whichever kind of signer it came
  // from - the rest of the login flow is identical (PLAN.md: "NIP-07 and
  // NIP-46 should ultimately feed the same verification pipeline").
  async function performSignIn(signEventFn, busyLabel) {
    clearMessage();
    setAllButtonsDisabled(true);
    var originalText = button.textContent;
    button.textContent = busyLabel || "Waiting for signature…";

    try {
      var challengeResult = await fetchJSON("/challenge");
      if (!challengeResult.ok) {
        showMessage("Could not start sign-in - please try again.", "error");
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

      var authResult = await fetchJSON("/authenticate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: signedEvent })
      });

      if (authResult.ok) {
        window.location.href = "/yunohost/sso/";
        return;
      }

      var errorText =
        (authResult.body && authResult.body.error) ||
        "Sign-in failed. The challenge may have expired - try again.";
      showMessage(errorText, "error");
    } catch (networkError) {
      showMessage(
        "Could not reach the server. Check your connection and try again.",
        "error"
      );
    } finally {
      setAllButtonsDisabled(false);
      button.textContent = originalText;
      qrBox.hidden = true;
    }
  }

  function hasNip07() {
    return !!(window.nostr && typeof window.nostr.signEvent === "function");
  }

  // NIP-07 extensions (Alby, nos2x, ...) commonly inject window.nostr by
  // inserting a page-context <script> from their content script, which is
  // NOT guaranteed to finish before this tail-of-body script runs - a
  // single synchronous check here false-negatives intermittently,
  // especially on a cold page load. Poll briefly instead of deciding once.
  function waitForNip07(timeoutMs) {
    if (hasNip07()) {
      return Promise.resolve(true);
    }
    return new Promise(function (resolve) {
      var waited = 0;
      var intervalMs = 100;
      var timer = setInterval(function () {
        waited += intervalMs;
        if (hasNip07()) {
          clearInterval(timer);
          resolve(true);
        } else if (waited >= timeoutMs) {
          clearInterval(timer);
          resolve(false);
        }
      }, intervalMs);
    });
  }

  function signInWithNip07() {
    if (!hasNip07()) {
      showMessage(
        "No Nostr browser extension was found. Install one (e.g. Alby, nos2x), " +
          "use a remote signer below, or use your password on the normal login page.",
        "error"
      );
      return;
    }
    return performSignIn(function (event) {
      return window.nostr.signEvent(event);
    });
  }

  async function signInWithSigner(signer) {
    try {
      await performSignIn(function (event) {
        return signer.signEvent(event);
      });
    } finally {
      signer.close();
    }
  }

  // The click handler always re-checks for the extension itself (see
  // signInWithNip07), so the button is never disabled here - a slow-to-
  // inject extension (or one that appears after this poll gives up) can
  // still work on the next click. This poll only drives the informational
  // subtitle text.
  button.addEventListener("click", signInWithNip07);
  waitForNip07(3000).then(function (found) {
    if (!found) {
      subtitle.textContent =
        "No Nostr browser extension detected yet. Install one (e.g. Alby, nos2x) " +
        "and click Sign in again, use a remote signer below, or use your password " +
        "on the normal login page.";
    }
  });

  if (window.NostrConnectUI && window.NostrConnectUI.hasSaved()) {
    reconnectBtn.hidden = false;
    reconnectBtn.addEventListener("click", async function () {
      clearMessage();
      setAllButtonsDisabled(true);
      try {
        var signer = await window.NostrConnectUI.reconnectSaved();
        if (!signer) {
          showMessage("No saved signer found.", "error");
          return;
        }
        await signInWithSigner(signer);
      } catch (e) {
        showMessage("Could not reconnect to your saved signer. Try connecting again below.", "error");
        window.NostrConnectUI.clearSaved();
        reconnectBtn.hidden = true;
      } finally {
        setAllButtonsDisabled(false);
      }
    });
  }

  if (window.NostrConnectUI && window.NostrConnectUI.hasLocalKey()) {
    localKeyBtn.hidden = false;
    localKeyBtn.addEventListener("click", async function () {
      clearMessage();
      var signer = window.NostrConnectUI.loadLocalSigner();
      if (!signer) {
        showMessage("No saved key found.", "error");
        return;
      }
      await signInWithSigner(signer);
    });
  }

  bunkerConnectBtn.addEventListener("click", async function () {
    clearMessage();
    var value = bunkerInput.value.trim();
    if (!value) {
      showMessage("Paste a bunker:// link or NIP-05 signer address first.", "error");
      return;
    }
    setAllButtonsDisabled(true);
    bunkerConnectBtn.textContent = "Connecting…";
    try {
      var signer = await window.NostrConnectUI.connectViaBunkerUri(value);
      await signInWithSigner(signer);
    } catch (e) {
      showMessage(e.message || "Could not connect to that signer.", "error");
    } finally {
      setAllButtonsDisabled(false);
      bunkerConnectBtn.textContent = "Connect";
    }
  });

  var qrAbortController = null;

  qrShowBtn.addEventListener("click", async function () {
    clearMessage();
    qrAbortController = new AbortController();
    qrBox.hidden = false;
    qrShowBtn.disabled = true;
    button.disabled = true;
    bunkerConnectBtn.disabled = true;
    reconnectBtn.disabled = true;
    var wasAborted = false;
    try {
      var signer = await window.NostrConnectUI.connectViaQr(function (uri, dataUrl) {
        qrImage.src = dataUrl;
        qrUriText.textContent = uri;
      }, qrAbortController.signal);
      qrBox.hidden = true;
      await signInWithSigner(signer);
    } catch (e) {
      wasAborted = qrAbortController.signal.aborted;
      if (!wasAborted) {
        showMessage("The connection request timed out or was not approved.", "error");
      }
    } finally {
      qrBox.hidden = true;
      qrShowBtn.disabled = false;
      button.disabled = false;
      bunkerConnectBtn.disabled = false;
      reconnectBtn.disabled = window.NostrConnectUI && !window.NostrConnectUI.hasSaved();
      qrAbortController = null;
    }
  });

  qrCancelBtn.addEventListener("click", function () {
    if (qrAbortController) qrAbortController.abort();
    qrBox.hidden = true;
  });

  app.hidden = false;
})();
