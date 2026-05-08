const { startRegistration, startAuthentication, browserSupportsWebAuthn } =
  SimpleWebAuthnBrowser;

const usernameInput = document.getElementById("username");
const displayNameInput = document.getElementById("displayName");
const output = document.getElementById("output");
const configOutput = document.getElementById("configOutput");

const registerBtn = document.getElementById("registerBtn");
const loginBtn = document.getElementById("loginBtn");
const tamperBtn = document.getElementById("tamperBtn");

function show(value) {
  if (typeof value === "string") {
    output.textContent = value;
  } else {
    output.textContent = JSON.stringify(value, null, 2);
  }
}

function getUsername() {
  return usernameInput.value.trim().toLowerCase();
}

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || JSON.stringify(data));
  }

  return data;
}

async function loadConfig() {
  const response = await fetch("/api/config");
  const config = await response.json();
  configOutput.textContent = JSON.stringify(config, null, 2);
}

function base64URLToString(base64url) {
  const base64 = base64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(base64url.length / 4) * 4, "=");

  return atob(base64);
}

function stringToBase64URL(value) {
  const base64 = btoa(value);

  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function registerPasskey() {
  try {
    if (!browserSupportsWebAuthn()) {
      show("This browser does not support WebAuthn.");
      return;
    }

    const username = getUsername();
    const displayName = displayNameInput.value.trim();

    if (!username) {
      show("Please enter a username.");
      return;
    }

    show("Requesting registration options from server...");

    const optionsJSON = await postJSON("/api/register/options", {
      username,
      displayName,
    });

    show("Calling authenticator. Follow your browser/device prompt...");

    const registrationResponse = await startRegistration({
      optionsJSON,
    });

    show("Sending attestation response to server for verification...");

    const verification = await postJSON(
      "/api/register/verify",
      registrationResponse,
    );

    show(verification);

    if (verification.verified) {
      window.location.href = "/protected.html";
    }
  } catch (error) {
    console.error(error);
    show(`Registration failed:\n${error.message}`);
  }
}

async function loginWithPasskey() {
  try {
    if (!browserSupportsWebAuthn()) {
      show("This browser does not support WebAuthn.");
      return;
    }

    const username = getUsername();

    if (!username) {
      show("Please enter a username.");
      return;
    }

    show("Requesting authentication options from server...");

    const optionsJSON = await postJSON("/api/login/options", {
      username,
    });

    show("Calling authenticator. Follow your browser/device prompt...");

    const authenticationResponse = await startAuthentication({
      optionsJSON,
    });

    show("Sending assertion response to server for verification...");

    const verification = await postJSON(
      "/api/login/verify",
      authenticationResponse,
    );

    show(verification);

    if (verification.verified) {
      window.location.href = "/protected.html";
    }
  } catch (error) {
    console.error(error);
    show(`Login failed:\n${error.message}`);
  }
}

async function tamperLoginResponse() {
  try {
    const username = getUsername();

    if (!username) {
      show("Please enter a username first.");
      return;
    }

    show("Starting normal login first...");

    const optionsJSON = await postJSON("/api/login/options", {
      username,
    });

    const authenticationResponse = await startAuthentication({
      optionsJSON,
    });

    show("Tampering with clientDataJSON before sending to server...");

    const clientDataJSONString = base64URLToString(
      authenticationResponse.response.clientDataJSON,
    );

    const clientData = JSON.parse(clientDataJSONString);

    // This changes the challenge after the authenticator already signed data.
    // The server should reject this response.
    clientData.challenge = "tampered-challenge-value";

    authenticationResponse.response.clientDataJSON = stringToBase64URL(
      JSON.stringify(clientData),
    );

    const verification = await postJSON(
      "/api/login/verify",
      authenticationResponse,
    );

    show({
      warning: "Unexpected success. This should not happen.",
      verification,
    });
  } catch (error) {
    console.error(error);

    show({
      negativeTestResult: "Server correctly rejected the tampered response",
      error: error.message,
    });
  }
}

registerBtn.addEventListener("click", registerPasskey);
loginBtn.addEventListener("click", loginWithPasskey);
tamperBtn.addEventListener("click", tamperLoginResponse);

loadConfig();
