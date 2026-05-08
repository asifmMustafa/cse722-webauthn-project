import { Router } from "express";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoUint8Array } from "@simplewebauthn/server/helpers";
import {
  createUser,
  findCredentialForUser,
  findUserByUsername,
  saveUser,
} from "../db/userStore.js";
import { config } from "../utils/config.js";
import {
  base64URLToUint8Array,
  uint8ArrayToBase64URL,
} from "../utils/encoding.js";
import { normalizeUsername } from "../utils/validators.js";

const authRouter = Router();

/**
 * Returns registration options for creating a passkey.
 *
 * @param {import("express").Request} req - Incoming HTTP request
 * @param {import("express").Response} res - Outgoing HTTP response
 * @returns {Promise<void>}
 */
const registerOptionsHandler = async (req, res) => {
  try {
    const { username, displayName } = req.body;

    if (!username || typeof username !== "string") {
      res.status(400).json({
        error: "Username is required",
      });
      return;
    }

    const cleanUsername = normalizeUsername(username);

    if (!cleanUsername) {
      res.status(400).json({
        error: "Username cannot be empty",
      });
      return;
    }

    const user = createUser(cleanUsername, displayName);

    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpId,
      userID: isoUint8Array.fromUTF8String(user.id),
      userName: user.username,
      userDisplayName: user.displayName,
      attestationType: "none",
      excludeCredentials: user.credentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports,
      })),
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      timeout: 60000,
    });

    req.session.currentRegistration = {
      username: user.username,
      challenge: options.challenge,
    };

    res.json(options);
  } catch (error) {
    console.error("Registration options error:", error);
    res.status(500).json({
      error: error.message || "Could not generate registration options",
    });
  }
};

/**
 * Verifies the registration response and stores the new authenticator.
 *
 * @param {import("express").Request} req - Incoming HTTP request
 * @param {import("express").Response} res - Outgoing HTTP response
 * @returns {Promise<void>}
 */
const registerVerifyHandler = async (req, res) => {
  try {
    const currentRegistration = req.session.currentRegistration;

    if (!currentRegistration) {
      res.status(400).json({
        verified: false,
        error: "No registration challenge found in session",
      });
      return;
    }

    const user = findUserByUsername(currentRegistration.username);

    if (!user) {
      res.status(400).json({
        verified: false,
        error: "User does not exist",
      });
      return;
    }

    let verification;

    try {
      verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: currentRegistration.challenge,
        expectedOrigin: config.expectedOrigins,
        expectedRPID: config.rpId,
        requireUserPresence: true,
        requireUserVerification: true,
      });
    } catch (error) {
      console.error("Registration verification failed:", error);
      res.status(400).json({
        verified: false,
        error: error.message,
      });
      return;
    }

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      res.status(400).json({
        verified: false,
        error: "Registration was not verified",
      });
      return;
    }

    const { credential, credentialDeviceType, credentialBackedUp } =
      registrationInfo;
    const existingCredential = findCredentialForUser(user, credential.id);

    if (!existingCredential) {
      user.credentials.push({
        id: credential.id,
        publicKey: uint8ArrayToBase64URL(credential.publicKey),
        counter: credential.counter,
        transports: credential.transports || req.body.response?.transports || [],
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        createdAt: new Date().toISOString(),
        lastUsedAt: null,
      });

      saveUser(user);
    }

    req.session.loggedInUser = user.username;
    req.session.lastAuthenticator = {
      credentialID: credential.id,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      counter: credential.counter,
    };

    delete req.session.currentRegistration;

    res.json({
      verified: true,
      username: user.username,
      authenticator: req.session.lastAuthenticator,
    });
  } catch (error) {
    console.error("Registration verify error:", error);
    res.status(500).json({
      verified: false,
      error: error.message || "Registration verification failed",
    });
  }
};

/**
 * Returns authentication options for an existing passkey user.
 *
 * @param {import("express").Request} req - Incoming HTTP request
 * @param {import("express").Response} res - Outgoing HTTP response
 * @returns {Promise<void>}
 */
const loginOptionsHandler = async (req, res) => {
  try {
    const { username } = req.body;

    if (!username || typeof username !== "string") {
      res.status(400).json({
        error: "Username is required",
      });
      return;
    }

    const cleanUsername = normalizeUsername(username);
    const user = findUserByUsername(cleanUsername);

    if (!user) {
      res.status(404).json({
        error: "User does not exist",
      });
      return;
    }

    if (!user.credentials.length) {
      res.status(400).json({
        error: "This user has no registered passkeys",
      });
      return;
    }

    const options = await generateAuthenticationOptions({
      rpID: config.rpId,
      allowCredentials: user.credentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports,
      })),
      userVerification: "required",
      timeout: 60000,
    });

    req.session.currentAuthentication = {
      username: user.username,
      challenge: options.challenge,
    };

    res.json(options);
  } catch (error) {
    console.error("Authentication options error:", error);
    res.status(500).json({
      error: error.message || "Could not generate authentication options",
    });
  }
};

/**
 * Verifies an authentication assertion and refreshes credential counter.
 *
 * @param {import("express").Request} req - Incoming HTTP request
 * @param {import("express").Response} res - Outgoing HTTP response
 * @returns {Promise<void>}
 */
const loginVerifyHandler = async (req, res) => {
  try {
    const currentAuthentication = req.session.currentAuthentication;

    if (!currentAuthentication) {
      res.status(400).json({
        verified: false,
        error: "No authentication challenge found in session",
      });
      return;
    }

    const user = findUserByUsername(currentAuthentication.username);

    if (!user) {
      res.status(400).json({
        verified: false,
        error: "User does not exist",
      });
      return;
    }

    const credential = findCredentialForUser(user, req.body.id);

    if (!credential) {
      res.status(400).json({
        verified: false,
        error: "Credential does not belong to this user",
      });
      return;
    }

    let verification;

    try {
      verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: currentAuthentication.challenge,
        expectedOrigin: config.expectedOrigins,
        expectedRPID: config.rpId,
        requireUserVerification: true,
        credential: {
          id: credential.id,
          publicKey: base64URLToUint8Array(credential.publicKey),
          counter: credential.counter,
          transports: credential.transports,
        },
      });
    } catch (error) {
      console.error("Authentication verification failed:", error);
      res.status(400).json({
        verified: false,
        error: error.message,
      });
      return;
    }

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      res.status(400).json({
        verified: false,
        error: "Authentication was not verified",
      });
      return;
    }

    credential.counter = authenticationInfo.newCounter;
    credential.lastUsedAt = new Date().toISOString();
    saveUser(user);

    req.session.loggedInUser = user.username;
    req.session.lastAuthenticator = {
      credentialID: credential.id,
      deviceType: credential.deviceType,
      backedUp: credential.backedUp,
      counter: credential.counter,
      transports: credential.transports,
      lastUsedAt: credential.lastUsedAt,
    };

    delete req.session.currentAuthentication;

    res.json({
      verified: true,
      username: user.username,
      authenticator: req.session.lastAuthenticator,
    });
  } catch (error) {
    console.error("Authentication verify error:", error);
    res.status(500).json({
      verified: false,
      error: error.message || "Authentication verification failed",
    });
  }
};

/**
 * Clears the current authenticated session state.
 *
 * @param {import("express").Request} req - Incoming HTTP request
 * @param {import("express").Response} res - Outgoing HTTP response
 * @returns {void}
 */
const logoutHandler = (req, res) => {
  req.session.destroy(() => {
    res.json({
      ok: true,
    });
  });
};

authRouter.post("/register/options", registerOptionsHandler);
authRouter.post("/register/verify", registerVerifyHandler);
authRouter.post("/login/options", loginOptionsHandler);
authRouter.post("/login/verify", loginVerifyHandler);
authRouter.post("/logout", logoutHandler);

export { authRouter };
