import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import crypto from "node:crypto";
import express from "express";
import session from "express-session";
import helmet from "helmet";
import dotenv from "dotenv";
import { fileURLToPath } from "node:url";

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

import { isoUint8Array } from "@simplewebauthn/server/helpers";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8443);
const RP_NAME = process.env.RP_NAME || "CSE722 WebAuthn Demo";
const RP_ID = process.env.RP_ID || "localhost";
const ORIGIN = process.env.ORIGIN || `https://${RP_ID}:${PORT}`;
const EXPECTED_ORIGINS = ORIGIN.split(",").map((origin) => origin.trim());
const USE_HTTPS = process.env.USE_HTTPS !== "false";

const DB_FILE = path.join(__dirname, "db.json");

const app = express();

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
  }),
);

app.use(express.json({ limit: "1mb" }));

app.use(
  session({
    secret:
      process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: EXPECTED_ORIGINS[0].startsWith("https://") ? "auto" : false,
      maxAge: 1000 * 60 * 60,
    },
  }),
);

app.use(express.static(path.join(__dirname, "public")));

/**
 * -------------------------
 * Simple JSON database layer
 * -------------------------
 */

function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    return { users: [] };
  }

  const raw = fs.readFileSync(DB_FILE, "utf8");

  if (!raw.trim()) {
    return { users: [] };
  }

  return JSON.parse(raw);
}

function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function findUserByUsername(username) {
  const db = readDB();
  return db.users.find((user) => user.username === username);
}

function createUser(username, displayName) {
  const db = readDB();

  const existingUser = db.users.find((user) => user.username === username);
  if (existingUser) {
    return existingUser;
  }

  const user = {
    id: crypto.randomUUID(),
    username,
    displayName: displayName || username,
    credentials: [],
  };

  db.users.push(user);
  writeDB(db);

  return user;
}

function saveUser(updatedUser) {
  const db = readDB();
  const index = db.users.findIndex((user) => user.id === updatedUser.id);

  if (index === -1) {
    db.users.push(updatedUser);
  } else {
    db.users[index] = updatedUser;
  }

  writeDB(db);
}

function findCredentialForUser(user, credentialID) {
  return user.credentials.find((credential) => credential.id === credentialID);
}

function uint8ArrayToBase64URL(value) {
  return Buffer.from(value).toString("base64url");
}

function base64URLToUint8Array(value) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function requireLoggedIn(req, res, next) {
  if (!req.session.loggedInUser) {
    return res.status(401).json({
      error: "You are not logged in",
    });
  }

  next();
}

/**
 * -------------------------
 * Utility endpoint
 * -------------------------
 */

app.get("/api/config", (req, res) => {
  res.json({
    rpName: RP_NAME,
    rpID: RP_ID,
    expectedOrigins: EXPECTED_ORIGINS,
  });
});

/**
 * -------------------------
 * Registration step 1:
 * Generate registration options
 * -------------------------
 */

app.post("/api/register/options", async (req, res) => {
  try {
    const { username, displayName } = req.body;

    if (!username || typeof username !== "string") {
      return res.status(400).json({
        error: "Username is required",
      });
    }

    const cleanUsername = username.trim().toLowerCase();

    if (!cleanUsername) {
      return res.status(400).json({
        error: "Username cannot be empty",
      });
    }

    const user = createUser(cleanUsername, displayName);

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,

      // SimpleWebAuthn v10+ expects userID as bytes, not a normal string.
      userID: isoUint8Array.fromUTF8String(user.id),
      userName: user.username,
      userDisplayName: user.displayName,

      // "none" avoids complex device/vendor attestation policy.
      // It is common for demos and privacy-friendly apps.
      attestationType: "none",

      // Prevent registering the same authenticator again for this user.
      excludeCredentials: user.credentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports,
      })),

      authenticatorSelection: {
        // Required helps create passkey-style discoverable credentials.
        // This helps with cross-browser/device tests when passkeys sync.
        residentKey: "required",

        // For this assignment we require user verification.
        // That means biometric/PIN/local device unlock.
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
});

/**
 * -------------------------
 * Registration step 2:
 * Verify registration response
 * -------------------------
 */

app.post("/api/register/verify", async (req, res) => {
  try {
    const currentRegistration = req.session.currentRegistration;

    if (!currentRegistration) {
      return res.status(400).json({
        verified: false,
        error: "No registration challenge found in session",
      });
    }

    const user = findUserByUsername(currentRegistration.username);

    if (!user) {
      return res.status(400).json({
        verified: false,
        error: "User does not exist",
      });
    }

    let verification;

    try {
      verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: currentRegistration.challenge,
        expectedOrigin: EXPECTED_ORIGINS,
        expectedRPID: RP_ID,
        requireUserPresence: true,
        requireUserVerification: true,
      });
    } catch (error) {
      console.error("Registration verification failed:", error);

      return res.status(400).json({
        verified: false,
        error: error.message,
      });
    }

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      return res.status(400).json({
        verified: false,
        error: "Registration was not verified",
      });
    }

    const { credential, credentialDeviceType, credentialBackedUp } =
      registrationInfo;

    const existingCredential = findCredentialForUser(user, credential.id);

    if (!existingCredential) {
      user.credentials.push({
        id: credential.id,
        publicKey: uint8ArrayToBase64URL(credential.publicKey),
        counter: credential.counter,
        transports:
          credential.transports || req.body.response?.transports || [],
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
});

/**
 * -------------------------
 * Authentication step 1:
 * Generate authentication options
 * -------------------------
 */

app.post("/api/login/options", async (req, res) => {
  try {
    const { username } = req.body;

    if (!username || typeof username !== "string") {
      return res.status(400).json({
        error: "Username is required",
      });
    }

    const cleanUsername = username.trim().toLowerCase();
    const user = findUserByUsername(cleanUsername);

    if (!user) {
      return res.status(404).json({
        error: "User does not exist",
      });
    }

    if (!user.credentials.length) {
      return res.status(400).json({
        error: "This user has no registered passkeys",
      });
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,

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
});

/**
 * -------------------------
 * Authentication step 2:
 * Verify authentication response
 * -------------------------
 */

app.post("/api/login/verify", async (req, res) => {
  try {
    const currentAuthentication = req.session.currentAuthentication;

    if (!currentAuthentication) {
      return res.status(400).json({
        verified: false,
        error: "No authentication challenge found in session",
      });
    }

    const user = findUserByUsername(currentAuthentication.username);

    if (!user) {
      return res.status(400).json({
        verified: false,
        error: "User does not exist",
      });
    }

    const credential = findCredentialForUser(user, req.body.id);

    if (!credential) {
      return res.status(400).json({
        verified: false,
        error: "Credential does not belong to this user",
      });
    }

    let verification;

    try {
      verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: currentAuthentication.challenge,
        expectedOrigin: EXPECTED_ORIGINS,
        expectedRPID: RP_ID,
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

      return res.status(400).json({
        verified: false,
        error: error.message,
      });
    }

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      return res.status(400).json({
        verified: false,
        error: "Authentication was not verified",
      });
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
});

/**
 * -------------------------
 * Protected page data
 * -------------------------
 */

app.get("/api/me", requireLoggedIn, (req, res) => {
  const user = findUserByUsername(req.session.loggedInUser);

  if (!user) {
    return res.status(404).json({
      error: "Logged-in user was not found",
    });
  }

  res.json({
    username: user.username,
    displayName: user.displayName,
    lastAuthenticator: req.session.lastAuthenticator,
    credentials: user.credentials.map((credential) => ({
      id: credential.id,
      counter: credential.counter,
      deviceType: credential.deviceType,
      backedUp: credential.backedUp,
      transports: credential.transports,
      createdAt: credential.createdAt,
      lastUsedAt: credential.lastUsedAt,
    })),
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      ok: true,
    });
  });
});

/**
 * -------------------------
 * Start server
 * -------------------------
 */

if (USE_HTTPS) {
  const keyPath = path.join(__dirname, "certs", "localhost-key.pem");
  const certPath = path.join(__dirname, "certs", "localhost-cert.pem");

  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    console.error("Missing HTTPS certificate files.");
    console.error("Expected:");
    console.error(keyPath);
    console.error(certPath);
    process.exit(1);
  }

  https
    .createServer(
      {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath),
      },
      app,
    )
    .listen(PORT, () => {
      console.log(`HTTPS server running at https://localhost:${PORT}`);
      console.log(`RP_ID: ${RP_ID}`);
      console.log(`Expected origin(s): ${EXPECTED_ORIGINS.join(", ")}`);
    });
} else {
  app.listen(PORT, () => {
    console.log(`HTTP server running at http://localhost:${PORT}`);
    console.log(
      "Use this only behind an HTTPS tunnel such as ngrok/Cloudflare Tunnel.",
    );
    console.log(`RP_ID: ${RP_ID}`);
    console.log(`Expected origin(s): ${EXPECTED_ORIGINS.join(", ")}`);
  });
}
