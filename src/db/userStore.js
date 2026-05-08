import fs from "node:fs";
import crypto from "node:crypto";
import { config } from "../utils/config.js";

/**
 * Reads the JSON database from disk.
 *
 * @returns {{ users: Array<Record<string, any>> }} Parsed database object
 */
const readDB = () => {
  if (!fs.existsSync(config.dbFilePath)) {
    return { users: [] };
  }

  const raw = fs.readFileSync(config.dbFilePath, "utf8");
  if (!raw.trim()) {
    return { users: [] };
  }

  return JSON.parse(raw);
};

/**
 * Persists the JSON database to disk.
 *
 * @param {{ users: Array<Record<string, any>> }} db - Updated database object
 * @returns {void}
 */
const writeDB = (db) => {
  fs.writeFileSync(config.dbFilePath, JSON.stringify(db, null, 2));
};

/**
 * Finds a single user by normalized username.
 *
 * @param {string} username - Normalized username
 * @returns {Record<string, any> | undefined} Matching user, if available
 */
const findUserByUsername = (username) => {
  const db = readDB();
  return db.users.find((user) => user.username === username);
};

/**
 * Creates a user if one does not already exist.
 *
 * @param {string} username - Normalized username
 * @param {string | undefined} displayName - Human-friendly display name
 * @returns {Record<string, any>} Existing or newly created user
 */
const createUser = (username, displayName) => {
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
};

/**
 * Updates an existing user record or inserts it if missing.
 *
 * @param {Record<string, any>} updatedUser - User object containing latest values
 * @returns {void}
 */
const saveUser = (updatedUser) => {
  const db = readDB();
  const index = db.users.findIndex((user) => user.id === updatedUser.id);

  if (index === -1) {
    db.users.push(updatedUser);
  } else {
    db.users[index] = updatedUser;
  }

  writeDB(db);
};

/**
 * Finds one credential for a given user.
 *
 * @param {Record<string, any>} user - User record with credentials array
 * @param {string} credentialID - Credential ID to find
 * @returns {Record<string, any> | undefined} Matching credential if present
 */
const findCredentialForUser = (user, credentialID) => {
  return user.credentials.find((credential) => credential.id === credentialID);
};

export {
  readDB,
  writeDB,
  findUserByUsername,
  createUser,
  saveUser,
  findCredentialForUser,
};
