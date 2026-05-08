/**
 * Converts WebAuthn byte values to a base64url string.
 *
 * @param {Uint8Array} value - Raw bytes from WebAuthn response data
 * @returns {string} Base64url encoded value for JSON storage
 */
const uint8ArrayToBase64URL = (value) => {
  return Buffer.from(value).toString("base64url");
};

/**
 * Converts stored base64url strings back to WebAuthn byte values.
 *
 * @param {string} value - Base64url encoded string stored in the database
 * @returns {Uint8Array} Decoded bytes required by SimpleWebAuthn verification
 */
const base64URLToUint8Array = (value) => {
  return new Uint8Array(Buffer.from(value, "base64url"));
};

export { uint8ArrayToBase64URL, base64URLToUint8Array };
