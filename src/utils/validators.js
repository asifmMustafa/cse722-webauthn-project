/**
 * Normalizes user-submitted usernames for consistent lookup.
 *
 * @param {string} username - Raw username submitted by the client
 * @returns {string} Trimmed and lowercased username
 */
const normalizeUsername = (username) => {
  return username.trim().toLowerCase();
};

export { normalizeUsername };
