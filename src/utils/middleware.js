/**
 * Protects endpoints that require an authenticated session.
 *
 * @param {import("express").Request} req - Incoming HTTP request
 * @param {import("express").Response} res - Outgoing HTTP response
 * @param {import("express").NextFunction} next - Express continuation callback
 * @returns {void}
 */
const requireLoggedIn = (req, res, next) => {
  if (!req.session.loggedInUser) {
    res.status(401).json({
      error: "You are not logged in",
    });
    return;
  }

  next();
};

export { requireLoggedIn };
