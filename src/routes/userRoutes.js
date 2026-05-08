import { Router } from "express";
import { findUserByUsername } from "../db/userStore.js";
import { requireLoggedIn } from "../utils/middleware.js";

const userRouter = Router();

userRouter.get("/me", requireLoggedIn, (req, res) => {
  const user = findUserByUsername(req.session.loggedInUser);

  if (!user) {
    res.status(404).json({
      error: "Logged-in user was not found",
    });
    return;
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

export { userRouter };
