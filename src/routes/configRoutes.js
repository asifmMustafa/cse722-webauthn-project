import { Router } from "express";
import { config } from "../utils/config.js";

const configRouter = Router();

configRouter.get("/config", (req, res) => {
  res.json({
    rpName: config.rpName,
    rpID: config.rpId,
    expectedOrigins: config.expectedOrigins,
  });
});

export { configRouter };
