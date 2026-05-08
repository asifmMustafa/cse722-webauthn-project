import fs from "node:fs";
import https from "node:https";
import { config } from "./config.js";

/**
 * Starts HTTP or HTTPS server based on runtime configuration.
 *
 * @param {import("express").Express} app - Configured Express application
 * @returns {void}
 */
const startServer = (app) => {
  if (config.useHttps) {
    if (!fs.existsSync(config.certKeyPath) || !fs.existsSync(config.certPath)) {
      console.error("Missing HTTPS certificate files.");
      console.error("Expected:");
      console.error(config.certKeyPath);
      console.error(config.certPath);
      process.exit(1);
    }

    https
      .createServer(
        {
          key: fs.readFileSync(config.certKeyPath),
          cert: fs.readFileSync(config.certPath),
        },
        app,
      )
      .listen(config.port, () => {
        console.log(`HTTPS server running at https://localhost:${config.port}`);
        console.log(`RP_ID: ${config.rpId}`);
        console.log(`Expected origin(s): ${config.expectedOrigins.join(", ")}`);
      });

    return;
  }

  app.listen(config.port, () => {
    console.log(`HTTP server running at http://localhost:${config.port}`);
    console.log(
      "Use this only behind an HTTPS tunnel such as ngrok/Cloudflare Tunnel.",
    );
    console.log(`RP_ID: ${config.rpId}`);
    console.log(`Expected origin(s): ${config.expectedOrigins.join(", ")}`);
  });
};

export { startServer };
