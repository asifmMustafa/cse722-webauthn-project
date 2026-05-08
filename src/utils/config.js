import crypto from "node:crypto";
import path from "node:path";
import dotenv from "dotenv";
import { fileURLToPath } from "node:url";

dotenv.config();

const currentFilePath = fileURLToPath(import.meta.url);
const currentDirPath = path.dirname(currentFilePath);
const serverRootDir = path.resolve(currentDirPath, "..", "..");

const port = Number(process.env.PORT || 8443);
const rpName = process.env.RP_NAME || "CSE722 WebAuthn Demo";
const rpId = process.env.RP_ID || "localhost";
const origin = process.env.ORIGIN || `https://${rpId}:${port}`;
const expectedOrigins = origin.split(",").map((value) => value.trim());
const useHttps = process.env.USE_HTTPS !== "false";
const sessionSecret =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

const config = {
  port,
  rpName,
  rpId,
  expectedOrigins,
  useHttps,
  sessionSecret,
  dbFilePath: path.join(serverRootDir, "db.json"),
  publicDirPath: path.join(serverRootDir, "public"),
  certKeyPath: path.join(serverRootDir, "certs", "localhost-key.pem"),
  certPath: path.join(serverRootDir, "certs", "localhost-cert.pem"),
};

export { config };
