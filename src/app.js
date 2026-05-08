import express from "express";
import session from "express-session";
import helmet from "helmet";
import { apiRouter } from "./routes/index.js";
import { config } from "./utils/config.js";

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
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: config.expectedOrigins[0].startsWith("https://") ? "auto" : false,
      maxAge: 1000 * 60 * 60,
    },
  }),
);

app.use(express.static(config.publicDirPath));
app.use("/api", apiRouter);

export { app };
