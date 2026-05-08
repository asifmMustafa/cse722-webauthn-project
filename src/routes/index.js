import { Router } from "express";
import { authRouter } from "./authRoutes.js";
import { configRouter } from "./configRoutes.js";
import { userRouter } from "./userRoutes.js";

const apiRouter = Router();

apiRouter.use(configRouter);
apiRouter.use(authRouter);
apiRouter.use(userRouter);

export { apiRouter };
