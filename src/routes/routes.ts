import { Router } from "express";
import authControllers from "../controllers/authControllers";
import { authValidator } from "../validators/authValidators";
import validateRequest from "../middleware/validateRequest";

const routes = Router();

// Authentication Routes
routes.post("/login",authValidator, validateRequest, authControllers.login);
routes.post("/register", authValidator, validateRequest, authControllers.register);
routes.post("/googleSignIn", authControllers.googleSignIn);

// check
routes.post("/refresh-token", authControllers.refreshToken);

export default routes;
