import { Router } from "express";
import authControllers from "../controllers/authControllers";
import profileControllers from "../controllers/profileControllers";
import { authValidator, profileValidators } from "../validators/validators";
import validateRequest from "../middleware/validateRequest";
import validateJwt, { checkRefreshToken } from "../middleware/validateJWT";

const routes = Router();

// Authentication Routes
routes.post("/login", authValidator, validateRequest, authControllers.login);
routes.post("/register", authValidator, validateRequest, authControllers.register);
routes.post("/googleSignIn", authControllers.googleSignIn);

// check
routes.get("/refresh-token", checkRefreshToken, authControllers.refreshToken);

// Profile
routes.get("/profile", validateJwt, profileControllers.fetchProfile);
routes.patch('/profile', validateJwt, profileValidators, profileControllers.updateProfile)

export default routes;
