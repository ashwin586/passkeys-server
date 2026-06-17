import { Router } from "express";
import authControllers from "../controllers/authControllers";
import profileControllers from "../controllers/profileControllers";
import {
  authValidator,
  importCSVValidator,
  passwordIdValidator,
  passwordValidators,
  profileValidators,
  settingsValidators,
} from "../validators/validators";
import validateRequest from "../middleware/validateRequest";
import validateJwt from "../middleware/validateJWT";

const routes = Router();

// Authentication Routes
routes.post("/login", authValidator, validateRequest, authControllers.login);
routes.post(
  "/register",
  authValidator,
  validateRequest,
  authControllers.register,
);

// Profile
routes.get("/profile", validateJwt, profileControllers.fetchProfile);
routes.patch(
  "/profile",
  validateJwt,
  profileValidators,
  validateRequest,
  profileControllers.updateProfile
);
routes.patch(
  "/profile/settings",
  validateJwt,
  settingsValidators,
  validateRequest,
  profileControllers.updateSettings
);
routes.delete("/profile/sessions", validateJwt, profileControllers.logoutAllSessions);

routes.get(
  "/profile/managePasswords",
  validateJwt,
  profileControllers.fetchPasswords
);
routes.post(
  "/profile/managePasswords",
  validateJwt,
  passwordValidators,
  validateRequest,
  profileControllers.addPasswords
);
routes.patch(
  "/profile/managePasswords/:id",
  validateJwt,
  passwordIdValidator,
  passwordValidators,
  validateRequest,
  profileControllers.updatePasswords
);
routes.delete(
  "/profile/managePasswords/:id",
  validateJwt,
  passwordIdValidator,
  validateRequest,
  profileControllers.deletePasswords
);

routes.post(
  "/profile/importCSV",
  validateJwt,
  importCSVValidator,
  validateRequest,
  profileControllers.importCSV
);
export default routes;
