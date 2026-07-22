import { Router } from "express";
import authControllers from "../controllers/authControllers";
import profileControllers from "../controllers/profileControllers";
import {
  authValidator,
  registerValidator,
  saltQueryValidator,
  importCSVValidator,
  passwordIdValidator,
  passwordValidators,
  profileValidators,
  settingsValidators,
} from "../validators/validators";
import validateRequest from "../middleware/validateRequest";
import validateJwt from "../middleware/validateJWT";
import optionalJwt from "../middleware/optionalJwt";

const routes = Router();

// Authentication Routes
routes.get(
  "/auth/salt",
  saltQueryValidator,
  validateRequest,
  authControllers.getSalt,
);
routes.post("/login", authValidator, validateRequest, authControllers.login);
routes.post(
  "/register",
  registerValidator,
  validateRequest,
  authControllers.register,
);
routes.post("/logout", optionalJwt, authControllers.logout);

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
