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
import {
  loginAccountLimiter,
  loginIpLimiter,
  registerIpLimiter,
  saltIpLimiter,
} from "../middleware/rateLimit";
import { ApiRoutes } from "../constants/routes.constants";

const routes = Router();

// Authentication Routes
routes.get(
  ApiRoutes.AUTH_SALT,
  saltIpLimiter,
  saltQueryValidator,
  validateRequest,
  authControllers.getSalt,
);
routes.post(
  ApiRoutes.LOGIN,
  loginIpLimiter,
  loginAccountLimiter,
  authValidator,
  validateRequest,
  authControllers.login,
);
routes.post(
  ApiRoutes.REGISTER,
  registerIpLimiter,
  registerValidator,
  validateRequest,
  authControllers.register,
);
routes.post(ApiRoutes.LOGOUT, optionalJwt, authControllers.logout);

// Profile
routes.get(ApiRoutes.PROFILE, validateJwt, profileControllers.fetchProfile);
routes.patch(
  ApiRoutes.PROFILE,
  validateJwt,
  profileValidators,
  validateRequest,
  profileControllers.updateProfile,
);
routes.patch(
  ApiRoutes.PROFILE_SETTINGS,
  validateJwt,
  settingsValidators,
  validateRequest,
  profileControllers.updateSettings,
);
routes.delete(
  ApiRoutes.PROFILE_SESSIONS,
  validateJwt,
  profileControllers.logoutAllSessions,
);

routes.get(
  ApiRoutes.MANAGE_PASSWORDS,
  validateJwt,
  profileControllers.fetchPasswords,
);
routes.post(
  ApiRoutes.MANAGE_PASSWORDS,
  validateJwt,
  passwordValidators,
  validateRequest,
  profileControllers.addPasswords,
);
routes.patch(
  ApiRoutes.MANAGE_PASSWORD_BY_ID,
  validateJwt,
  passwordIdValidator,
  passwordValidators,
  validateRequest,
  profileControllers.updatePasswords,
);
routes.delete(
  ApiRoutes.MANAGE_PASSWORD_BY_ID,
  validateJwt,
  passwordIdValidator,
  validateRequest,
  profileControllers.deletePasswords,
);

routes.post(
  ApiRoutes.IMPORT_CSV,
  validateJwt,
  importCSVValidator,
  validateRequest,
  profileControllers.importCSV,
);
export default routes;
