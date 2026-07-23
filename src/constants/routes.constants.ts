// API route path constants.
export const ApiRoutes = {
  AUTH_SALT: "/auth/salt",
  LOGIN: "/login",
  REGISTER: "/register",
  LOGOUT: "/logout",
  PROFILE: "/profile",
  PROFILE_SETTINGS: "/profile/settings",
  PROFILE_SESSIONS: "/profile/sessions",
  MANAGE_PASSWORDS: "/profile/managePasswords",
  MANAGE_PASSWORD_BY_ID: "/profile/managePasswords/:id",
  IMPORT_CSV: "/profile/importCSV",
} as const;
