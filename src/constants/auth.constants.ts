// Auth cookie, token, and JWT-related constants (non-env defaults). 
export const AuthCookie = {
  NAME: "vault_access_token",
  PATH: "/",
  DEFAULT_SAMESITE: "none",
} as const;

export const JwtDefaults = {
  EXPIRES_IN: "30m",
  ACCESS_TOKEN_MAX_AGE_MS: 30 * 60 * 1000,
  MIN_SECRET_LENGTH: 32,
} as const;

export const AuthRole = {
  USER: "user",
} as const;

export const AuthTokenErrors = {
  EXPIRED: "TokenExpiredError",
  INVALID: "JsonWebTokenError",
} as const;

export const AuthMessages = {
  INVALID_CREDENTIALS: "Invalid email or password",
  EMAIL_REQUIRED: "Email is required",
  VAULT_SALT_REQUIRED: "vaultSalt is required",
  LOGIN_SUCCESS: "Login Successful",
  LOGOUT_SUCCESS: "Logged out successfully",
  REGISTER_SUCCESS:
    "Account created successfully. You can sign in.",
  ACTIVITY_SUCCESSFUL_LOGIN: "Successful login",
  TOKEN_MISSING: "Token Missing",
  INVALID_TOKEN: "Invalid token",
  SESSION_REVOKED: "Session revoked",
  SESSION_EXPIRED: "Session Expired",
  JWT_SECRET_TOO_SHORT:
    "JWT_SECRET must be at least 32 characters",
} as const;
