/** Application defaults and non-secret operational constants. */
export const AppDefaults = {
  SESSION_HISTORY_LIMIT: 20,
  ACTIVITY_HISTORY_LIMIT: 20,
  PROFILE_ACTIVITY_PREVIEW_LIMIT: 10,
  UNKNOWN_DEVICE: "Unknown device",
  UNKNOWN_IP: "Unknown IP",
  FALLBACK_IP_KEY: "unknown",
  MISSING_EMAIL_KEY: "missing-email",
} as const;

export const DefaultUserSettings = {
  autoLockTimeout: 15,
  clipboardTimer: 30,
  maskSensitiveData: true,
  securityReminders: true,
  lockOnClose: true,
  themePreference: "System default",
  notifications: true,
  generatorLength: 18,
  generatorSymbols: true,
  generatorNumbers: true,
  generatorUppercase: true,
  generatorLowercase: true,
  language: "English",
} as const;

export const ThemePreferences = [
  "System default",
  "Dark",
  "Light",
] as const;

export const SettingsFields = [
  "autoLockTimeout",
  "clipboardTimer",
  "maskSensitiveData",
  "securityReminders",
  "lockOnClose",
  "themePreference",
  "notifications",
  "generatorLength",
  "generatorSymbols",
  "generatorNumbers",
  "generatorUppercase",
  "generatorLowercase",
  "language",
] as const;

export const CorsDefaults = {
  ALLOWED_ORIGINS: ["http://localhost:3000"],
} as const;

export const ActivityTypes = {
  LOGIN: "login",
  PROFILE_UPDATE: "profile_update",
  PASSWORD_CHANGE: "password_change",
  SETTINGS_UPDATE: "settings_update",
  SESSION_REVOKE: "session_revoke",
} as const;
