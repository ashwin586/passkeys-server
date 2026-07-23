import { CryptoLengths, HexPattern } from "./security.constants";
import { ThemePreferences } from "./app.constants";

// Validation constraint messages and numeric bounds.
export const ValidationMessages = {
  INCORRECT_EMAIL_OR_PASSWORD: "Incorrect email and password",
  INVALID_VAULT_SALT: "Invalid vault salt",
  VALID_EMAIL_REQUIRED: "Valid email is required",
  NO_CHANGES_PROVIDED: "No changes provided",
  PASSWORD_CHANGE_BOTH_REQUIRED:
    "Both currentPassword and newPassword are required for password change",
  VAULT_SALT_REQUIRED_ON_PASSWORD_CHANGE:
    "vaultSalt is required when changing password",
  NAME_REQUIRED: "Name is required",
  NAME_MIN_LENGTH: "Name should be at least 4 characters",
  NAME_PATTERN:
    "Name must start with a letter and contain only letters and spaces",
  INVALID_CURRENT_PASSWORD_VERIFIER: "Invalid current password verifier",
  INVALID_NEW_PASSWORD_VERIFIER: "Invalid new password verifier",
  AUTO_LOCK_RANGE: "autoLockTimeout must be between 5 and 60",
  CLIPBOARD_TIMER_RANGE: "clipboardTimer must be between 10 and 120",
  MASK_SENSITIVE_BOOLEAN: "maskSensitiveData must be a boolean",
  SECURITY_REMINDERS_BOOLEAN: "securityReminders must be a boolean",
  LOCK_ON_CLOSE_BOOLEAN: "lockOnClose must be a boolean",
  INVALID_THEME: "Invalid themePreference",
  NOTIFICATIONS_BOOLEAN: "notifications must be a boolean",
  GENERATOR_LENGTH_RANGE: "generatorLength must be between 8 and 50",
  GENERATOR_SYMBOLS_BOOLEAN: "generatorSymbols must be a boolean",
  GENERATOR_NUMBERS_BOOLEAN: "generatorNumbers must be a boolean",
  GENERATOR_UPPERCASE_BOOLEAN: "generatorUppercase must be a boolean",
  GENERATOR_LOWERCASE_BOOLEAN: "generatorLowercase must be a boolean",
  LANGUAGE_LENGTH: "language must be between 2 and 30 characters",
  APP_NAME_REQUIRED: "App Name is required",
  URL_REQUIRED: "URL is required",
  USERNAME_REQUIRED: "Username or Email is required",
  INVALID_ENCRYPTED_PASSWORD: "Invalid encrypted password payload",
  INVALID_ENCRYPTION_IV: "Invalid encryption IV",
  INVALID_CREDENTIAL_ID: "Invalid credential id",
  CSV_DATA_NON_EMPTY: "csvData must be a non-empty array",
} as const;

export const ValidationBounds = {
  NAME_MIN: 4,
  AUTO_LOCK_MIN: 5,
  AUTO_LOCK_MAX: 60,
  CLIPBOARD_MIN: 10,
  CLIPBOARD_MAX: 120,
  GENERATOR_LENGTH_MIN: 8,
  GENERATOR_LENGTH_MAX: 50,
  LANGUAGE_MIN: 2,
  LANGUAGE_MAX: 30,
  AUTH_HASH_LENGTH: CryptoLengths.AUTH_HASH_HEX,
  VAULT_SALT_LENGTH: CryptoLengths.VAULT_SALT_HEX,
  IV_LENGTH: CryptoLengths.IV_HEX,
  CIPHERTEXT_MIN: CryptoLengths.CIPHERTEXT_HEX_MIN,
  CIPHERTEXT_MAX: CryptoLengths.CIPHERTEXT_HEX_MAX,
  THEME_OPTIONS: ThemePreferences,
  HEX_PATTERN: HexPattern,
  NAME_PATTERN: /^[A-Za-z][A-Za-z\s]*$/,
} as const;
