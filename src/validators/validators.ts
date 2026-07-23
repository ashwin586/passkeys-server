import { body, check, param, query } from "express-validator";
import {
  ValidationBounds,
  ValidationMessages,
} from "../constants/validation.constants";

export const authValidator = [
  check("email")
    .isEmail()
    .withMessage(ValidationMessages.INCORRECT_EMAIL_OR_PASSWORD),
  check("password")
    .notEmpty()
    .isLength({
      min: ValidationBounds.AUTH_HASH_LENGTH,
      max: ValidationBounds.AUTH_HASH_LENGTH,
    })
    .matches(ValidationBounds.HEX_PATTERN)
    .withMessage(ValidationMessages.INCORRECT_EMAIL_OR_PASSWORD),
];

export const registerValidator = [
  ...authValidator,
  check("vaultSalt")
    .notEmpty()
    .isLength({
      min: ValidationBounds.VAULT_SALT_LENGTH,
      max: ValidationBounds.VAULT_SALT_LENGTH,
    })
    .matches(ValidationBounds.HEX_PATTERN)
    .withMessage(ValidationMessages.INVALID_VAULT_SALT),
];

export const saltQueryValidator = [
  query("email").isEmail().withMessage(ValidationMessages.VALID_EMAIL_REQUIRED),
];

export const profileValidators = [
  body().custom((value) => {
    const hasName = Object.prototype.hasOwnProperty.call(value, "name");
    const hasCurrentPassword = Object.prototype.hasOwnProperty.call(
      value,
      "currentPassword",
    );
    const hasNewPassword = Object.prototype.hasOwnProperty.call(
      value,
      "newPassword",
    );
    const hasVaultSalt = Object.prototype.hasOwnProperty.call(
      value,
      "vaultSalt",
    );

    if (!hasName && !hasCurrentPassword && !hasNewPassword) {
      throw new Error(ValidationMessages.NO_CHANGES_PROVIDED);
    }

    if (hasCurrentPassword !== hasNewPassword) {
      throw new Error(ValidationMessages.PASSWORD_CHANGE_BOTH_REQUIRED);
    }

    if (hasCurrentPassword && hasNewPassword && !hasVaultSalt) {
      throw new Error(ValidationMessages.VAULT_SALT_REQUIRED_ON_PASSWORD_CHANGE);
    }

    return true;
  }),
  check("name")
    .optional()
    .trim()
    .notEmpty()
    .withMessage(ValidationMessages.NAME_REQUIRED)
    .isLength({ min: ValidationBounds.NAME_MIN })
    .withMessage(ValidationMessages.NAME_MIN_LENGTH)
    .matches(ValidationBounds.NAME_PATTERN)
    .withMessage(ValidationMessages.NAME_PATTERN),
  check("currentPassword")
    .optional()
    .trim()
    .isLength({
      min: ValidationBounds.AUTH_HASH_LENGTH,
      max: ValidationBounds.AUTH_HASH_LENGTH,
    })
    .matches(ValidationBounds.HEX_PATTERN)
    .withMessage(ValidationMessages.INVALID_CURRENT_PASSWORD_VERIFIER),
  check("newPassword")
    .optional()
    .trim()
    .isLength({
      min: ValidationBounds.AUTH_HASH_LENGTH,
      max: ValidationBounds.AUTH_HASH_LENGTH,
    })
    .matches(ValidationBounds.HEX_PATTERN)
    .withMessage(ValidationMessages.INVALID_NEW_PASSWORD_VERIFIER),
  check("vaultSalt")
    .optional()
    .isLength({
      min: ValidationBounds.VAULT_SALT_LENGTH,
      max: ValidationBounds.VAULT_SALT_LENGTH,
    })
    .matches(ValidationBounds.HEX_PATTERN)
    .withMessage(ValidationMessages.INVALID_VAULT_SALT),
];

export const settingsValidators = [
  check("autoLockTimeout")
    .optional()
    .isInt({
      min: ValidationBounds.AUTO_LOCK_MIN,
      max: ValidationBounds.AUTO_LOCK_MAX,
    })
    .withMessage(ValidationMessages.AUTO_LOCK_RANGE),
  check("clipboardTimer")
    .optional()
    .isInt({
      min: ValidationBounds.CLIPBOARD_MIN,
      max: ValidationBounds.CLIPBOARD_MAX,
    })
    .withMessage(ValidationMessages.CLIPBOARD_TIMER_RANGE),
  check("maskSensitiveData")
    .optional()
    .isBoolean()
    .withMessage(ValidationMessages.MASK_SENSITIVE_BOOLEAN),
  check("securityReminders")
    .optional()
    .isBoolean()
    .withMessage(ValidationMessages.SECURITY_REMINDERS_BOOLEAN),
  check("lockOnClose")
    .optional()
    .isBoolean()
    .withMessage(ValidationMessages.LOCK_ON_CLOSE_BOOLEAN),
  check("themePreference")
    .optional()
    .isIn([...ValidationBounds.THEME_OPTIONS])
    .withMessage(ValidationMessages.INVALID_THEME),
  check("notifications")
    .optional()
    .isBoolean()
    .withMessage(ValidationMessages.NOTIFICATIONS_BOOLEAN),
  check("generatorLength")
    .optional()
    .isInt({
      min: ValidationBounds.GENERATOR_LENGTH_MIN,
      max: ValidationBounds.GENERATOR_LENGTH_MAX,
    })
    .withMessage(ValidationMessages.GENERATOR_LENGTH_RANGE),
  check("generatorSymbols")
    .optional()
    .isBoolean()
    .withMessage(ValidationMessages.GENERATOR_SYMBOLS_BOOLEAN),
  check("generatorNumbers")
    .optional()
    .isBoolean()
    .withMessage(ValidationMessages.GENERATOR_NUMBERS_BOOLEAN),
  check("generatorUppercase")
    .optional()
    .isBoolean()
    .withMessage(ValidationMessages.GENERATOR_UPPERCASE_BOOLEAN),
  check("generatorLowercase")
    .optional()
    .isBoolean()
    .withMessage(ValidationMessages.GENERATOR_LOWERCASE_BOOLEAN),
  check("language")
    .optional()
    .isString()
    .isLength({
      min: ValidationBounds.LANGUAGE_MIN,
      max: ValidationBounds.LANGUAGE_MAX,
    })
    .withMessage(ValidationMessages.LANGUAGE_LENGTH),
];

export const passwordValidators = [
  check("name")
    .trim()
    .notEmpty()
    .withMessage(ValidationMessages.APP_NAME_REQUIRED),
  check("url").trim().notEmpty().withMessage(ValidationMessages.URL_REQUIRED),
  check("userName")
    .trim()
    .notEmpty()
    .withMessage(ValidationMessages.USERNAME_REQUIRED),
  check("password")
    .trim()
    .matches(ValidationBounds.HEX_PATTERN)
    .isLength({
      min: ValidationBounds.CIPHERTEXT_MIN,
      max: ValidationBounds.CIPHERTEXT_MAX,
    })
    .withMessage(ValidationMessages.INVALID_ENCRYPTED_PASSWORD),
  check("iv")
    .trim()
    .matches(ValidationBounds.HEX_PATTERN)
    .isLength({
      min: ValidationBounds.IV_LENGTH,
      max: ValidationBounds.IV_LENGTH,
    })
    .withMessage(ValidationMessages.INVALID_ENCRYPTION_IV),
];

export const passwordIdValidator = [
  param("id").isMongoId().withMessage(ValidationMessages.INVALID_CREDENTIAL_ID),
];

export const importCSVValidator = [
  body("csvData")
    .isArray({ min: 1 })
    .withMessage(ValidationMessages.CSV_DATA_NON_EMPTY),
];
