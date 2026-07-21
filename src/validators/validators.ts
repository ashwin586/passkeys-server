import { body, check, param, query } from "express-validator";

export const authValidator = [
  check("email").isEmail().withMessage("Incorrect email and password"),
  check("password")
    .notEmpty()
    .isLength({ min: 64, max: 64 })
    .matches(/^[a-f0-9]+$/i)
    .withMessage("Incorrect email and password"),
];

export const registerValidator = [
  ...authValidator,
  check("vaultSalt")
    .notEmpty()
    .isLength({ min: 32, max: 32 })
    .matches(/^[a-f0-9]+$/i)
    .withMessage("Invalid vault salt"),
];

export const saltQueryValidator = [
  query("email").isEmail().withMessage("Valid email is required"),
];

export const profileValidators = [
  body().custom((value) => {
    const hasName = Object.prototype.hasOwnProperty.call(value, "name");
    const hasCurrentPassword = Object.prototype.hasOwnProperty.call(
      value,
      "currentPassword"
    );
    const hasNewPassword = Object.prototype.hasOwnProperty.call(
      value,
      "newPassword"
    );
    const hasVaultSalt = Object.prototype.hasOwnProperty.call(
      value,
      "vaultSalt"
    );

    if (!hasName && !hasCurrentPassword && !hasNewPassword) {
      throw new Error("No changes provided");
    }

    if (hasCurrentPassword !== hasNewPassword) {
      throw new Error(
        "Both currentPassword and newPassword are required for password change"
      );
    }

    if (hasCurrentPassword && hasNewPassword && !hasVaultSalt) {
      throw new Error("vaultSalt is required when changing password");
    }

    return true;
  }),
  check("name")
    .optional()
    .trim()
    .notEmpty()
    .withMessage("Name is required")
    .isLength({ min: 4 })
    .withMessage("Name should be at least 4 characters")
    .matches(/^[A-Za-z][A-Za-z\s]*$/)
    .withMessage(
      "Name must start with a letter and contain only letters and spaces"
    ),
  check("currentPassword")
    .optional()
    .trim()
    .isLength({ min: 64, max: 64 })
    .matches(/^[a-f0-9]+$/i)
    .withMessage("Invalid current password verifier"),
  check("newPassword")
    .optional()
    .trim()
    .isLength({ min: 64, max: 64 })
    .matches(/^[a-f0-9]+$/i)
    .withMessage("Invalid new password verifier"),
  check("vaultSalt")
    .optional()
    .isLength({ min: 32, max: 32 })
    .matches(/^[a-f0-9]+$/i)
    .withMessage("Invalid vault salt"),
];

export const settingsValidators = [
  check("autoLockTimeout")
    .optional()
    .isInt({ min: 5, max: 60 })
    .withMessage("autoLockTimeout must be between 5 and 60"),
  check("clipboardTimer")
    .optional()
    .isInt({ min: 10, max: 120 })
    .withMessage("clipboardTimer must be between 10 and 120"),
  check("maskSensitiveData")
    .optional()
    .isBoolean()
    .withMessage("maskSensitiveData must be a boolean"),
  check("securityReminders")
    .optional()
    .isBoolean()
    .withMessage("securityReminders must be a boolean"),
  check("lockOnClose")
    .optional()
    .isBoolean()
    .withMessage("lockOnClose must be a boolean"),
  check("themePreference")
    .optional()
    .isIn(["System default", "Dark", "Light"])
    .withMessage("Invalid themePreference"),
  check("notifications")
    .optional()
    .isBoolean()
    .withMessage("notifications must be a boolean"),
  check("generatorLength")
    .optional()
    .isInt({ min: 8, max: 50 })
    .withMessage("generatorLength must be between 8 and 50"),
  check("generatorSymbols")
    .optional()
    .isBoolean()
    .withMessage("generatorSymbols must be a boolean"),
  check("generatorNumbers")
    .optional()
    .isBoolean()
    .withMessage("generatorNumbers must be a boolean"),
  check("generatorUppercase")
    .optional()
    .isBoolean()
    .withMessage("generatorUppercase must be a boolean"),
  check("generatorLowercase")
    .optional()
    .isBoolean()
    .withMessage("generatorLowercase must be a boolean"),
  check("language")
    .optional()
    .isString()
    .isLength({ min: 2, max: 30 })
    .withMessage("language must be between 2 and 30 characters"),
];

export const passwordValidators = [
  check("name").trim().notEmpty().withMessage("App Name is required"),
  check("url").trim().notEmpty().withMessage("URL is required"),
  check("userName")
    .trim()
    .notEmpty()
    .withMessage("Username or Email is required"),
  check("password")
    .trim()
    .matches(/^[a-f0-9]+$/i)
    .isLength({ min: 32, max: 8192 })
    .withMessage("Invalid encrypted password payload"),
  check("iv")
    .trim()
    .matches(/^[a-f0-9]+$/i)
    .isLength({ min: 24, max: 24 })
    .withMessage("Invalid encryption IV"),
];

export const passwordIdValidator = [
  param("id").isMongoId().withMessage("Invalid credential id"),
];

export const importCSVValidator = [
  body("csvData")
    .isArray({ min: 1 })
    .withMessage("csvData must be a non-empty array"),
];
