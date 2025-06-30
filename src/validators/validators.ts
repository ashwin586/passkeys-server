import { check } from "express-validator";

export const authValidator = [
  check("email").isEmail().withMessage("Incorrect email and password"),
  check("password")
    .notEmpty()
    .isLength({ min: 8 })
    .withMessage("Incorrect email and password"),
];

export const profileValidators = [
  check("name")
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
    .trim()
    .notEmpty()
    .withMessage("Current Password is required")
    .isLength({ min: 8 })
    .withMessage("Current password should be atleast 8 characters"),
  check("newPassword")
    .trim()
    .notEmpty()
    .withMessage("Current Password is required")
    .isLength({ min: 8 })
    .withMessage("Current password should be atleast 8 characters"),
];
