import { check } from "express-validator";

export const authValidator = [
  check("email").isEmail().withMessage("Incorrect email and password"),
  check("password")
    .notEmpty()
    .isLength({ min: 8 })
    .withMessage("Incorrect email and password"),
];
