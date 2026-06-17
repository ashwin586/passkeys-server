import { validationResult } from "express-validator";
import { Request, Response, NextFunction } from "express";

const validateRequest = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const firstError = errors.array()[0];
    res.status(400).json({ message: firstError?.msg || "Invalid request payload" });
    return;
  }
  next();
};

export default validateRequest;
