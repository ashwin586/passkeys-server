import { validationResult } from "express-validator";
import { Request, Response, NextFunction } from "express";
import { ErrorMessages } from "../constants/messages.constants";
import { HttpStatus } from "../constants/http.constants";

const validateRequest = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const firstError = errors.array()[0];
    res.status(HttpStatus.BAD_REQUEST).json({
      message: firstError?.msg || ErrorMessages.INVALID_REQUEST_PAYLOAD,
    });
    return;
  }
  next();
};

export default validateRequest;
