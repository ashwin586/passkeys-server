import jwt from "jsonwebtoken";
import { Response, NextFunction } from "express";
import { payloadInterface, AuthRequest } from "../types/interface";
import { AUTH_COOKIE_NAME } from "../utils/authCookies";

/**
 * Attaches req.user when a valid cookie/Bearer token is present.
 * Never fails the request — used for logout cookie cleanup.
 */
const optionalJwt = (
  req: AuthRequest,
  _res: Response,
  next: NextFunction,
) => {
  try {
    const cookieToken = req.cookies?.[AUTH_COOKIE_NAME];
    const authHeader = req.headers.authorization;
    const token =
      (typeof cookieToken === "string" && cookieToken) ||
      (authHeader?.startsWith("Bearer ") ? authHeader.split(" ")[1] : null);

    if (!token) {
      next();
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    req.user = decoded as payloadInterface;
  } catch {
    // Expired/invalid token — still allow logout to clear the cookie.
  }
  next();
};

export default optionalJwt;
