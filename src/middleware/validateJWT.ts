import jwt from "jsonwebtoken";
import { Response, NextFunction } from "express";
import { payloadInterface, AuthRequest } from "../types/interface";
import User from "../models/users";
import { AUTH_COOKIE_NAME, clearAuthCookie } from "../utils/authCookies";
import { revokeSession } from "../utils/sessions";
import { AuthMessages, AuthTokenErrors } from "../constants/auth.constants";
import { ErrorMessages } from "../constants/messages.constants";
import {
  AuthScheme,
  HttpHeaders,
  HttpStatus,
} from "../constants/http.constants";

const extractToken = (req: AuthRequest): string | null => {
  const cookieToken = req.cookies?.[AUTH_COOKIE_NAME];
  if (typeof cookieToken === "string" && cookieToken.length > 0) {
    return cookieToken;
  }

  const authHeader = req.headers[HttpHeaders.AUTHORIZATION];
  if (
    typeof authHeader === "string" &&
    authHeader.startsWith(AuthScheme.BEARER_PREFIX)
  ) {
    return authHeader.split(" ")[1] || null;
  }

  return null;
};

const markExpiredSessionInactive = async (token: string) => {
  try {
    const decoded = jwt.decode(token) as payloadInterface | null;
    if (!decoded?.email || !decoded?.sessionId) return;

    const user: any = await User.findOne({ email: decoded.email });
    if (!user) return;

    if (revokeSession(user, decoded.sessionId)) {
      await user.save();
    }
  } catch {
    // Best-effort cleanup only.
  }
};

const validateJwt = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction,
) => {
  const token = extractToken(req);
  try {
    if (!token) {
      res
        .status(HttpStatus.UNAUTHORIZED)
        .json({ message: AuthMessages.TOKEN_MISSING });
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    const payload = decoded as payloadInterface;

    if (!payload.sessionId) {
      clearAuthCookie(res);
      res
        .status(HttpStatus.UNAUTHORIZED)
        .json({ message: AuthMessages.INVALID_TOKEN });
      return;
    }

    const user: any = await User.findOne({ email: payload.email });

    if (!user) {
      clearAuthCookie(res);
      res
        .status(HttpStatus.UNAUTHORIZED)
        .json({ message: AuthMessages.INVALID_TOKEN });
      return;
    }

    const activeSession = (user.sessions || []).find(
      (session: any) =>
        session.sessionId === payload.sessionId && session.active,
    );
    if (!activeSession) {
      clearAuthCookie(res);
      res
        .status(HttpStatus.UNAUTHORIZED)
        .json({ message: AuthMessages.SESSION_REVOKED });
      return;
    }

    activeSession.lastSeenAt = new Date();
    await user.save();

    req.user = payload;
    next();
  } catch (error: any) {
    clearAuthCookie(res);
    if (error.name === AuthTokenErrors.EXPIRED) {
      if (token) {
        await markExpiredSessionInactive(token);
      }
      res
        .status(HttpStatus.UNAUTHORIZED)
        .json({ message: AuthMessages.SESSION_EXPIRED });
      return;
    } else if (error.name === AuthTokenErrors.INVALID) {
      res
        .status(HttpStatus.UNAUTHORIZED)
        .json({ message: AuthMessages.INVALID_TOKEN });
      return;
    }

    res
      .status(HttpStatus.INTERNAL_SERVER_ERROR)
      .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR_LOWER });
    return;
  }
};

export default validateJwt;
