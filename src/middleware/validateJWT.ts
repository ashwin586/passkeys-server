import jwt from "jsonwebtoken";
import { Response, NextFunction } from "express";
import { payloadInterface, AuthRequest } from "../types/interface";
import User from "../models/users";
import { AUTH_COOKIE_NAME, clearAuthCookie } from "../utils/authCookies";

const extractToken = (req: AuthRequest): string | null => {
  const cookieToken = req.cookies?.[AUTH_COOKIE_NAME];
  if (typeof cookieToken === "string" && cookieToken.length > 0) {
    return cookieToken;
  }

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.split(" ")[1] || null;
  }

  return null;
};

const validateJwt = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction,
) => {
  try {
    const token = extractToken(req);
    if (!token) {
      res.status(401).json({ message: "Token Missing" });
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    const payload = decoded as payloadInterface;
    const user: any = await User.findOne({ email: payload.email });

    if (!user) {
      clearAuthCookie(res);
      res.status(401).json({ message: "Invalid token" });
      return;
    }

    if (payload.sessionId) {
      const activeSession = (user.sessions || []).find(
        (session: any) =>
          session.sessionId === payload.sessionId && session.active,
      );
      if (!activeSession) {
        clearAuthCookie(res);
        res.status(401).json({ message: "Session revoked" });
        return;
      }
      activeSession.lastSeenAt = new Date();
      await user.save();
    }

    req.user = payload;
    next();
  } catch (error: any) {
    clearAuthCookie(res);
    if (error.name === "TokenExpiredError") {
      res.status(401).json({ message: "Session Expired" });
      return;
    } else if (error.name === "JsonWebTokenError") {
      res.status(401).json({ message: "Invalid token" });
      return;
    }

    res.status(500).json({ message: "Internal server error" });
    return;
  }
};

export default validateJwt;
