import jwt from "jsonwebtoken";
import { Response, NextFunction } from "express";
import { payloadInterface, AuthRequest } from "../types/interface";
import User from "../models/users";
import { AUTH_COOKIE_NAME, clearAuthCookie } from "../utils/authCookies";
import { revokeSession } from "../utils/sessions";

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
      res.status(401).json({ message: "Token Missing" });
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    const payload = decoded as payloadInterface;

    if (!payload.sessionId) {
      clearAuthCookie(res);
      res.status(401).json({ message: "Invalid token" });
      return;
    }

    const user: any = await User.findOne({ email: payload.email });

    if (!user) {
      clearAuthCookie(res);
      res.status(401).json({ message: "Invalid token" });
      return;
    }

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

    req.user = payload;
    next();
  } catch (error: any) {
    clearAuthCookie(res);
    if (error.name === "TokenExpiredError") {
      if (token) {
        await markExpiredSessionInactive(token);
      }
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
