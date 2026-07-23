import crypto from "crypto";
import { Request } from "express";
import { AppDefaults } from "../constants/app.constants";
import { HttpHeaders } from "../constants/http.constants";

export const revokeSession = (user: any, sessionId: string) => {
  if (!user || !Array.isArray(user.sessions) || !sessionId) return false;

  let revoked = false;
  user.sessions = user.sessions.map((session: any) => {
    if (session.sessionId !== sessionId) return session;
    revoked = true;
    return {
      ...session.toObject?.(),
      ...session,
      active: false,
      lastSeenAt: new Date(),
    };
  });
  return revoked;
};

export const revokeAllSessions = (user: any) => {
  if (!user || !Array.isArray(user.sessions)) return;
  user.sessions = user.sessions.map((session: any) => ({
    ...session.toObject?.(),
    ...session,
    active: false,
    lastSeenAt: new Date(),
  }));
};

export const createSessionRecord = (req: Request) => {
  const now = new Date();
  return {
    sessionId: crypto.randomUUID(),
    userAgent: req.get(HttpHeaders.USER_AGENT) || AppDefaults.UNKNOWN_DEVICE,
    ipAddress:
      req.ip ||
      (req.headers[HttpHeaders.X_FORWARDED_FOR] as string) ||
      AppDefaults.UNKNOWN_IP,
    createdAt: now,
    lastSeenAt: now,
    active: true,
  };
};
