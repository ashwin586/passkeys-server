import crypto from "crypto";
import { Request } from "express";

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
    userAgent: req.get("user-agent") || "Unknown device",
    ipAddress:
      req.ip || (req.headers["x-forwarded-for"] as string) || "Unknown IP",
    createdAt: now,
    lastSeenAt: now,
    active: true,
  };
};
