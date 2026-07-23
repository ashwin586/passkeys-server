import rateLimit from "express-rate-limit";
import { Request } from "express";
import { ErrorMessages } from "../constants/messages.constants";
import {
  RateLimitMax,
  RateLimitWindows,
} from "../constants/security.constants";
import { AppDefaults } from "../constants/app.constants";

const authRateLimitMessage = {
  message: ErrorMessages.RATE_LIMIT_EXCEEDED,
};

/** Stricter IP throttle for login. */
export const loginIpLimiter = rateLimit({
  windowMs: RateLimitWindows.FIFTEEN_MINUTES_MS,
  max: RateLimitMax.LOGIN_IP,
  standardHeaders: true,
  legacyHeaders: false,
  message: authRateLimitMessage,
});

/**
 * Account-level login throttle (normalized email + IP).
 * Slows credential stuffing against a specific account from one source.
 */
export const loginAccountLimiter = rateLimit({
  windowMs: RateLimitWindows.FIFTEEN_MINUTES_MS,
  max: RateLimitMax.LOGIN_ACCOUNT,
  standardHeaders: true,
  legacyHeaders: false,
  message: authRateLimitMessage,
  keyGenerator: (req: Request) => {
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();
    const ip = req.ip || req.socket.remoteAddress || AppDefaults.FALLBACK_IP_KEY;
    return `${ip}:${email || AppDefaults.MISSING_EMAIL_KEY}`;
  },
});

/** Register IP throttle — lower than login to limit mass account creation. */
export const registerIpLimiter = rateLimit({
  windowMs: RateLimitWindows.ONE_HOUR_MS,
  max: RateLimitMax.REGISTER_IP,
  standardHeaders: true,
  legacyHeaders: false,
  message: authRateLimitMessage,
});

/** Salt endpoint throttle — prevents salt-fetch flooding. */
export const saltIpLimiter = rateLimit({
  windowMs: RateLimitWindows.FIFTEEN_MINUTES_MS,
  max: RateLimitMax.SALT_IP,
  standardHeaders: true,
  legacyHeaders: false,
  message: authRateLimitMessage,
});
