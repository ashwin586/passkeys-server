import { CookieOptions, Response } from "express";
import {
  AuthCookie,
  AuthMessages,
  JwtDefaults,
} from "../constants/auth.constants";

export const AUTH_COOKIE_NAME = AuthCookie.NAME;

export const getJwtExpiresIn = (): string =>
  process.env.JWT_EXPIRES_IN || JwtDefaults.EXPIRES_IN;

const isProduction = process.env.NODE_ENV === "production";

/**
 * Cross-origin SPA (e.g. :3000 → :5000) requires SameSite=None and Secure.
 * Secure cookies are allowed on localhost in modern browsers.
 */
const getCookieOptions = (maxAge?: number): CookieOptions => {
  const sameSiteEnv = (
    process.env.COOKIE_SAMESITE || AuthCookie.DEFAULT_SAMESITE
  ).toLowerCase();
  const sameSite: CookieOptions["sameSite"] =
    sameSiteEnv === "strict" || sameSiteEnv === "lax" || sameSiteEnv === "none"
      ? sameSiteEnv
      : AuthCookie.DEFAULT_SAMESITE;

  // SameSite=None requires Secure. Default Secure=true so cross-origin SPA auth works
  // on localhost and in production. Override with COOKIE_SECURE=false only if needed.
  const secureEnv = process.env.COOKIE_SECURE;
  const secure =
    sameSite === "none"
      ? true
      : secureEnv === "false"
        ? false
        : secureEnv === "true" || isProduction;

  return {
    httpOnly: true,
    secure,
    sameSite,
    path: AuthCookie.PATH,
    maxAge: maxAge ?? JwtDefaults.ACCESS_TOKEN_MAX_AGE_MS,
  };
};

export const setAuthCookie = (res: Response, token: string) => {
  res.cookie(AUTH_COOKIE_NAME, token, getCookieOptions());
};

export const clearAuthCookie = (res: Response) => {
  res.clearCookie(AUTH_COOKIE_NAME, {
    ...getCookieOptions(0),
    maxAge: 0,
  });
};

export const assertJwtSecret = () => {
  const secret = process.env.JWT_SECRET || "";
  if (secret.length < JwtDefaults.MIN_SECRET_LENGTH) {
    throw new Error(AuthMessages.JWT_SECRET_TOO_SHORT);
  }
};
