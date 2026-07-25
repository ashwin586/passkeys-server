import { Request, Response, NextFunction } from "express";
import helmet from "helmet";

export const securityHeaders = helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
    },
  },
  // 2 years; includeSubDomains + preload for HTTPS deployments
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true,
  },
  frameguard: {
    action: "deny",
  },
  noSniff: true,
  referrerPolicy: {
    policy: "strict-origin-when-cross-origin",
  },
  // Helmet's crossOriginEmbedderPolicy can break some cross-origin flows; keep off for API
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
});

//Permissions-Policy is not set by default helmet — add explicitly.
export const permissionsPolicyHeader = (
  _req: Request,
  res: Response,
  next: NextFunction,
) => {
  res.setHeader(
    "Permissions-Policy",
    [
      "camera=()",
      "microphone=()",
      "geolocation=()",
      "payment=()",
      "usb=()",
      "interest-cohort=()",
    ].join(", "),
  );
  next();
};
