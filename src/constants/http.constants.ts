//  HTTP status codes used by the API. 
export const HttpStatus = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  NOT_FOUND: 404,
  CONFLICT: 409,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
} as const;

// Common HTTP header / authorization scheme constants.
export const HttpHeaders = {
  AUTHORIZATION: "authorization",
  USER_AGENT: "user-agent",
  X_FORWARDED_FOR: "x-forwarded-for",
} as const;

export const AuthScheme = {
  BEARER_PREFIX: "Bearer ",
} as const;
