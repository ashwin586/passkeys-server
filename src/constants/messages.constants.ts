// Shared API response messages (success and error).
export const ErrorMessages = {
  INTERNAL_SERVER_ERROR: "Internal Server Error",
  INTERNAL_SERVER_ERROR_LOWER: "Internal server error",
  SOMETHING_WENT_WRONG: "Something went wrong",
  USER_NOT_FOUND: "User not found",
  CREDENTIAL_NOT_FOUND: "Credential not found",
  INVALID_REQUEST_PAYLOAD: "Invalid request payload",
  NO_CHANGES_TO_SAVE: "No changes to save",
  NO_SETTINGS_CHANGES: "No settings changes provided",
  INCORRECT_CURRENT_PASSWORD: "Incorrect current password, Try again",
  CSV_DATA_MUST_BE_ARRAY: "csvData must be an array",
  RATE_LIMIT_EXCEEDED: "Too many attempts. Please try again later.",
  CORS_NOT_ALLOWED: "Not allowed by CORS",
} as const;

export const SuccessMessages = {
  PROFILE_UPDATED: "Profile updated successfully",
  PROFILE_UPDATED_RELOGIN:
    "Profile updated successfully. Please sign in again.",
  SETTINGS_UPDATED: "Settings updated successfully",
  ALL_SESSIONS_SIGNED_OUT: "All sessions signed out successfully",
  CREDENTIALS_ADDED: "Credentials added successfully",
  CREDENTIALS_UPDATED: "Updated Credentials",
  CREDENTIAL_DELETED: "Credential deleted successfully",
} as const;

export const ActivityMessages = {
  PROFILE_UPDATED: "Profile details updated",
  PASSWORD_CHANGED: "Password changed successfully",
  SETTINGS_UPDATED: "Security preferences updated",
  SESSION_REVOKED_ALL: "Signed out from all devices",
} as const;

export const SecuritySummaryLabels = {
  ACCOUNT_PROTECTED: "Protected",
  ACCOUNT_SESSION_INACTIVE: "Session inactive",
  ENCRYPTION_ZERO_KNOWLEDGE: "Client-side zero-knowledge",
  ENCRYPTION_READY: "Ready (no vault entries)",
} as const;

export const csvImportSuccessMessage = (
  savedCount: number,
  skippedCount: number,
): string =>
  `${savedCount} imported successfully${
    skippedCount > 0
      ? `, ${skippedCount} skipped (duplicates or missing fields)`
      : ""
  }`;
