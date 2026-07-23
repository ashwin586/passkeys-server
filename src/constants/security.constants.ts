// Security, crypto payload shapes, and rate-limit tuning.
export const CryptoLengths = {
  AUTH_HASH_HEX: 64,
  VAULT_SALT_HEX: 32,
  IV_HEX: 24,
  CIPHERTEXT_HEX_MIN: 32,
  CIPHERTEXT_HEX_MAX: 8192,
} as const;

export const BcryptConfig = {
  ROUNDS: 10,
} as const;

export const DummySalt = {
  PREFIX: "vault-salt-dummy:",
} as const;

export const RateLimitWindows = {
  FIFTEEN_MINUTES_MS: 15 * 60 * 1000,
  ONE_HOUR_MS: 60 * 60 * 1000,
} as const;

export const RateLimitMax = {
  LOGIN_IP: 20,
  LOGIN_ACCOUNT: 10,
  REGISTER_IP: 10,
  SALT_IP: 40,
} as const;

export const HexPattern = /^[a-f0-9]+$/i;
