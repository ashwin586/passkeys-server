import { Types } from "mongoose";
import { Request } from "express";

export interface userInterface {
  name: string;
  email: string;
  password: string;
  vaultSalt: string;
  createdAt: Date;
  settings?: userSettingsInterface;
  securityMetadata?: securityMetadataInterface;
  sessions?: userSessionInterface[];
  activity?: userActivityInterface[];
}

export interface authInterface {
  email: string;
  password: string;
  vaultSalt?: string;
}

export interface payloadInterface {
  email: string;
  role: string;
  sessionId: string;
  iat: number;
  exp: number;
}

export interface userSettingsInterface {
  autoLockTimeout: number;
  clipboardTimer: number;
  maskSensitiveData: boolean;
  securityReminders: boolean;
  lockOnClose: boolean;
  themePreference: string;
  notifications: boolean;
  generatorLength: number;
  generatorSymbols: boolean;
  generatorNumbers: boolean;
  generatorUppercase: boolean;
  generatorLowercase: boolean;
  language: string;
}

export interface securityMetadataInterface {
  lastLoginAt: Date | null;
  previousLoginAt: Date | null;
  lastPasswordUpdatedAt: Date | null;
  loginCount: number;
}

export interface userSessionInterface {
  sessionId: string;
  userAgent: string;
  ipAddress: string;
  createdAt: Date;
  lastSeenAt: Date;
  active: boolean;
}

export interface userActivityInterface {
  type: string;
  message: string;
  createdAt: Date;
}

export interface securitySummaryInterface {
  accountStatus: string;
  encryptionStatus: string;
  passwordHealthScore: number | null;
  savedPasswordCount: number;
  weakPasswordCount: number;
  reusedPasswordCount: number;
  maskingEnabled: boolean;
}

export interface userPasswordsInterface {
  id: string;
  name: string;
  url: string;
  userName: string;
  password: string;
  iv: string;
}

export interface AuthRequest extends Request {
  user?: any;
}
