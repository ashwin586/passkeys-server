import mongoose from "mongoose";

const userSettingsSchema = new mongoose.Schema(
  {
    autoLockTimeout: { type: Number, default: 15 },
    clipboardTimer: { type: Number, default: 30 },
    maskSensitiveData: { type: Boolean, default: true },
    securityReminders: { type: Boolean, default: true },
    lockOnClose: { type: Boolean, default: true },
    themePreference: { type: String, default: "System default" },
    notifications: { type: Boolean, default: true },
    generatorLength: { type: Number, default: 18 },
    generatorSymbols: { type: Boolean, default: true },
    generatorNumbers: { type: Boolean, default: true },
    generatorUppercase: { type: Boolean, default: true },
    generatorLowercase: { type: Boolean, default: true },
    language: { type: String, default: "English" },
  },
  { _id: false }
);

const securityMetadataSchema = new mongoose.Schema(
  {
    lastLoginAt: { type: Date, default: null },
    previousLoginAt: { type: Date, default: null },
    lastPasswordUpdatedAt: { type: Date, default: null },
    loginCount: { type: Number, default: 0 },
  },
  { _id: false }
);

const sessionSchema = new mongoose.Schema(
  {
    sessionId: { type: String, required: true },
    userAgent: { type: String, default: "Unknown device" },
    ipAddress: { type: String, default: "Unknown IP" },
    createdAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    active: { type: Boolean, default: true },
  },
  { _id: false }
);

const activitySchema = new mongoose.Schema(
  {
    type: { type: String, required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const userData = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  createdAt: { type: Date, default: Date.now },
  settings: { type: userSettingsSchema, default: () => ({}) },
  securityMetadata: { type: securityMetadataSchema, default: () => ({}) },
  sessions: { type: [sessionSchema], default: [] },
  activity: { type: [activitySchema], default: [] },
});

const User = mongoose.model("users", userData);

export default User;
