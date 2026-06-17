import { Response } from "express";
import User from "../models/users";
import SavedPassword from "../models/savedPasswords";
import { decrypt, encrypt } from "../utils/crypto";
import { calculateStrength } from "../utils/passwordStrength";
import { AuthRequest, securitySummaryInterface } from "../types/interface";
import bcrypt from "bcrypt";

const DEFAULT_SETTINGS = {
  autoLockTimeout: 15,
  clipboardTimer: 30,
  maskSensitiveData: true,
  securityReminders: true,
  lockOnClose: true,
  themePreference: "System default",
  notifications: true,
  generatorLength: 18,
  generatorSymbols: true,
  generatorNumbers: true,
  generatorUppercase: true,
  generatorLowercase: true,
  language: "English",
};

const asPlainObject = (value: any) => {
  if (!value) return {};
  return value.toObject ? value.toObject() : value;
};

const appendActivity = (user: any, type: string, message: string) => {
  const activity = Array.isArray(user.activity) ? user.activity : [];
  activity.unshift({ type, message, createdAt: new Date() });
  user.activity = activity.slice(0, 20);
};

const ensureUserDefaults = (user: any) => {
  user.settings = {
    ...DEFAULT_SETTINGS,
    ...asPlainObject(user.settings),
  };
  user.securityMetadata = {
    lastLoginAt: null,
    previousLoginAt: null,
    lastPasswordUpdatedAt: null,
    loginCount: 0,
    ...asPlainObject(user.securityMetadata),
  };
  user.sessions = Array.isArray(user.sessions) ? user.sessions : [];
  user.activity = Array.isArray(user.activity) ? user.activity : [];
};

const findCurrentUser = async (email?: string) => {
  if (!email) return null;
  return User.findOne({ email });
};

const buildSecuritySummary = async (
  user: any,
  activeSessions: number
): Promise<securitySummaryInterface> => {
  const savedPasswords = await SavedPassword.find({ user: user._id });
  const decryptedPasswords = savedPasswords.map((entry) =>
    decrypt(entry.password, entry.iv)
  );
  const scores = decryptedPasswords.map((password) =>
    calculateStrength(password)
  );
  const passwordHealthScore =
    scores.length > 0
      ? Math.round(scores.reduce((total, score) => total + score, 0) / scores.length)
      : null;
  const weakPasswordCount = scores.filter((score) => score < 40).length;

  const passwordUsage = new Map<string, number>();
  for (const password of decryptedPasswords) {
    passwordUsage.set(password, (passwordUsage.get(password) || 0) + 1);
  }
  const reusedPasswordCount = [...passwordUsage.values()].filter(
    (count) => count > 1
  ).length;

  return {
    accountStatus: activeSessions > 0 ? "Protected" : "Session inactive",
    encryptionStatus:
      savedPasswords.length > 0 ? "Active" : "Ready (no vault entries)",
    passwordHealthScore,
    savedPasswordCount: savedPasswords.length,
    weakPasswordCount,
    reusedPasswordCount,
    maskingEnabled: Boolean(user.settings?.maskSensitiveData),
  };
};

const profileControllers = {
  fetchProfile: async (req: AuthRequest, res: Response) => {
    try {
      const userInfo = req.user;
      const user: any = await findCurrentUser(userInfo?.email);
      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      ensureUserDefaults(user);
      const activeSessions = user.sessions.filter(
        (session: any) => session.active
      ).length;
      const securitySummary = await buildSecuritySummary(user, activeSessions);
      const userDetails = {
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
        settings: user.settings,
        securityMetadata: user.securityMetadata,
        activeSessions,
        activity: user.activity.slice(0, 10),
        securitySummary,
      };
      res.status(200).json({ user: userDetails });
      return;
    } catch (error: unknown) {
      console.error("Fetch Profile Error", error);
      res.status(500).json({ message: "Internal Server Error" });
    }
  },
  updateProfile: async (req: AuthRequest, res: Response) => {
    try {
      const userInfo = req.user;
      const user: any = await findCurrentUser(userInfo?.email);
      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      ensureUserDefaults(user);

      const { name, currentPassword, newPassword } = req.body;
      let hasChanges = false;

      if (name !== undefined && name !== user.name) {
        user.name = name;
        appendActivity(user, "profile_update", "Profile details updated");
        hasChanges = true;
      }

      if (currentPassword && newPassword) {
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
          res
            .status(400)
            .json({ message: "Incorrect current password, Try again" });
          return;
        }
        user.password = await bcrypt.hash(newPassword, 10);
        user.securityMetadata.lastPasswordUpdatedAt = new Date();
        appendActivity(user, "password_change", "Password changed successfully");
        hasChanges = true;
      }

      if (!hasChanges) {
        res.status(400).json({ message: "No changes to save" });
        return;
      }

      await user.save();
      res.status(200).json({ message: "Profile updated successfully" });
      return;
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Something went wrong" });
      return;
    }
  },

  updateSettings: async (req: AuthRequest, res: Response) => {
    try {
      const userInfo = req.user;
      const user: any = await findCurrentUser(userInfo?.email);
      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      ensureUserDefaults(user);

      const settingsFields = [
        "autoLockTimeout",
        "clipboardTimer",
        "maskSensitiveData",
        "securityReminders",
        "lockOnClose",
        "themePreference",
        "notifications",
        "generatorLength",
        "generatorSymbols",
        "generatorNumbers",
        "generatorUppercase",
        "generatorLowercase",
        "language",
      ];

      let hasChanges = false;
      for (const field of settingsFields) {
        if (Object.prototype.hasOwnProperty.call(req.body, field)) {
          user.settings[field] = req.body[field];
          hasChanges = true;
        }
      }

      if (!hasChanges) {
        res.status(400).json({ message: "No settings changes provided" });
        return;
      }

      appendActivity(user, "settings_update", "Security preferences updated");
      user.markModified("settings");
      await user.save();
      res.status(200).json({
        message: "Settings updated successfully",
        settings: user.settings,
      });
      return;
    } catch (error) {
      console.error("Update settings error", error);
      res.status(500).json({ message: "Internal Server Error" });
      return;
    }
  },

  logoutAllSessions: async (req: AuthRequest, res: Response) => {
    try {
      const userInfo = req.user;
      const user: any = await findCurrentUser(userInfo?.email);
      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      ensureUserDefaults(user);
      user.sessions = user.sessions.map((session: any) => ({
        ...session.toObject?.(),
        ...session,
        active: false,
        lastSeenAt: new Date(),
      }));
      appendActivity(user, "session_revoke", "Signed out from all devices");
      await user.save();

      res.status(200).json({ message: "All sessions signed out successfully" });
      return;
    } catch (error) {
      console.error("Logout all sessions error", error);
      res.status(500).json({ message: "Internal Server Error" });
      return;
    }
  },

  fetchPasswords: async (req: AuthRequest, res: Response) => {
    try {
      const user = req.user;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      const userPasswords = await SavedPassword.find({ user: userDoc._id });
      const userCredentials = userPasswords.map((credentials) => ({
        id: credentials?._id,
        name: credentials?.name,
        url: credentials.url,
        userName: credentials.userName,
        password: decrypt(credentials.password, credentials.iv),
      }));
      res.status(200).json({ passwords: userCredentials });
      return;
    } catch (error) {
      console.error("Fetch Password Error", error);
      res.status(500).json({ message: "Something went wrong" });
    }
  },

  addPasswords: async (req: AuthRequest, res: Response) => {
    try {
      const { name, password, url, userName } = req.body;
      const user = req.user;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      const { iv, encryptedData } = encrypt(password);

      const appDetails = new SavedPassword({
        user: userDoc._id,
        name,
        url,
        userName,
        iv,
        password: encryptedData,
      });

      await appDetails.save();
      res.status(201).json({
        message: "Credentials added successfully",
        newData: {
          id: appDetails._id,
          name: appDetails.name,
          url: appDetails.url,
          userName: appDetails.userName,
          password: decrypt(appDetails.password, appDetails.iv),
        },
      });
      return;
    } catch (error) {
      console.error("Add password error", error);
      res.status(500).json({ message: "Internal Server Error" });
    }
  },

  updatePasswords: async (req: AuthRequest, res: Response) => {
    try {
      const user = req.user;
      const { name, password, url, userName } = req.body;
      const { id } = req.params;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      const { iv, encryptedData } = encrypt(password);
      const updatedDetails = {
        user: userDoc._id,
        name,
        url,
        userName,
        iv,
        password: encryptedData,
      };
      const response = await SavedPassword.findOneAndUpdate(
        { _id: id, user: userDoc._id },
        updatedDetails,
        { new: true }
      );
      if (!response) {
        res.status(404).json({ message: "Credential not found" });
        return;
      }
      res.status(200).json({
        message: "Updated Credentials",
        updatedData: {
          id: response?._id,
          name: response?.name,
          userName: response?.userName,
          password: decrypt(response.password, response.iv),
          url: response?.url,
        },
      });
      return;
    } catch (error) {
      console.error("Update password error", error);
      res.status(500).json({ message: "Internal Server Error" });
    }
  },

  deletePasswords: async (req: AuthRequest, res: Response) => {
    try {
      const { id } = req.params;
      const user = req.user;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res.status(404).json({ message: "User not found" });
        return;
      }
      const deleted = await SavedPassword.findOneAndDelete({
        _id: id,
        user: userDoc._id,
      });
      if (!deleted) {
        res.status(404).json({ message: "Credential not found" });
        return;
      }
      res.status(200).json({ message: "Credential deleted successfully" });
      return;
    } catch (error) {
      console.error("Delete password error", error);
      res.status(500).json({ message: "Internal Server Error" });
    }
  },

  importCSV: async (req: AuthRequest, res: Response) => {
    try {
      const user = req.user;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res.status(404).json({ message: "User not found" });
        return;
      }
      const savedEntries = [];
      let skipped = 0;
      const { csvData } = req.body;
      if (!Array.isArray(csvData)) {
        res.status(400).json({ message: "csvData must be an array" });
        return;
      }
      for (const entry of csvData) {
        if (!entry.name || !entry.url || !entry.username || !entry.password) {
          skipped++;
          continue;
        }
        const existing = await SavedPassword.findOne({
          user: userDoc._id,
          url: entry.url,
          userName: entry.username,
        });
        if (existing) {
          skipped++;
          continue;
        }
        const { iv, encryptedData } = encrypt(entry.password);
        const appDetails = new SavedPassword({
          user: userDoc._id,
          name: entry.name,
          url: entry.url,
          userName: entry.username,
          iv,
          password: encryptedData,
        });
        await appDetails.save();
        savedEntries.push({
          id: appDetails._id,
          name: appDetails.name,
          url: appDetails.url,
          userName: appDetails.userName,
          password: decrypt(appDetails.password, appDetails.iv),
        });
      }
      res.status(200).json({
        message: `${savedEntries.length} imported successfully${skipped > 0 ? `, ${skipped} skipped (duplicates or missing fields)` : ""}`,
        newData: savedEntries,
      });
    } catch (error) {
      console.error("Import CSV error", error);
      res.status(500).json({ message: "Internal Server Error" });
    }
  },
};

export default profileControllers;
