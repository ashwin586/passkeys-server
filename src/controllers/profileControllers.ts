import { Response } from "express";
import User from "../models/users";
import SavedPassword from "../models/savedPasswords";
import { AuthRequest, securitySummaryInterface } from "../types/interface";
import bcrypt from "bcrypt";
import { clearAuthCookie } from "../utils/authCookies";
import { revokeAllSessions } from "../utils/sessions";
import {
  ActivityTypes,
  AppDefaults,
  DefaultUserSettings,
  SettingsFields,
} from "../constants/app.constants";
import { AuthMessages } from "../constants/auth.constants";
import {
  ActivityMessages,
  ErrorMessages,
  SecuritySummaryLabels,
  SuccessMessages,
  csvImportSuccessMessage,
} from "../constants/messages.constants";
import { BcryptConfig } from "../constants/security.constants";
import { HttpStatus } from "../constants/http.constants";

const asPlainObject = (value: any) => {
  if (!value) return {};
  return value.toObject ? value.toObject() : value;
};

const appendActivity = (user: any, type: string, message: string) => {
  const activity = Array.isArray(user.activity) ? user.activity : [];
  activity.unshift({ type, message, createdAt: new Date() });
  user.activity = activity.slice(0, AppDefaults.ACTIVITY_HISTORY_LIMIT);
};

const ensureUserDefaults = (user: any) => {
  user.settings = {
    ...DefaultUserSettings,
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

const buildSecuritySummary = (
  user: any,
  activeSessions: number,
  savedPasswordCount: number,
): securitySummaryInterface => ({
  accountStatus:
    activeSessions > 0
      ? SecuritySummaryLabels.ACCOUNT_PROTECTED
      : SecuritySummaryLabels.ACCOUNT_SESSION_INACTIVE,
  encryptionStatus:
    savedPasswordCount > 0
      ? SecuritySummaryLabels.ENCRYPTION_ZERO_KNOWLEDGE
      : SecuritySummaryLabels.ENCRYPTION_READY,
  passwordHealthScore: null,
  savedPasswordCount,
  weakPasswordCount: 0,
  reusedPasswordCount: 0,
  maskingEnabled: Boolean(user.settings?.maskSensitiveData),
});

const profileControllers = {
  fetchProfile: async (req: AuthRequest, res: Response) => {
    try {
      const userInfo = req.user;
      const user: any = await findCurrentUser(userInfo?.email);
      if (!user) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.USER_NOT_FOUND });
        return;
      }

      ensureUserDefaults(user);
      const activeSessions = user.sessions.filter(
        (session: any) => session.active,
      ).length;
      const savedPasswordCount = await SavedPassword.countDocuments({
        user: user._id,
      });
      const securitySummary = buildSecuritySummary(
        user,
        activeSessions,
        savedPasswordCount,
      );
      const userDetails = {
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
        settings: user.settings,
        securityMetadata: user.securityMetadata,
        activeSessions,
        activity: user.activity.slice(0, AppDefaults.PROFILE_ACTIVITY_PREVIEW_LIMIT),
        securitySummary,
      };
      res.status(HttpStatus.OK).json({ user: userDetails });
      return;
    } catch (error: unknown) {
      console.error("Fetch Profile Error", error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
    }
  },
  updateProfile: async (req: AuthRequest, res: Response) => {
    try {
      const userInfo = req.user;
      const user: any = await findCurrentUser(userInfo?.email);
      if (!user) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.USER_NOT_FOUND });
        return;
      }

      ensureUserDefaults(user);

      const { name, currentPassword, newPassword, vaultSalt } = req.body;
      let hasChanges = false;

      if (name !== undefined && name !== user.name) {
        user.name = name;
        appendActivity(
          user,
          ActivityTypes.PROFILE_UPDATE,
          ActivityMessages.PROFILE_UPDATED,
        );
        hasChanges = true;
      }

      if (currentPassword && newPassword) {
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
          res
            .status(HttpStatus.BAD_REQUEST)
            .json({ message: ErrorMessages.INCORRECT_CURRENT_PASSWORD });
          return;
        }
        if (!vaultSalt) {
          res
            .status(HttpStatus.BAD_REQUEST)
            .json({ message: AuthMessages.VAULT_SALT_REQUIRED });
          return;
        }
        user.password = await bcrypt.hash(newPassword, BcryptConfig.ROUNDS);
        user.vaultSalt = vaultSalt;
        user.securityMetadata.lastPasswordUpdatedAt = new Date();
        revokeAllSessions(user);
        appendActivity(
          user,
          ActivityTypes.PASSWORD_CHANGE,
          ActivityMessages.PASSWORD_CHANGED,
        );
        hasChanges = true;
      }

      if (!hasChanges) {
        res
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: ErrorMessages.NO_CHANGES_TO_SAVE });
        return;
      }

      await user.save();

      if (currentPassword && newPassword) {
        clearAuthCookie(res);
        res.status(HttpStatus.OK).json({
          message: SuccessMessages.PROFILE_UPDATED_RELOGIN,
          sessionRevoked: true,
        });
        return;
      }

      res
        .status(HttpStatus.OK)
        .json({ message: SuccessMessages.PROFILE_UPDATED });
      return;
    } catch (error) {
      console.error(error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.SOMETHING_WENT_WRONG });
      return;
    }
  },

  updateSettings: async (req: AuthRequest, res: Response) => {
    try {
      const userInfo = req.user;
      const user: any = await findCurrentUser(userInfo?.email);
      if (!user) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.USER_NOT_FOUND });
        return;
      }

      ensureUserDefaults(user);

      let hasChanges = false;
      for (const field of SettingsFields) {
        if (Object.prototype.hasOwnProperty.call(req.body, field)) {
          user.settings[field] = req.body[field];
          hasChanges = true;
        }
      }

      if (!hasChanges) {
        res
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: ErrorMessages.NO_SETTINGS_CHANGES });
        return;
      }

      appendActivity(
        user,
        ActivityTypes.SETTINGS_UPDATE,
        ActivityMessages.SETTINGS_UPDATED,
      );
      user.markModified("settings");
      await user.save();
      res.status(HttpStatus.OK).json({
        message: SuccessMessages.SETTINGS_UPDATED,
        settings: user.settings,
      });
      return;
    } catch (error) {
      console.error("Update settings error", error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
      return;
    }
  },

  logoutAllSessions: async (req: AuthRequest, res: Response) => {
    try {
      const userInfo = req.user;
      const user: any = await findCurrentUser(userInfo?.email);
      if (!user) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.USER_NOT_FOUND });
        return;
      }

      ensureUserDefaults(user);
      revokeAllSessions(user);
      appendActivity(
        user,
        ActivityTypes.SESSION_REVOKE,
        ActivityMessages.SESSION_REVOKED_ALL,
      );
      await user.save();

      clearAuthCookie(res);
      res
        .status(HttpStatus.OK)
        .json({ message: SuccessMessages.ALL_SESSIONS_SIGNED_OUT });
      return;
    } catch (error) {
      console.error("Logout all sessions error", error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
      return;
    }
  },

  fetchPasswords: async (req: AuthRequest, res: Response) => {
    try {
      const user = req.user;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.USER_NOT_FOUND });
        return;
      }

      const userPasswords = await SavedPassword.find({ user: userDoc._id });
      const userCredentials = userPasswords.map((credentials) => ({
        id: credentials?._id,
        name: credentials?.name,
        url: credentials.url,
        userName: credentials.userName,
        password: credentials.password,
        iv: credentials.iv,
      }));
      res.status(HttpStatus.OK).json({ passwords: userCredentials });
      return;
    } catch (error) {
      console.error("Fetch Password Error", error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.SOMETHING_WENT_WRONG });
    }
  },

  addPasswords: async (req: AuthRequest, res: Response) => {
    try {
      const { name, password, url, userName, iv } = req.body;
      const user = req.user;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.USER_NOT_FOUND });
        return;
      }

      const appDetails = new SavedPassword({
        user: userDoc._id,
        name,
        url,
        userName,
        iv,
        password,
      });

      await appDetails.save();
      res.status(HttpStatus.CREATED).json({
        message: SuccessMessages.CREDENTIALS_ADDED,
        newData: {
          id: appDetails._id,
          name: appDetails.name,
          url: appDetails.url,
          userName: appDetails.userName,
          password: appDetails.password,
          iv: appDetails.iv,
        },
      });
      return;
    } catch (error) {
      console.error("Add password error", error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
    }
  },

  updatePasswords: async (req: AuthRequest, res: Response) => {
    try {
      const user = req.user;
      const { name, password, url, userName, iv } = req.body;
      const { id } = req.params;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.USER_NOT_FOUND });
        return;
      }

      const updatedDetails = {
        user: userDoc._id,
        name,
        url,
        userName,
        iv,
        password,
      };
      const response = await SavedPassword.findOneAndUpdate(
        { _id: id, user: userDoc._id },
        updatedDetails,
        { new: true },
      );
      if (!response) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.CREDENTIAL_NOT_FOUND });
        return;
      }
      res.status(HttpStatus.OK).json({
        message: SuccessMessages.CREDENTIALS_UPDATED,
        updatedData: {
          id: response?._id,
          name: response?.name,
          userName: response?.userName,
          password: response.password,
          iv: response.iv,
          url: response?.url,
        },
      });
      return;
    } catch (error) {
      console.error("Update password error", error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
    }
  },

  deletePasswords: async (req: AuthRequest, res: Response) => {
    try {
      const { id } = req.params;
      const user = req.user;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.USER_NOT_FOUND });
        return;
      }
      const deleted = await SavedPassword.findOneAndDelete({
        _id: id,
        user: userDoc._id,
      });
      if (!deleted) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.CREDENTIAL_NOT_FOUND });
        return;
      }
      res
        .status(HttpStatus.OK)
        .json({ message: SuccessMessages.CREDENTIAL_DELETED });
      return;
    } catch (error) {
      console.error("Delete password error", error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
    }
  },

  importCSV: async (req: AuthRequest, res: Response) => {
    try {
      const user = req.user;
      const userDoc: any = await findCurrentUser(user?.email);
      if (!userDoc) {
        res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: ErrorMessages.USER_NOT_FOUND });
        return;
      }
      const savedEntries = [];
      let skipped = 0;
      const { csvData } = req.body;
      if (!Array.isArray(csvData)) {
        res
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: ErrorMessages.CSV_DATA_MUST_BE_ARRAY });
        return;
      }
      for (const entry of csvData) {
        if (
          !entry.name ||
          !entry.url ||
          !entry.username ||
          !entry.password ||
          !entry.iv
        ) {
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
        const appDetails = new SavedPassword({
          user: userDoc._id,
          name: entry.name,
          url: entry.url,
          userName: entry.username,
          iv: entry.iv,
          password: entry.password,
        });
        await appDetails.save();
        savedEntries.push({
          id: appDetails._id,
          name: appDetails.name,
          url: appDetails.url,
          userName: appDetails.userName,
          password: appDetails.password,
          iv: appDetails.iv,
        });
      }
      res.status(HttpStatus.OK).json({
        message: csvImportSuccessMessage(savedEntries.length, skipped),
        newData: savedEntries,
      });
    } catch (error) {
      console.error("Import CSV error", error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
    }
  },
};

export default profileControllers;
