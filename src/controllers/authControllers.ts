import { Request, Response } from "express";
import User from "../models/users";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { userInterface, authInterface, AuthRequest } from "../types/interface";
import {
  clearAuthCookie,
  getJwtExpiresIn,
  setAuthCookie,
} from "../utils/authCookies";
import {
  createSessionRecord,
  revokeSession,
} from "../utils/sessions";
import { AuthMessages, AuthRole } from "../constants/auth.constants";
import { ErrorMessages } from "../constants/messages.constants";
import { ActivityTypes, AppDefaults } from "../constants/app.constants";
import {
  BcryptConfig,
  CryptoLengths,
  DummySalt,
} from "../constants/security.constants";
import { HttpStatus } from "../constants/http.constants";

const asPlainObject = (value: any) => {
  if (!value) return {};
  return value.toObject ? value.toObject() : value;
};

const dummySaltForEmail = (email: string) =>
  crypto
    .createHash("sha256")
    .update(`${DummySalt.PREFIX}${email.toLowerCase()}`)
    .digest("hex")
    .slice(0, CryptoLengths.VAULT_SALT_HEX);

const authControllers = {
  getSalt: async (req: Request, res: Response): Promise<void> => {
    try {
      const email = String(req.query.email || "")
        .trim()
        .toLowerCase();
      if (!email) {
        res
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: AuthMessages.EMAIL_REQUIRED });
        return;
      }

      const existingUser = await User.findOne({ email });
      res.status(HttpStatus.OK).json({
        salt: existingUser?.vaultSalt || dummySaltForEmail(email),
      });
      return;
    } catch (error) {
      console.error(error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
      return;
    }
  },

  login: async (
    req: Request<{}, {}, authInterface>,
    res: Response,
  ): Promise<void> => {
    const { email, password } = req.body;
    try {
      const existingUser: (userInterface & any) | null = await User.findOne({
        email: email,
      });

      const hashToCompare =
        existingUser?.password || process.env.DUMMY_PASSWORD_HASH!;
      const isCredentials = await bcrypt.compare(password, hashToCompare);

      if (!existingUser || !isCredentials) {
        res
          .status(HttpStatus.UNAUTHORIZED)
          .json({ message: AuthMessages.INVALID_CREDENTIALS });
        return;
      }

      const now = new Date();
      const session = createSessionRecord(req);
      const previousLoginAt =
        existingUser?.securityMetadata?.lastLoginAt || null;
      existingUser.securityMetadata = {
        ...asPlainObject(existingUser.securityMetadata),
        previousLoginAt,
        lastLoginAt: now,
        loginCount: (existingUser?.securityMetadata?.loginCount || 0) + 1,
      };
      existingUser.sessions = [session, ...(existingUser.sessions || [])].slice(
        0,
        AppDefaults.SESSION_HISTORY_LIMIT,
      );
      existingUser.activity = [
        {
          type: ActivityTypes.LOGIN,
          message: AuthMessages.ACTIVITY_SUCCESSFUL_LOGIN,
          createdAt: now,
        },
        ...(existingUser.activity || []),
      ].slice(0, AppDefaults.ACTIVITY_HISTORY_LIMIT);

      await existingUser.save();

      const payload = {
        email: existingUser?.email,
        role: AuthRole.USER,
        sessionId: session.sessionId,
      };
      const accessToken = jwt.sign(payload, process.env.JWT_SECRET!, {
        expiresIn: getJwtExpiresIn(),
      } as jwt.SignOptions);

      setAuthCookie(res, accessToken);

      res.status(HttpStatus.OK).json({
        message: AuthMessages.LOGIN_SUCCESS,
        vaultSalt: existingUser.vaultSalt,
        expiresIn: getJwtExpiresIn(),
      });
      return;
    } catch (error) {
      console.error(error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
      return;
    }
  },

  logout: async (req: AuthRequest, res: Response): Promise<void> => {
    try {
      const email = req.user?.email;
      const sessionId = req.user?.sessionId;

      if (email && sessionId) {
        const user: any = await User.findOne({ email });
        if (user) {
          revokeSession(user, sessionId);
          await user.save();
        }
      }

      clearAuthCookie(res);
      res
        .status(HttpStatus.OK)
        .json({ message: AuthMessages.LOGOUT_SUCCESS });
      return;
    } catch (error) {
      console.error(error);
      clearAuthCookie(res);
      res
        .status(HttpStatus.OK)
        .json({ message: AuthMessages.LOGOUT_SUCCESS });
      return;
    }
  },

  register: async (
    req: Request<{}, {}, authInterface>,
    res: Response,
  ): Promise<void> => {
    const { email, password, vaultSalt } = req.body;

    try {
      if (!vaultSalt) {
        res
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: AuthMessages.VAULT_SALT_REQUIRED });
        return;
      }

      const existingUser = await User.findOne({ email: email });
      if (existingUser) {
        // Burn similar work so existence is harder to infer from timing.
        await bcrypt.hash(password, BcryptConfig.ROUNDS);
        res
          .status(HttpStatus.CREATED)
          .json({ message: AuthMessages.REGISTER_SUCCESS });
        return;
      }

      const hashedPassword = await bcrypt.hash(password, BcryptConfig.ROUNDS);
      const name = email.split("@")[0];
      const newUser = new User({
        name,
        email,
        password: hashedPassword,
        vaultSalt,
        securityMetadata: {
          lastLoginAt: null,
          previousLoginAt: null,
          lastPasswordUpdatedAt: null,
          loginCount: 0,
        },
      });
      await newUser.save();
      res
        .status(HttpStatus.CREATED)
        .json({ message: AuthMessages.REGISTER_SUCCESS });
      return;
    } catch (error) {
      console.error(error);
      res
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: ErrorMessages.INTERNAL_SERVER_ERROR });
      return;
    }
  },
};

export default authControllers;
