import { Request, Response } from "express";
import User from "../models/users";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { userInterface, authInterface } from "../types/interface";

const asPlainObject = (value: any) => {
  if (!value) return {};
  return value.toObject ? value.toObject() : value;
};

const dummySaltForEmail = (email: string) =>
  crypto
    .createHash("sha256")
    .update(`vault-salt-dummy:${email.toLowerCase()}`)
    .digest("hex")
    .slice(0, 32);

const authControllers = {
  getSalt: async (req: Request, res: Response): Promise<void> => {
    try {
      const email = String(req.query.email || "")
        .trim()
        .toLowerCase();
      if (!email) {
        res.status(400).json({ message: "Email is required" });
        return;
      }

      const existingUser = await User.findOne({ email });
      res.status(200).json({
        salt: existingUser?.vaultSalt || dummySaltForEmail(email),
      });
      return;
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Internal Server Error" });
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

      if (!existingUser) {
        res.status(404).json({ message: "User not found." });
        return;
      }

      const isCredentials = await bcrypt.compare(
        password,
        existingUser?.password,
      );
      if (!isCredentials) {
        res.status(401).json({ message: "Incorrect email or password." });
        return;
      }

      const now = new Date();
      const sessionId = crypto.randomUUID();
      const previousLoginAt = existingUser?.securityMetadata?.lastLoginAt || null;
      existingUser.securityMetadata = {
        ...asPlainObject(existingUser.securityMetadata),
        previousLoginAt,
        lastLoginAt: now,
        loginCount: (existingUser?.securityMetadata?.loginCount || 0) + 1,
      };
      existingUser.sessions = [
        {
          sessionId,
          userAgent: req.get("user-agent") || "Unknown device",
          ipAddress:
            req.ip || (req.headers["x-forwarded-for"] as string) || "Unknown IP",
          createdAt: now,
          lastSeenAt: now,
          active: true,
        },
        ...(existingUser.sessions || []),
      ].slice(0, 20);
      existingUser.activity = [
        {
          type: "login",
          message: "Successful login",
          createdAt: now,
        },
        ...(existingUser.activity || []),
      ].slice(0, 20);

      await existingUser.save();

      const payload = {
        email: existingUser?.email,
        role: "user",
        sessionId,
      };
      const accesToken = jwt.sign(payload, process.env.JWT_SECRET!, {
        expiresIn: "30m",
      });

      res.status(200).json({
        message: "Login Successful",
        token: accesToken,
        vaultSalt: existingUser.vaultSalt,
      });
      return;
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Internal Server Error" });
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
        res.status(400).json({ message: "vaultSalt is required" });
        return;
      }

      const existingUser = await User.findOne({ email: email });
      if (existingUser) {
        res
          .status(409)
          .json({ message: "Email already registered, Please login." });
        return;
      }
      const hashedPassword = await bcrypt.hash(password, 10);
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
      res.status(201).json({ message: "User added successfuly" });
      return;
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Internal Server Error" });
      return;
    }
  },
};

export default authControllers;
