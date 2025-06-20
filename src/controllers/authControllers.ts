import { Request, Response } from "express";
import User from "../models/users";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { userInterface, authInterface } from "../types/interface";

const authControllers = {
  login: async (
    req: Request<{}, {}, authInterface>,
    res: Response
  ): Promise<void> => {
    const { email, password } = req.body;
    try {
      const existingUser: userInterface | null = await User.findOne({
        email: email,
      });

      if (!existingUser) {
        res.status(404).json({ message: "User not found." });
        return;
      }

      const isCredentials = await bcrypt.compare(
        password,
        existingUser?.password
      );
      if (!isCredentials) {
        res.status(401).json({ message: "Incorrect email or password." });
        return;
      }

      const payload = {
        email: existingUser?.email,
        role: "user",
      };
      const accesToken = jwt.sign(payload, process.env.JWT_SECRET!, {
        expiresIn: "1m",
      });
      const refreshToken = jwt.sign({ email }, process.env.JWT_REFRESH!, {
        expiresIn: "2m",
      });
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 2 * 60 * 1000,
      });
      res.status(200).json({ message: "Login Successful", token: accesToken });
      return;
    } catch (error) {
      console.error(error);
    }
  },

  register: async (
    req: Request<{}, {}, authInterface>,
    res: Response
  ): Promise<void> => {
    const { email, password } = req.body;
    try {
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

  googleSignIn: async (req: Request, res: Response) => {},

  refreshToken: async (req: Request, res: Response) => {
    try {
      const refreshToken = req.cookies.refreshToken;
      if (!refreshToken) {
        res.status(401).json({ message: "Token Expired" });
        return;
      }
      const payload = jwt.verify(
        refreshToken,
        process.env.JWT_REFRESH!
      ) as jwt.JwtPayload;
      const email = payload?.email;

      const newAccessToken = jwt.sign({ email }, process.env.JWT_SECRET!, {
        expiresIn: "1m",
      });

      res.status(200).json({ token: newAccessToken });
      return;
    } catch (error) {
      console.error(error);
      res.status(403).json({ message: "Invalid or expired refresh token" });
      return;
    }
  },

  fetchProfile: async (req: Request, res: Response) => {
    try {
      const userInfo = req.user;
      const user = await User.findOne({ email: userInfo?.email });
      res.status(200).json({ user: user });
      return;
    } catch (error: unknown) {
      console.error("profile error", error);
    }
  },
};

export default authControllers;
