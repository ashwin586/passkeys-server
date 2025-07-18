import { Request, Response } from "express";
import bcrypt from "bcrypt";
import User from "../models/users";
import SavedPassword from "../models/savedPasswords";
import { encrypt } from "../utils/crypto";

const profileControllers = {
  fetchProfile: async (req: Request, res: Response) => {
    try {
      const userInfo = req.user;
      const user = await User.findOne({ email: userInfo?.email });
      const userDetails = {
        name: user?.name,
        email: user?.email,
        createdAt: user?.createdAt,
      };
      res.status(200).json({ user: userDetails });
      return;
    } catch (error: unknown) {
      console.error("profile error", error);
    }
  },

  updateProfile: async (req: Request, res: Response) => {
    try {
      const userInfo = req.user;
      const user = await User.findOne({ email: userInfo?.email });
      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }
      if (req.body.name !== undefined) user.name = req.body.name;

      const { currentPassword, newPassword } = req.body;
      if (currentPassword && newPassword) {
        const isMatch = await bcrypt.compare(currentPassword, user?.password!);
        if (!isMatch) {
          res
            .status(400)
            .json({ message: "Incorrect current password, Try again" });
          return;
        }
        user.password = await bcrypt.hash(newPassword, 10);
      }

      await user.save();
      res.json({ message: "Profile updated successfully" });
      return;
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Something went wrong" });
      return;
    }
  },

  // * * Manage Password controllers
  fetchPasswords: async (req: Request, res: Response) => {
    try {
      const userEmail = req.user;
      const userId = await User.findOne({ email: userEmail });
      const userPasswords = await SavedPassword.find({ user: userId });
      res.status(200).json({ passwords: userPasswords });
      return;
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Something went wrong" });
    }
  },

  addPasswords: async (req: Request, res: Response) => {
    try {
      const { appName, password, url, userName } = req.body;
      const user = req.user;
      const userId = await User.findOne({ email: user?.email });
      const { iv, encryptedData } = encrypt(password);

      const appDetails = new SavedPassword({
        user: userId,
        name: appName,
        url,
        userName,
        iv,
        password: encryptedData,
      });

      await appDetails.save();
      res.status(200).json({ message: "Credentials added successfully" });
      return;
    } catch (error) {
      console.error(error);
    }
  },
  updatePasswords: async (req: Request, res: Response) => {},
  deletePasswords: async (req: Request, res: Response) => {},
};

export default profileControllers;
