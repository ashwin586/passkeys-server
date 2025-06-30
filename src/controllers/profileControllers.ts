import { Request, Response } from "express";
import bcrypt from "bcrypt";
import User from "../models/users";

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
      console.log(error);
      res.status(500).json({ message: "Something went wrong" });
      return;
    }
  },
};

export default profileControllers;
