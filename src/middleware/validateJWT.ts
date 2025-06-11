import jwt from "jsonwebtoken";
import { Response, Request, NextFunction } from "express";
import { payloadInterface } from "../types/interface";

const validateJwt = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({ message: "Token Missing" });
      return;
    }
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    req.user = decoded as payloadInterface;
    next();
  } catch (error: any) {
    console.error(error);
    if (error.name === "TokenExpiredError") {
      res.status(401).json({ message: "Token Expired" });
      return;
    } else if (error.name === "JsonWebTokenError") {
      res.status(401).json({ message: "Invalid token" });
      return;
    }

    res.status(500).json({ message: "Internal server error" });
    return;
  }
};

export default validateJwt;
