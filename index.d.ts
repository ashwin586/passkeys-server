import { payloadInterface } from "./src/types/interface";
import { JwtPayload } from "jsonwebtoken";

declare global {
  namespace Express {
    interface Request {
      user?: payloadInterface | JwtPayload;
    }
  }
}
