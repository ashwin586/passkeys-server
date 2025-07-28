import { Types } from "mongoose";

export interface userInterface {
  name: string;
  email: string;
  password: string;
  createdAt: Date;
}

export interface authInterface {
  email: string;
  password: string;
}

export interface payloadInterface {
  email: string;
  role: string;
  iat: number;
  exp: number;
}

export interface userPasswordsInterface {
  id: string;
  name: string;
  url: string;
  userName: string;
  password: string;
  iv: string;
}
