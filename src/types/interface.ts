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
