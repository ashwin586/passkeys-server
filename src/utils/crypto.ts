import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

const algorithm = process.env.ENCRYPTION_ALGORITHM!;
const key = Buffer.from(process.env.ENCRYPTION_KEY!, "hex");
const iv = crypto.randomBytes(16);

export function encrypt(password: string) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(password, "utf-8", "hex");
  encrypted += cipher.final("hex");
  return { iv: iv.toString("hex"), encryptedData: encrypted };
}

export function decrypt(encryptedData: string, ivHex: string) {
  const decipher = crypto.createDecipheriv(
    algorithm,
    key,
    Buffer.from(ivHex, "hex")
  );
  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
