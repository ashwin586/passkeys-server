import mongoose from "mongoose";

export default async function mongoDb() {
  try {
    const uri = process.env.MONGODB_URI || "";
    if (!uri) {
      throw new Error("MONGODB_URI is not defined or empty");
    }
    await mongoose.connect(uri);
    console.log("Connected to DB");
  } catch (error: any) {
    console.error(error);
  }
}
