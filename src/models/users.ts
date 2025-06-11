import mongoose from "mongoose";

const userData = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("users", userData);

export default User;
