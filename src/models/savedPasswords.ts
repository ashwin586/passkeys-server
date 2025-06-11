import mongoose from "mongoose";

const savedPasswordSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  site: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const SavedPassword = mongoose.model("SavedPassword", savedPasswordSchema);
export default SavedPassword;
