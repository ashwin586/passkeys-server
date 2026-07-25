import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import mongoDb from "./config/mongoDB";
import routes from "./routes/routes";
import corsOptions from "./config/cors";
import { assertJwtSecret } from "./utils/authCookies";
import {
  permissionsPolicyHeader,
  securityHeaders,
} from "./middleware/securityHeaders";

assertJwtSecret();

const app = express();

mongoDb();

app.use(securityHeaders);
app.use(permissionsPolicyHeader);
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

app.use("/", routes);

const server = app.listen(process.env.PORT, () => {
  console.log("Server started.");
});

process.on("SIGINT", () => {
  server.close(() => {
    console.log("Server closed on SIGINT");
    process.exit(0);
  });
});

process.on("SIGTERM", () => {
  server.close(() => {
    console.log("Server closed on SIGTERM");
    process.exit(0);
  });
});
