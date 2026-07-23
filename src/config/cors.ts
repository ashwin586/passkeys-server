import { CorsDefaults } from "../constants/app.constants";
import { ErrorMessages } from "../constants/messages.constants";

const allowLists = CorsDefaults.ALLOWED_ORIGINS;

const corsOptions = {
  origin: (origin: any, callback: any) => {
    if (!origin) return callback(null, true);
    if (allowLists.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(ErrorMessages.CORS_NOT_ALLOWED));
    }
  },
  credentials: true,
};

export default corsOptions;
