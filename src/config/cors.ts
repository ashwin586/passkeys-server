const allowLists = ["http://localhost:3000"];

const corsOptions = {
  origin: (origin: any, callback: any) => {
    if (!origin) return callback(null, true);
    if (allowLists.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};

export default corsOptions;
