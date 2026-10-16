import express from "express";
import authorizeRouter from "./routes/authorize.js";
import permissionsRouter from "./routes/permissions.js";

const app = express();

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());

app.get("/", (_req, res) => {
  res.json({
    status: "OK",
    message: "Authentication & Authorization Service is running",
    endpoints: {
      health: "GET /health",
      authorize: "POST /authorize (requires JSON: { access_token or user_id, method, path })",
      logs: "GET /authorize/logs",
      permissions: {
        list: "GET /permissions?user_id=xyz",
        create: "POST /permissions (JSON: { user_id, action, resource, effect })",
        update: "PATCH /permissions/:id",
        delete: "DELETE /permissions/:id",
      },
    },
  });
});

app.get("/health", (_req, res) => {
  res.json({ status: "OK" });
});

app.use("/authorize", authorizeRouter);
app.use("/permissions", permissionsRouter);

export default app;
