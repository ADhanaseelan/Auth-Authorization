import { Router } from "express";
import { authorize } from "../services/permissionService.js";
import { validateAccessToken } from "../auth/validateToken.js";
import db from "../database/db.js";

const router = Router();

router.get("/", (_req, res) => {
  res.json({
    message: "/authorize endpoint expects a POST request with JSON body.",
    schema: {
      access_token: "string (Auth0 JWT token)",
      method: "string ('GET' | 'POST' | 'PUT' | 'DELETE')",
      path: "string (e.g. '/transactions')",
    },
    example_test_command: "npm run token",
  });
});

router.post("/", async (req, res) => {
  const { access_token, user_id, method, path } = req.body ?? {};

  let token = access_token;
  if (!token && typeof req.headers.authorization === "string" && req.headers.authorization.startsWith("Bearer ")) {
    token = req.headers.authorization.slice(7).trim();
  }

  let resolvedUserId = user_id;

  if (token) {
    try {
      const payload = await validateAccessToken(token);
      resolvedUserId = payload.sub as string;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Invalid or expired token";
      return res.status(401).json({
        decision: "DENY",
        error: "Unauthorized",
        reason: "Invalid or expired access token",
        details: message,
      });
    }
  }

  if (
    typeof resolvedUserId !== "string" ||
    !resolvedUserId.trim() ||
    typeof method !== "string" ||
    typeof path !== "string"
  ) {
    return res.status(400).json({
      error: "access_token (or user_id), method and path are required",
    });
  }

  const result = authorize(resolvedUserId, method, path);

  try {
    db.prepare(`
      INSERT INTO authorization_logs (user_id, method, path, decision, reason)
      VALUES (?, ?, ?, ?, ?)
    `).run(resolvedUserId, method.toUpperCase(), path, result.decision, result.reason);
  } catch (err) {
    console.error("Failed to persist authorization log:", err);
  }

  return res.json(result);
});

// GET /authorize/logs - Get recent decision logs
router.get("/logs", (_req, res) => {
  try {
    const logs = db
      .prepare("SELECT * FROM authorization_logs ORDER BY id DESC LIMIT 50")
      .all();
    return res.json({ count: logs.length, logs });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Database error";
    return res.status(500).json({ error: message });
  }
});

// DELETE /authorize/logs - Clear logs
router.delete("/logs", (_req, res) => {
  try {
    db.prepare("DELETE FROM authorization_logs").run();
    return res.json({ message: "Authorization logs cleared successfully" });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Database error";
    return res.status(500).json({ error: message });
  }
});

export default router;

