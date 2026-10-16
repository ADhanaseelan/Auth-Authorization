const Database = require("better-sqlite3");
const db = new Database("permissions.db");
const userId = "PIAvI4kXAiP5f2Twn3Qf0qufp0bPOHim@clients";
const rows = db.prepare(`
  SELECT id, user_id, action, resource, effect
  FROM user_permissions
  WHERE user_id = ?
    AND action = ?
    AND resource = ?
`).all(userId, "read", "transactions");
console.log(rows);