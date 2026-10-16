import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.resolve(__dirname, "../../permissions.db");

const db = new Database(dbPath);
console.log(`[Database] Connected to SQLite database at: ${dbPath}`);

export function syncToDriveE() {
  const eDir = "E:\\auth-authorization-service\\auth-authorization-service";
  const eFile = "E:\\auth-authorization-service\\auth-authorization-service\\permissions.db";
  try {
    if (fs.existsSync(eDir)) {
      fs.copyFileSync(dbPath, eFile);
    }
  } catch (err) {
    // silently catch if file is temporarily locked by another app
  }
}

db.pragma("foreign_keys = ON");

// Auto-initialize required tables if not already present
db.exec(`
  CREATE TABLE IF NOT EXISTS user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny'))
  );

  CREATE TABLE IF NOT EXISTS authorization_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

export default db;

