import db from "./db.js";

db.exec(`
  CREATE TABLE IF NOT EXISTS user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    effect TEXT NOT NULL
      CHECK (effect IN ('allow', 'deny'))
  );
`);

const insertPermission = db.prepare(`
  INSERT INTO user_permissions
    (user_id, action, resource, effect)
  VALUES (?, ?, ?, ?)
`);

const permissions = [
  ["user123", "read", "transactions", "allow"],
  ["user123", "write", "transactions", "allow"],
  ["user123", "delete", "transactions", "deny"],
  ["user123", "read", "accounts", "allow"],
  ["user456", "read", "wallets/*", "allow"],
  ["user456", "write", "wallets/wallet-789", "allow"],
  ["user456", "read", "wallets/wallet-789/transactions", "allow"],
  ["user789", "write", "wallets/*/transactions/*", "allow"],
  ["admin789", "read", "*", "allow"],
  ["admin789", "write", "*", "allow"],
  ["admin789", "delete", "*", "allow"],
  ["user12", "read", "transactions", "deny"],
  ["user123", "write", "*", "allow"],
] as const;

const seedPermissions = db.transaction(() => {
  const checkExisting = db.prepare(`
    SELECT id FROM user_permissions 
    WHERE user_id = ? AND action = ? AND resource = ? AND effect = ?
  `);

  for (const permission of permissions) {
    const exists = checkExisting.get(...permission);
    if (!exists) {
      insertPermission.run(...permission);
    }
  }
});

seedPermissions();

const rows = db.prepare(
  "SELECT * FROM user_permissions ORDER BY id"
).all();

console.log("SQLite database initialized.");
console.log("Total permissions:", rows.length);
console.table(rows);

db.close();
