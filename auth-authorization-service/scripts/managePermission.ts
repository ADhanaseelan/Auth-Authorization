import db from "../src/database/db.js";

const [action, ...args] = process.argv.slice(2);

function printHelp() {
  console.log(`
  🛠️  Permission Management CLI Tool
  ====================================
  Usage:
    npm run perm list [user_id]
      👉 Lists all permissions or permissions for a specific user.

    npm run perm add <user_id> <action> <resource> <effect>
      👉 Adds a permission dynamically.
      👉 Example: npm run perm add user999 read reports allow
      👉 Example: npm run perm add user999 delete reports deny

    npm run perm delete <id>
      👉 Deletes permission by row ID.
      👉 Example: npm run perm delete 5

    npm run perm check <user_id> <method> <path>
      👉 Directly tests authorization query.
      👉 Example: npm run perm check user999 GET /reports
  `);
}

switch (action) {
  case "list": {
    const targetUser = args[0];
    const query = targetUser
      ? db.prepare("SELECT * FROM user_permissions WHERE user_id = ? ORDER BY id ASC")
      : db.prepare("SELECT * FROM user_permissions ORDER BY id ASC");
    const rows = targetUser ? query.all(targetUser) : query.all();
    console.log(`\n📋 Permissions List (Total: ${rows.length}):`);
    console.table(rows);
    break;
  }

  case "add": {
    const [userId, act, res, eff] = args;
    if (!userId || !act || !res || !eff) {
      console.error("❌ Error: Missing parameters!");
      console.log("Usage: npm run perm add <user_id> <action> <resource> <effect>");
      process.exit(1);
    }

    const normAction = act.toLowerCase();
    const normEffect = eff.toLowerCase();
    const normResource = res.replace(/^\/+|\/+$/g, "");

    const insert = db.prepare(`
      INSERT INTO user_permissions (user_id, action, resource, effect)
      VALUES (?, ?, ?, ?)
    `);

    const result = insert.run(userId, normAction, normResource, normEffect);
    console.log(`\n✅ Added permission successfully! (Row ID: ${result.lastInsertRowid})`);
    console.log(`User: ${userId} | Action: ${normAction} | Resource: ${normResource} | Effect: ${normEffect}\n`);
    break;
  }

  case "delete": {
    const id = Number(args[0]);
    if (isNaN(id)) {
      console.error("❌ Error: Invalid ID.");
      process.exit(1);
    }
    const result = db.prepare("DELETE FROM user_permissions WHERE id = ?").run(id);
    if (result.changes === 0) {
      console.log(`⚠️ No permission found with ID ${id}`);
    } else {
      console.log(`✅ Permission with ID ${id} deleted.`);
    }
    break;
  }

  default:
    printHelp();
    break;
}
