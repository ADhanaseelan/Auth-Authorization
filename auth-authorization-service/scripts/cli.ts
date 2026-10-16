import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import db, { syncToDriveE } from "../src/database/db.js";
import { authorize } from "../src/services/permissionService.js";

// ANSI Styling Helpers
const colors = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
  bgGreen: "\x1b[42m\x1b[30m",
  bgRed: "\x1b[41m\x1b[37m",
  bgCyan: "\x1b[46m\x1b[30m",
};

interface PermissionRow {
  id: number;
  user_id: string;
  action: string;
  resource: string;
  effect: "allow" | "deny";
}

interface LogRow {
  id: number;
  user_id: string;
  method: string;
  path: string;
  decision: string;
  reason: string;
  created_at: string;
}

// Format badge for ALLOW / DENY
function formatEffect(effect: string): string {
  if (effect.toLowerCase() === "allow") {
    return `${colors.green}${colors.bold}ALLOW${colors.reset}`;
  }
  return `${colors.red}${colors.bold}DENY ${colors.reset}`;
}

// Print banner and stats dashboard
function printHeader() {
  const totalCount = (db.prepare("SELECT COUNT(*) as c FROM user_permissions").get() as { c: number }).c;
  const allowCount = (db.prepare("SELECT COUNT(*) as c FROM user_permissions WHERE effect = 'allow'").get() as { c: number }).c;
  const denyCount = (db.prepare("SELECT COUNT(*) as c FROM user_permissions WHERE effect = 'deny'").get() as { c: number }).c;
  const userCount = (db.prepare("SELECT COUNT(DISTINCT user_id) as c FROM user_permissions").get() as { c: number }).c;

  console.log(`\n${colors.cyan}${colors.bold}╔═══════════════════════════════════════════════════════════════════════════════════╗${colors.reset}`);
  console.log(`${colors.cyan}${colors.bold}║       🛡️  AUTH & AUTHORIZATION SERVICE - TERMINAL CONTROL PANEL                    ║${colors.reset}`);
  console.log(`${colors.cyan}${colors.bold}╚═══════════════════════════════════════════════════════════════════════════════════╝${colors.reset}`);
  console.log(`  ${colors.green}● Database: Connected${colors.reset} (SQLite) | ${colors.magenta}Engine: Active${colors.reset}`);
  console.log(`  ${colors.bold}📊 Statistics:${colors.reset} Total Rules: ${colors.bold}${totalCount}${colors.reset} │ Allows: ${colors.green}${allowCount}${colors.reset} │ Denies: ${colors.red}${denyCount}${colors.reset} │ Unique Users: ${colors.yellow}${userCount}${colors.reset}`);
  console.log(`${colors.gray}───────────────────────────────────────────────────────────────────────────────────${colors.reset}`);
}

// Render formatted table for permissions
function renderPermissionTable(rows: PermissionRow[], title = "Permissions List") {
  console.log(`\n${colors.bold}${colors.blue}📋 ${title} (Total: ${rows.length})${colors.reset}`);
  if (rows.length === 0) {
    console.log(`  ${colors.gray}(No permission records found)${colors.reset}\n`);
    return;
  }

  const idWidth = 5;
  const userWidth = 32;
  const actionWidth = 10;
  const resourceWidth = 28;
  const effectWidth = 8;

  const header = `  ${colors.bold}${"ID".padEnd(idWidth)} ${"USER ID".padEnd(userWidth)} ${"ACTION".padEnd(actionWidth)} ${"RESOURCE".padEnd(resourceWidth)} ${"EFFECT".padEnd(effectWidth)}${colors.reset}`;
  console.log(`${colors.gray}  ${"─".repeat(idWidth + userWidth + actionWidth + resourceWidth + effectWidth + 4)}${colors.reset}`);
  console.log(header);
  console.log(`${colors.gray}  ${"─".repeat(idWidth + userWidth + actionWidth + resourceWidth + effectWidth + 4)}${colors.reset}`);

  for (const row of rows) {
    const idStr = String(row.id).padEnd(idWidth);
    const userStr = (row.user_id.length > userWidth - 2 ? row.user_id.slice(0, userWidth - 5) + "..." : row.user_id).padEnd(userWidth);
    const actionStr = row.action.padEnd(actionWidth);
    const resStr = (row.resource.length > resourceWidth - 2 ? row.resource.slice(0, resourceWidth - 5) + "..." : row.resource).padEnd(resourceWidth);
    const effStr = formatEffect(row.effect);

    console.log(`  ${colors.yellow}${idStr}${colors.reset} ${colors.white}${userStr}${colors.reset} ${colors.cyan}${actionStr}${colors.reset} ${colors.magenta}${resStr}${colors.reset} ${effStr}`);
  }
  console.log(`${colors.gray}  ${"─".repeat(idWidth + userWidth + actionWidth + resourceWidth + effectWidth + 4)}${colors.reset}\n`);
}

// Render formatted table for logs
function renderLogsTable(logs: LogRow[]) {
  console.log(`\n${colors.bold}${colors.blue}📜 Authorization Decision Logs (Recent: ${logs.length})${colors.reset}`);
  if (logs.length === 0) {
    console.log(`  ${colors.gray}(No authorization logs recorded yet)${colors.reset}\n`);
    return;
  }

  const idWidth = 5;
  const timeWidth = 20;
  const userWidth = 24;
  const methodWidth = 8;
  const pathWidth = 22;
  const decisionWidth = 10;

  const header = `  ${colors.bold}${"ID".padEnd(idWidth)} ${"TIME".padEnd(timeWidth)} ${"USER ID".padEnd(userWidth)} ${"METHOD".padEnd(methodWidth)} ${"PATH".padEnd(pathWidth)} ${"DECISION".padEnd(decisionWidth)} REASON${colors.reset}`;
  console.log(`${colors.gray}  ${"─".repeat(idWidth + timeWidth + userWidth + methodWidth + pathWidth + decisionWidth + 30)}${colors.reset}`);
  console.log(header);
  console.log(`${colors.gray}  ${"─".repeat(idWidth + timeWidth + userWidth + methodWidth + pathWidth + decisionWidth + 30)}${colors.reset}`);

  for (const log of logs) {
    const idStr = String(log.id).padEnd(idWidth);
    const timeStr = String(log.created_at || "N/A").slice(0, 19).padEnd(timeWidth);
    const userStr = (log.user_id.length > userWidth - 2 ? log.user_id.slice(0, userWidth - 5) + "..." : log.user_id).padEnd(userWidth);
    const methodStr = log.method.padEnd(methodWidth);
    const pathStr = (log.path.length > pathWidth - 2 ? log.path.slice(0, pathWidth - 5) + "..." : log.path).padEnd(pathWidth);
    const decStr = log.decision === "ALLOW" ? `${colors.green}${colors.bold}ALLOW    ${colors.reset}` : `${colors.red}${colors.bold}DENY     ${colors.reset}`;

    console.log(`  ${colors.yellow}${idStr}${colors.reset} ${colors.gray}${timeStr}${colors.reset} ${colors.white}${userStr}${colors.reset} ${colors.cyan}${methodStr}${colors.reset} ${colors.magenta}${pathStr}${colors.reset} ${decStr} ${colors.dim}${log.reason}${colors.reset}`);
  }
  console.log(`${colors.gray}  ${"─".repeat(idWidth + timeWidth + userWidth + methodWidth + pathWidth + decisionWidth + 30)}${colors.reset}\n`);
}

// Core Operations
export function listPermissions(filter?: string) {
  let rows: PermissionRow[];
  if (filter && filter.trim()) {
    const tokens = filter
      .split(/[\s,]+/)
      .map((t) => t.trim())
      .filter(Boolean);

    if (tokens.length === 0) {
      rows = db.prepare("SELECT * FROM user_permissions ORDER BY id ASC").all() as PermissionRow[];
    } else {
      const clauses: string[] = [];
      const params: (string | number)[] = [];

      for (const token of tokens) {
        clauses.push(`(user_id LIKE ? OR action LIKE ? OR resource LIKE ? OR effect LIKE ? OR id = ?)`);
        const q = `%${token}%`;
        params.push(q, q, q, q, Number(token) || -1);
      }

      const sql = `
        SELECT * FROM user_permissions 
        WHERE ${clauses.join(" AND ")}
        ORDER BY id ASC
      `;
      rows = db.prepare(sql).all(...params) as PermissionRow[];
    }
  } else {
    rows = db.prepare("SELECT * FROM user_permissions ORDER BY id ASC").all() as PermissionRow[];
  }
  renderPermissionTable(rows, filter ? `Filtered Permissions matching '${filter}'` : "All Permissions");
  return rows;
}

export function addPermission(userId: string, action: string, resource: string, effect: string) {
  const normAction = action.trim().toLowerCase();
  const normEffect = effect.trim().toLowerCase();
  const normResource = resource.trim().replace(/^\/+|\/+$/g, "");
  const normUserId = userId.trim();

  const validActions = ["read", "write", "delete"];
  const validEffects = ["allow", "deny"];

  if (!validActions.includes(normAction)) {
    console.log(`${colors.red}❌ Error: Invalid action '${action}'. Allowed: read, write, delete${colors.reset}`);
    return null;
  }
  if (!validEffects.includes(normEffect)) {
    console.log(`${colors.red}❌ Error: Invalid effect '${effect}'. Allowed: allow, deny${colors.reset}`);
    return null;
  }

  const result = db.prepare(`
    INSERT INTO user_permissions (user_id, action, resource, effect)
    VALUES (?, ?, ?, ?)
  `).run(normUserId, normAction, normResource, normEffect);

  syncToDriveE();
  console.log(`\n${colors.green}✅ Permission added successfully! (ID: ${result.lastInsertRowid})${colors.reset}`);
  console.log(`   User: ${colors.bold}${normUserId}${colors.reset} | Action: ${colors.cyan}${normAction}${colors.reset} | Resource: ${colors.magenta}${normResource}${colors.reset} | Effect: ${formatEffect(normEffect)}\n`);
  return result.lastInsertRowid;
}

export function editPermission(id: number, updates: { userId?: string; action?: string; resource?: string; effect?: string }) {
  const existing = db.prepare("SELECT * FROM user_permissions WHERE id = ?").get(id) as PermissionRow | undefined;
  if (!existing) {
    console.log(`${colors.red}❌ Error: Permission with ID ${id} not found.${colors.reset}`);
    return false;
  }

  const updatedUserId = updates.userId?.trim() || existing.user_id;
  const updatedAction = updates.action?.trim().toLowerCase() || existing.action;
  const updatedResource = updates.resource ? updates.resource.trim().replace(/^\/+|\/+$/g, "") : existing.resource;
  const updatedEffect = updates.effect?.trim().toLowerCase() || existing.effect;

  const validActions = ["read", "write", "delete"];
  const validEffects = ["allow", "deny"];

  if (!validActions.includes(updatedAction)) {
    console.log(`${colors.red}❌ Error: Invalid action '${updatedAction}'. Allowed: read, write, delete${colors.reset}`);
    return false;
  }
  if (!validEffects.includes(updatedEffect)) {
    console.log(`${colors.red}❌ Error: Invalid effect '${updatedEffect}'. Allowed: allow, deny${colors.reset}`);
    return false;
  }

  db.prepare(`
    UPDATE user_permissions
    SET user_id = ?, action = ?, resource = ?, effect = ?
    WHERE id = ?
  `).run(updatedUserId, updatedAction, updatedResource, updatedEffect, id);

  syncToDriveE();
  console.log(`\n${colors.green}✅ Permission ID ${id} updated successfully!${colors.reset}`);
  console.log(`   User: ${colors.bold}${updatedUserId}${colors.reset} | Action: ${colors.cyan}${updatedAction}${colors.reset} | Resource: ${colors.magenta}${updatedResource}${colors.reset} | Effect: ${formatEffect(updatedEffect)}\n`);
  return true;
}

export function toggleEffect(id: number) {
  const existing = db.prepare("SELECT * FROM user_permissions WHERE id = ?").get(id) as PermissionRow | undefined;
  if (!existing) {
    console.log(`${colors.red}❌ Error: Permission with ID ${id} not found.${colors.reset}`);
    return false;
  }
  const nextEffect = existing.effect === "allow" ? "deny" : "allow";
  db.prepare("UPDATE user_permissions SET effect = ? WHERE id = ?").run(nextEffect, id);
  syncToDriveE();
  console.log(`\n${colors.green}🔄 Toggled Permission ID ${id} (${existing.user_id}): ${formatEffect(existing.effect)} ➔ ${formatEffect(nextEffect)}${colors.reset}\n`);
  return true;
}

export function deletePermission(id: number) {
  const result = db.prepare("DELETE FROM user_permissions WHERE id = ?").run(id);
  if (result.changes === 0) {
    console.log(`${colors.yellow}⚠️ No permission found with ID ${id}${colors.reset}`);
    return false;
  }
  syncToDriveE();
  console.log(`\n${colors.green}✅ Permission ID ${id} deleted successfully.${colors.reset}\n`);
  return true;
}

export function simulateAuth(userId: string, method: string, path: string) {
  console.log(`\n${colors.bold}${colors.blue}🎯 Simulating Authorization Evaluation...${colors.reset}`);
  console.log(`   Subject/User:  ${colors.bold}${userId}${colors.reset}`);
  console.log(`   HTTP Method:   ${colors.cyan}${method.toUpperCase()}${colors.reset}`);
  console.log(`   Resource Path: ${colors.magenta}${path}${colors.reset}`);

  const result = authorize(userId.trim(), method.toUpperCase(), path.trim());

  // Log decision to database
  try {
    db.prepare(`
      INSERT INTO authorization_logs (user_id, method, path, decision, reason)
      VALUES (?, ?, ?, ?, ?)
    `).run(userId.trim(), method.toUpperCase(), path.trim(), result.decision, result.reason);
  } catch (err) {
    console.error("Log error:", err);
  }

  console.log(`\n${colors.gray}─────────────────────────────────────────────────────────────${colors.reset}`);
  if (result.decision === "ALLOW") {
    console.log(`  ${colors.bgGreen} RESULT: ALLOWED ${colors.reset}  ${colors.green}${colors.bold}Access Granted${colors.reset}`);
  } else {
    console.log(`  ${colors.bgRed} RESULT: DENIED  ${colors.reset}  ${colors.red}${colors.bold}Access Blocked${colors.reset}`);
  }
  console.log(`  ${colors.bold}Reason:${colors.reset} ${result.reason}`);

  if (result.matched_permissions && result.matched_permissions.length > 0) {
    console.log(`  ${colors.bold}Matched Rule(s):${colors.reset}`);
    for (const p of result.matched_permissions) {
      console.log(`    • action: ${p.action} | resource: ${p.resource} | effect: ${formatEffect(p.effect)}`);
    }
  } else {
    console.log(`  ${colors.gray}(No specific matching rules evaluated)${colors.reset}`);
  }
  console.log(`${colors.gray}─────────────────────────────────────────────────────────────${colors.reset}\n`);
  return result;
}

export function showLogs(limit = 20) {
  const rows = db.prepare("SELECT * FROM authorization_logs ORDER BY id DESC LIMIT ?").all(limit) as LogRow[];
  renderLogsTable(rows);
}

export function clearLogs() {
  db.prepare("DELETE FROM authorization_logs").run();
  console.log(`\n${colors.green}🧹 Authorization decision logs cleared successfully.${colors.reset}\n`);
}

export async function fetchAuth0TokenAndTest() {
  const domain = process.env.AUTH0_DOMAIN || "dev-gx56u528ljl5u6mo.us.auth0.com";
  const audience = process.env.AUTH0_AUDIENCE || "https://auth-service.example.com";
  const clientId = process.env.AUTH0_CLIENT_ID || "PIAvI4kXAiP5f2Twn3Qf0qufp0bPOHim";
  const clientSecret = process.env.AUTH0_CLIENT_SECRET || "qz56WcSudCrWJyPJSIYzuxl8MIt5fIpxJlpW_Z5x31Z2kUxPUzpFerVbmcVZjrR5";

  console.log(`\n${colors.cyan}🌐 Requesting M2M Token from Auth0 (${domain})...${colors.reset}`);
  try {
    const res = await fetch(`https://${domain}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        audience: audience,
        grant_type: "client_credentials",
      }),
    });

    const data = (await res.json()) as { access_token?: string; token_type?: string; expires_in?: number; error?: string };
    if (!res.ok || !data.access_token) {
      console.error(`${colors.red}❌ Auth0 Token Error:${colors.reset}`, data);
      return;
    }

    const token = data.access_token;
    console.log(`${colors.green}✅ Access Token acquired successfully!${colors.reset}`);
    console.log(`   Token Type: ${data.token_type} | Expires in: ${data.expires_in}s`);
    console.log(`   Token Preview: ${colors.gray}${token.slice(0, 18)}...${token.slice(-12)}${colors.reset}`);

    const clientSubject = `${clientId}@clients`;
    const existing = db.prepare("SELECT * FROM user_permissions WHERE user_id = ? AND resource = ?").get(clientSubject, "transactions");
    if (!existing) {
      db.prepare(`
        INSERT INTO user_permissions (user_id, action, resource, effect)
        VALUES (?, 'read', 'transactions', 'allow')
      `).run(clientSubject);
      syncToDriveE();
      console.log(`   ${colors.green}✅ Auto-seeded rule for '${clientSubject}' -> read transactions (ALLOW)${colors.reset}`);
    }

    console.log(`\n${colors.blue}🎯 Evaluating Authorization with token subject '${clientSubject}' on GET /transactions...${colors.reset}`);
    simulateAuth(clientSubject, "GET", "/transactions");
  } catch (err) {
    console.error(`${colors.red}❌ Error connecting to Auth0:${colors.reset}`, err);
  }
}

// Print CLI Help
function printHelp() {
  printHeader();
  console.log(`
${colors.bold}COMMAND-LINE USAGE:${colors.reset}
  ${colors.cyan}npm run cli${colors.reset}                                 Launch interactive terminal menu
  ${colors.cyan}npm run cli list [search_term]${colors.reset}              List all rules or filter by keyword/user
  ${colors.cyan}npm run cli add <user> <action> <res> <eff>${colors.reset}  Add new permission rule
  ${colors.cyan}npm run cli edit <id> [action] [res] [eff]${colors.reset}   Update rule by ID
  ${colors.cyan}npm run cli toggle <id>${colors.reset}                     Quick toggle ALLOW <-> DENY
  ${colors.cyan}npm run cli delete <id>${colors.reset}                     Delete rule by ID
  ${colors.cyan}npm run cli test <user> <method> <path>${colors.reset}     Simulate authorization evaluation
  ${colors.cyan}npm run cli logs [limit]${colors.reset}                   View recent decision audit logs
  ${colors.cyan}npm run cli clear-logs${colors.reset}                     Clear all decision logs
  ${colors.cyan}npm run cli token${colors.reset}                          Fetch Auth0 token & run live test
  ${colors.cyan}npm run cli stats${colors.reset}                          Display service metrics summary
`);
}

// Interactive Terminal Menu
async function runInteractiveMenu() {
  const rl = readline.createInterface({ input, output });

  while (true) {
    printHeader();
    console.log(`  ${colors.bold}Available Terminal Operations:${colors.reset}`);
    console.log(`   ${colors.cyan}1${colors.reset} ➔  ${colors.bold}List All Permissions${colors.reset}`);
    console.log(`   ${colors.cyan}2${colors.reset} ➔  🔍 ${colors.bold}Search & Filter Permissions${colors.reset}`);
    console.log(`   ${colors.cyan}3${colors.reset} ➔  ➕ ${colors.bold}Add New Permission Rule${colors.reset}`);
    console.log(`   ${colors.cyan}4${colors.reset} ➔  ✏️  ${colors.bold}Edit Permission Rule${colors.reset}`);
    console.log(`   ${colors.cyan}5${colors.reset} ➔  🔄 ${colors.bold}Quick Toggle Effect (ALLOW ⮂ DENY)${colors.reset}`);
    console.log(`   ${colors.cyan}6${colors.reset} ➔  🗑️  ${colors.bold}Delete Permission Rule${colors.reset}`);
    console.log(`   ${colors.cyan}7${colors.reset} ➔  🎯 ${colors.bold}Quick Access Simulator (Test Access)${colors.reset}`);
    console.log(`   ${colors.cyan}8${colors.reset} ➔  📜 ${colors.bold}View Audit Decision Logs${colors.reset}`);
    console.log(`   ${colors.cyan}9${colors.reset} ➔  🧹 ${colors.bold}Clear Audit Logs${colors.reset}`);
    console.log(`  ${colors.cyan}10${colors.reset} ➔  🔑 ${colors.bold}Fetch Auth0 Token & Test Live${colors.reset}`);
    console.log(`   ${colors.red}0${colors.reset} ➔  🚪 ${colors.bold}Exit${colors.reset}`);
    console.log(`${colors.gray}───────────────────────────────────────────────────────────────────────────────────${colors.reset}`);

    const choice = (await rl.question(`${colors.bold}Enter selection (0-10): ${colors.reset}`)).trim();

    if (choice === "0") {
      console.log(`\n${colors.green}👋 Exiting Terminal Panel. Goodbye!${colors.reset}\n`);
      rl.close();
      break;
    }

    switch (choice) {
      case "1": {
        listPermissions();
        break;
      }
      case "2": {
        const query = await rl.question(`${colors.bold}Enter search query (user ID, action, resource, or effect): ${colors.reset}`);
        listPermissions(query);
        break;
      }
      case "3": {
        console.log(`\n${colors.bold}➕ Add New Permission Rule${colors.reset}`);
        const userId = await rl.question(`  User ID (e.g. user123, admin789): `);
        const action = await rl.question(`  Action [read/write/delete]: `);
        const resource = await rl.question(`  Resource path (e.g. transactions, accounts/*): `);
        const effect = await rl.question(`  Effect [allow/deny]: `);

        if (userId && action && resource && effect) {
          addPermission(userId, action, resource, effect);
        } else {
          console.log(`${colors.red}❌ Error: All fields are required.${colors.reset}`);
        }
        break;
      }
      case "4": {
        const idInput = await rl.question(`${colors.bold}Enter Permission ID to edit: ${colors.reset}`);
        const id = Number(idInput);
        if (isNaN(id)) {
          console.log(`${colors.red}❌ Error: Invalid ID.${colors.reset}`);
          break;
        }
        const existing = db.prepare("SELECT * FROM user_permissions WHERE id = ?").get(id) as PermissionRow | undefined;
        if (!existing) {
          console.log(`${colors.red}❌ Error: Permission ID ${id} not found.${colors.reset}`);
          break;
        }
        console.log(`\nEditing Rule #${id} (Leave blank to keep existing value):`);
        const newUserId = await rl.question(`  User ID [${existing.user_id}]: `);
        const newAction = await rl.question(`  Action [${existing.action}]: `);
        const newResource = await rl.question(`  Resource [${existing.resource}]: `);
        const newEffect = await rl.question(`  Effect [${existing.effect}]: `);

        editPermission(id, {
          userId: newUserId || undefined,
          action: newAction || undefined,
          resource: newResource || undefined,
          effect: newEffect || undefined,
        });
        break;
      }
      case "5": {
        const idInput = await rl.question(`${colors.bold}Enter Permission ID to toggle effect: ${colors.reset}`);
        const id = Number(idInput);
        if (!isNaN(id)) {
          toggleEffect(id);
        } else {
          console.log(`${colors.red}❌ Invalid ID.${colors.reset}`);
        }
        break;
      }
      case "6": {
        const idInput = await rl.question(`${colors.bold}Enter Permission ID to delete: ${colors.reset}`);
        const id = Number(idInput);
        if (!isNaN(id)) {
          const confirm = await rl.question(`⚠️ Are you sure you want to delete permission #${id}? (y/N): `);
          if (confirm.toLowerCase() === "y" || confirm.toLowerCase() === "yes") {
            deletePermission(id);
          } else {
            console.log(`${colors.yellow}Delete cancelled.${colors.reset}`);
          }
        } else {
          console.log(`${colors.red}❌ Invalid ID.${colors.reset}`);
        }
        break;
      }
      case "7": {
        console.log(`\n${colors.bold}🎯 Quick Access Simulator${colors.reset}`);
        const userId = (await rl.question(`  User ID [user123]: `)) || "user123";
        const method = (await rl.question(`  HTTP Method [GET]: `)) || "GET";
        const path = (await rl.question(`  Resource Path [/transactions]: `)) || "/transactions";
        simulateAuth(userId, method, path);
        break;
      }
      case "8": {
        const limitInput = await rl.question(`  Number of recent logs to show [20]: `);
        const limit = Number(limitInput) || 20;
        showLogs(limit);
        break;
      }
      case "9": {
        const confirm = await rl.question(`⚠️ Are you sure you want to clear all decision logs? (y/N): `);
        if (confirm.toLowerCase() === "y" || confirm.toLowerCase() === "yes") {
          clearLogs();
        } else {
          console.log(`${colors.yellow}Action cancelled.${colors.reset}`);
        }
        break;
      }
      case "10": {
        await fetchAuth0TokenAndTest();
        break;
      }
      default:
        console.log(`${colors.red}❌ Invalid option selected. Please choose from 0 to 10.${colors.reset}`);
        break;
    }

    await rl.question(`\n${colors.dim}Press Enter to continue...${colors.reset}`);
  }
}

// Entrypoint dispatcher
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    await runInteractiveMenu();
    return;
  }

  const command = args[0].toLowerCase();

  switch (command) {
    case "list":
    case "ls": {
      listPermissions(args[1]);
      break;
    }
    case "add": {
      const [, userId, action, resource, effect] = args;
      if (!userId || !action || !resource || !effect) {
        console.log(`${colors.red}❌ Error: Missing parameters!${colors.reset}`);
        console.log(`Usage: npm run cli add <user_id> <action> <resource> <effect>`);
        process.exit(1);
      }
      addPermission(userId, action, resource, effect);
      break;
    }
    case "edit": {
      const id = Number(args[1]);
      if (isNaN(id)) {
        console.log(`${colors.red}❌ Error: Missing or invalid ID.${colors.reset}`);
        console.log(`Usage: npm run cli edit <id> [action] [resource] [effect]`);
        process.exit(1);
      }
      editPermission(id, {
        action: args[2],
        resource: args[3],
        effect: args[4],
      });
      break;
    }
    case "toggle": {
      const id = Number(args[1]);
      if (isNaN(id)) {
        console.log(`${colors.red}❌ Error: Missing or invalid ID.${colors.reset}`);
        console.log(`Usage: npm run cli toggle <id>`);
        process.exit(1);
      }
      toggleEffect(id);
      break;
    }
    case "delete":
    case "del":
    case "rm": {
      const id = Number(args[1]);
      if (isNaN(id)) {
        console.log(`${colors.red}❌ Error: Missing or invalid ID.${colors.reset}`);
        console.log(`Usage: npm run cli delete <id>`);
        process.exit(1);
      }
      deletePermission(id);
      break;
    }
    case "test":
    case "check":
    case "sim": {
      const [, userId, method, path] = args;
      if (!userId || !method || !path) {
        console.log(`${colors.red}❌ Error: Missing parameters!${colors.reset}`);
        console.log(`Usage: npm run cli test <user_id> <method> <path>`);
        process.exit(1);
      }
      simulateAuth(userId, method, path);
      break;
    }
    case "logs": {
      const limit = Number(args[1]) || 25;
      showLogs(limit);
      break;
    }
    case "clear-logs": {
      clearLogs();
      break;
    }
    case "token": {
      await fetchAuth0TokenAndTest();
      break;
    }
    case "stats": {
      printHeader();
      break;
    }
    case "help":
    case "--help":
    case "-h":
    default: {
      printHelp();
      break;
    }
  }
}

main().catch((err) => {
  console.error("CLI encountered an unexpected error:", err);
  process.exit(1);
});
