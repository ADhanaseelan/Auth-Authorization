// Script to fetch Auth0 Access Token via Node.js
import db from "../src/database/db.js";

const domain = process.env.AUTH0_DOMAIN || "dev-gx56u528ljl5u6mo.us.auth0.com";
const audience = process.env.AUTH0_AUDIENCE || "https://auth-service.example.com";
const clientId = process.env.AUTH0_CLIENT_ID || "PIAvI4kXAiP5f2Twn3Qf0qufp0bPOHim";
const clientSecret = process.env.AUTH0_CLIENT_SECRET || "qz56WcSudCrWJyPJSIYzuxl8MIt5fIpxJlpW_Z5x31Z2kUxPUzpFerVbmcVZjrR5";

async function fetchToken() {
  console.log("Requesting token from Auth0...");

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

  const data = await res.json();
  if (!res.ok) {
    console.error("Auth0 Error:", data);
    process.exit(1);
  }

  console.log("\n✅ Token obtained successfully from Auth0!");
  console.log("Access Token (masked):", data.access_token.slice(0, 15) + "..." + data.access_token.slice(-10));

  // Auto-seed permission for this M2M client in SQLite if not already present
  const clientSubject = `${clientId}@clients`;
  const existing = db.prepare("SELECT * FROM user_permissions WHERE user_id = ? AND resource = ?").get(clientSubject, "transactions");
  if (!existing) {
    db.prepare(`
      INSERT INTO user_permissions (user_id, action, resource, effect)
      VALUES (?, 'read', 'transactions', 'allow')
    `).run(clientSubject);
    console.log(`\n✅ Added permission for '${clientSubject}' to SQLite database!`);
  }

  console.log("\n--- Testing http://localhost:3000/authorize with valid token ---");
  try {
    const authRes = await fetch("http://localhost:3000/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        access_token: data.access_token,
        method: "GET",
        path: "/transactions",
      }),
    });
    const authData = await authRes.json();
    console.log(`\nHTTP Status Code: ${authRes.status}`);
    console.log("🎯 Final Authorization Decision Result:");
    console.dir(authData, { depth: null });
  } catch {
    console.log("(Note: Make sure your server is running with 'npm run dev')");
  }
}

fetchToken();
