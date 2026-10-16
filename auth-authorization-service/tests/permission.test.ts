import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import app from "../src/app.js";
import { authorize } from "../src/services/permissionService.js";
import db from "../src/database/db.js";
describe("Authorization API Tests", () => {
  it("Test 1: should ALLOW user456 to GET /wallets/wallet-789/transactions", async () => {
    const res = await request(app)
      .post("/authorize")
      .send({
        user_id: "user456",
        method: "GET",
        path: "/wallets/wallet-789/transactions",
      });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("ALLOW");
    expect(res.body.user_id).toBe("user456");
  });
  it("Test 2: should DENY user123 from DELETE /transactions/txn-456", async () => {
    const res = await request(app)
      .post("/authorize")
      .send({
        user_id: "user123",
        method: "DELETE",
        path: "/transactions/txn-456",
      });

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("DENY");
    expect(res.body.user_id).toBe("user123");
  });

  it("Test 3: should ALLOW admin789 to DELETE /accounts/acc-123/settings", async () => {
    const res = await request(app)
      .post("/authorize")
      .send({
        user_id: "admin789",
        method: "DELETE",
        path: "/accounts/acc-123/settings",
      });

    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("ALLOW");
    expect(res.body.user_id).toBe("admin789");
  });

  it("Test 4: should reject invalid JWT token with 401 Unauthorized", async () => {
    const res = await request(app)
      .post("/authorize")
      .send({
        access_token: "invalid.token.structure",
        method: "GET",
        path: "/transactions",
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Unauthorized");
  });
});

describe("Deny Precedence Tests", () => {
  beforeAll(() => {
    // Seed test-deny-user with both allow and deny for accounts
    const count = db
      .prepare("SELECT COUNT(*) AS count FROM user_permissions WHERE user_id = ?")
      .get("test-deny-user") as { count: number };

    if (count.count === 0) {
      const insert = db.prepare(
        "INSERT INTO user_permissions (user_id, action, resource, effect) VALUES (?, ?, ?, ?)"
      );
      insert.run("test-deny-user", "read", "accounts", "allow");
      insert.run("test-deny-user", "read", "accounts", "deny");
    }
  });

  it("should DENY when both ALLOW and DENY permissions match", () => {
    const result = authorize(
      "test-deny-user",
      "GET",
      "/accounts"
    );

    expect(result.decision).toBe("DENY");
  });
});

describe("Sample Nested Resource Test Scenarios (Assignment Spec)", () => {
  it("Scenario 1: Should ALLOW - user123 has read access to transactions", async () => {
    const res = await request(app).post("/authorize").send({
      access_token: "valid_token_for_user123",
      method: "GET",
      path: "/transactions",
    });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("ALLOW");
  });

  it("Scenario 2: Should DENY - user123 explicitly denied delete access", async () => {
    const res = await request(app).post("/authorize").send({
      access_token: "valid_token_for_user123",
      method: "DELETE",
      path: "/transactions/txn-456",
    });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("DENY");
  });

  it("Scenario 3: Should ALLOW - user456 has specific permission for wallet-789 transactions", async () => {
    const res = await request(app).post("/authorize").send({
      access_token: "valid_token_for_user456",
      method: "GET",
      path: "/wallets/wallet-789/transactions",
    });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("ALLOW");
  });

  it("Scenario 4a: Should ALLOW - user789 can write to any transaction in any wallet (nested item)", async () => {
    const res = await request(app).post("/authorize").send({
      access_token: "valid_token_for_user789",
      method: "POST",
      path: "/wallets/wallet-456/transactions/txn-999",
    });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("ALLOW");
  });

  it("Scenario 4b: Should ALLOW - user789 can write to any transaction collection in any wallet", async () => {
    const res = await request(app).post("/authorize").send({
      access_token: "valid_token_for_user789",
      method: "POST",
      path: "/wallets/wallet-789/transactions",
    });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("ALLOW");
  });

  it("Scenario 5: Should DENY - user456 only has read access to wallet-789 transactions, not write", async () => {
    const res = await request(app).post("/authorize").send({
      access_token: "valid_token_for_user456",
      method: "POST",
      path: "/wallets/wallet-789/transactions",
    });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("DENY");
  });

  it("Scenario 6: Should ALLOW - admin789 has global wildcard permissions", async () => {
    const res = await request(app).post("/authorize").send({
      access_token: "valid_token_for_admin789",
      method: "DELETE",
      path: "/accounts/acc-123/settings",
    });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("ALLOW");
  });

  it("Scenario 7: Test wildcard inheritance behavior - user456 accesses wallet-999", async () => {
    const res = await request(app).post("/authorize").send({
      access_token: "valid_token_for_user456",
      method: "GET",
      path: "/wallets/wallet-999",
    });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("ALLOW");
  });
});
