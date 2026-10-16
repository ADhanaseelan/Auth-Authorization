import { Router } from "express";
import db, { syncToDriveE } from "../database/db.js";

const router = Router();

// GET /permissions - List all or filter by user_id
router.get("/", (req, res) => {
  const { user_id } = req.query;

  if (typeof user_id === "string" && user_id.trim()) {
    const rows = db
      .prepare("SELECT * FROM user_permissions WHERE user_id = ? ORDER BY id DESC")
      .all(user_id.trim());
    return res.json({ count: rows.length, permissions: rows });
  }

  const rows = db
    .prepare("SELECT * FROM user_permissions ORDER BY id DESC")
    .all();
  return res.json({ count: rows.length, permissions: rows });
});

// POST /permissions - Dynamically add a new permission rule
router.post("/", (req, res) => {
  const { user_id, action, resource, effect } = req.body ?? {};

  if (!user_id || !action || !resource || !effect) {
    return res.status(400).json({
      error: "Missing required fields: user_id, action, resource, effect",
    });
  }

  const validActions = ["read", "write", "delete"];
  const validEffects = ["allow", "deny"];

  const normalizedAction = String(action).toLowerCase();
  const normalizedEffect = String(effect).toLowerCase();

  if (!validActions.includes(normalizedAction)) {
    return res.status(400).json({
      error: `Invalid action '${action}'. Allowed: ${validActions.join(", ")}`,
    });
  }

  if (!validEffects.includes(normalizedEffect)) {
    return res.status(400).json({
      error: `Invalid effect '${effect}'. Allowed: ${validEffects.join(", ")}`,
    });
  }

  // Normalize resource pattern (remove leading/trailing slashes)
  const normalizedResource = String(resource).replace(/^\/+|\/+$/g, "");

  try {
    const insert = db.prepare(`
      INSERT INTO user_permissions (user_id, action, resource, effect)
      VALUES (?, ?, ?, ?)
    `);

    const result = insert.run(
      String(user_id).trim(),
      normalizedAction,
      normalizedResource,
      normalizedEffect
    );
    syncToDriveE();

    return res.status(201).json({
      message: "Permission added successfully",
      permission: {
        id: result.lastInsertRowid,
        user_id: String(user_id).trim(),
        action: normalizedAction,
        resource: normalizedResource,
        effect: normalizedEffect,
      },
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Database error";
    return res.status(500).json({ error: message });
  }
});

// DELETE /permissions/:id - Remove a permission rule by ID
router.delete("/:id", (req, res) => {
  const id = Number(req.params.id);

  if (isNaN(id)) {
    return res.status(400).json({ error: "Invalid permission ID" });
  }

  const result = db.prepare("DELETE FROM user_permissions WHERE id = ?").run(id);

  if (result.changes === 0) {
    return res.status(404).json({ error: `Permission with ID ${id} not found` });
  }
  syncToDriveE();

  return res.json({ message: `Permission ${id} deleted successfully` });
});

// PATCH /permissions/:id - Update an existing permission rule
router.patch("/:id", (req, res) => {
  const id = Number(req.params.id);

  if (isNaN(id)) {
    return res.status(400).json({ error: "Invalid permission ID" });
  }

  const existing = db.prepare("SELECT * FROM user_permissions WHERE id = ?").get(id) as
    | { id: number; user_id: string; action: string; resource: string; effect: string }
    | undefined;

  if (!existing) {
    return res.status(404).json({ error: `Permission with ID ${id} not found` });
  }

  const { action, resource, effect, user_id } = req.body ?? {};

  const updatedUserId = user_id ? String(user_id).trim() : existing.user_id;
  const updatedAction = action ? String(action).toLowerCase() : existing.action;
  const updatedResource = resource
    ? String(resource).replace(/^\/+|\/+$/g, "")
    : existing.resource;
  const updatedEffect = effect ? String(effect).toLowerCase() : existing.effect;

  const validActions = ["read", "write", "delete"];
  const validEffects = ["allow", "deny"];

  if (!validActions.includes(updatedAction)) {
    return res.status(400).json({
      error: `Invalid action '${updatedAction}'. Allowed: ${validActions.join(", ")}`,
    });
  }

  if (!validEffects.includes(updatedEffect)) {
    return res.status(400).json({
      error: `Invalid effect '${updatedEffect}'. Allowed: ${validEffects.join(", ")}`,
    });
  }

  db.prepare(`
    UPDATE user_permissions
    SET user_id = ?, action = ?, resource = ?, effect = ?
    WHERE id = ?
  `).run(updatedUserId, updatedAction, updatedResource, updatedEffect, id);
  syncToDriveE();

  return res.json({
    message: "Permission updated successfully",
    permission: {
      id,
      user_id: updatedUserId,
      action: updatedAction,
      resource: updatedResource,
      effect: updatedEffect,
    },
  });
});

export default router;
