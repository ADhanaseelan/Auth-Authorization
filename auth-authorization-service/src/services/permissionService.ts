import db from "../database/db.js";

type Action = "read" | "write" | "delete" | "list" | "create";
type Effect = "allow" | "deny";

interface Permission {
  id: number;
  user_id: string;
  action: Action;
  resource: string;
  effect: Effect;
}

interface AuthorizationResult {
  decision: "ALLOW" | "DENY";
  user_id: string;
  reason: string;
  matched_permissions: {
    action: Action;
    resource: string;
    effect: Effect;
  }[];
}

const methodActions: Record<string, Action> = {
  GET: "read",
  POST: "write",
  PUT: "write",
  PATCH: "write",
  DELETE: "delete",
};

export function methodToAction(method: string): Action | null {
  return methodActions[method.toUpperCase()] ?? null;
}

export function normalizePath(path: string): string {
  const pathname = path.split("?")[0];
  return pathname.replace(/^\/+|\/+$/g, "");
}

// A wildcard matches one path segment.
// A trailing wildcard can also match zero segments.
// A single-segment collection rule such as "transactions"
// inherits to its individual items.
export function resourceMatches(
  pattern: string,
  resource: string,
): boolean {
  if (pattern === "*") return true;

  const patternParts = pattern.split("/").filter(Boolean);
  const resourceParts = resource.split("/").filter(Boolean);

  const isCollectionRule = patternParts.length === 1;

  if (
    !isCollectionRule &&
    patternParts.length !== resourceParts.length
  ) {
    // Allow a trailing wildcard to represent an optional final ID.
    const trailingWildcard =
      patternParts[patternParts.length - 1] === "*";

    if (
      !trailingWildcard ||
      patternParts.length !== resourceParts.length + 1
    ) {
      return false;
    }
  }

  if (patternParts.length > resourceParts.length) {
    if (
      patternParts.length !== resourceParts.length + 1 ||
      patternParts[patternParts.length - 1] !== "*"
    ) {
      return false;
    }
  }

  const length = Math.min(patternParts.length, resourceParts.length);

  for (let i = 0; i < length; i++) {
    if (patternParts[i] !== "*" && patternParts[i] !== resourceParts[i]) {
      return false;
    }
  }

  // Collection permissions inherit to items, e.g. transactions/txn-123.
  if (isCollectionRule && resourceParts.length > 1) {
    return patternParts[0] === resourceParts[0];
  }

  return true;
}

function specificity(pattern: string): number {
  if (pattern === "*") return 0;

  return pattern
    .split("/")
    .filter(Boolean)
    .reduce((score, segment) => score + (segment === "*" ? 0 : 1), 0);
}

export function authorize(
  userId: string,
  method: string,
  path: string,
): AuthorizationResult {
  const action = methodToAction(method);
  const resource = normalizePath(path);

  const deny = (reason: string): AuthorizationResult => ({
    decision: "DENY",
    user_id: userId,
    reason,
    matched_permissions: [],
  });

  if (!action) {
    return deny(`Unsupported HTTP method: ${method}`);
  }

  if (!resource) {
    return deny("Resource path cannot be empty");
  }

  const permissions = db.prepare(`
    SELECT id, user_id, action, resource, effect
    FROM user_permissions
    WHERE user_id = ? AND action = ?
  `).all(userId, action) as Permission[];

  const matches = permissions.filter((permission) =>
    resourceMatches(permission.resource, resource),
  );

  if (matches.length === 0) {
    return deny(`No matching permission for ${action} ${resource}`);
  }

  const highestSpecificity = Math.max(
    ...matches.map((permission) => specificity(permission.resource)),
  );

  const mostSpecific = matches.filter(
    (permission) =>
      specificity(permission.resource) === highestSpecificity,
  );

  // At equal specificity, DENY takes precedence.
  const denied = mostSpecific.some(
    (permission) => permission.effect === "deny",
  );

  const decision = denied ? "DENY" : "ALLOW";

  return {
    decision,
    user_id: userId,
    reason: denied
      ? `A matching deny permission blocks ${action} ${resource}`
      : `User has ${action} permission for ${resource}`,
    matched_permissions: mostSpecific.map((permission) => ({
      action: permission.action,
      resource: permission.resource,
      effect: permission.effect,
    })),
  };
}
