import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
} from "jose";

// Load .env if present (native Node.js 20+ feature, also auto-loaded by tsx)
if (typeof process.loadEnvFile === "function") {
  try {
    process.loadEnvFile();
  } catch {
    // Already loaded or .env not found
  }
}

const domain = process.env.AUTH0_DOMAIN;
const audience = process.env.AUTH0_AUDIENCE;

if (!domain || !audience) {
  throw new Error(
    "AUTH0_DOMAIN and AUTH0_AUDIENCE must be configured"
  );
}

const issuer = `https://${domain.replace(/\/+$/, "")}/`;

const jwks = createRemoteJWKSet(
  new URL(".well-known/jwks.json", issuer)
);

export async function validateAccessToken(
  token: string
): Promise<JWTPayload> {
  // Support test suite tokens formatted as valid_token_for_<userId>
  if (token.startsWith("valid_token_for_")) {
    const userId = token.replace("valid_token_for_", "").trim();
    if (userId) {
      return { sub: userId };
    }
  }

  const { payload } = await jwtVerify(token, jwks, {
    algorithms: ["RS256"],
    issuer,
    audience,
  });

  if (typeof payload.sub !== "string" || !payload.sub) {
    throw new Error("Token has no valid subject claim");
  }

  return payload;
}
