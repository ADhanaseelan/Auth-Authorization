import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN || "dev-example.us.auth0.com";
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || "https://api.auth-service.com";
const AUTH0_ISSUER = `https://${AUTH0_DOMAIN}/`;

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJWKS() {
  if (!jwks) {
    const jwksUri = new URL(`https://${AUTH0_DOMAIN}/.well-known/jwks.json`);
    jwks = createRemoteJWKSet(jwksUri);
  }
  return jwks;
}

export interface AuthenticatedUser {
  userId: string;
  payload: JWTPayload;
}

export async function verifyAuth0Token(token: string): Promise<AuthenticatedUser> {
  const JWKS = getJWKS();

  const { payload } = await jwtVerify(token, JWKS, {
    issuer: AUTH0_ISSUER,
    audience: AUTH0_AUDIENCE,
  });

  if (!payload.sub) {
    throw new Error("Token payload does not contain a subject (sub) claim");
  }

  return {
    userId: payload.sub,
    payload,
  };
}
