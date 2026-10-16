import { Request, Response, NextFunction } from "express";
import { verifyAuth0Token, AuthenticatedUser } from "./jwt.js";

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}

export async function authenticateToken(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      error: "Authorization header is missing",
    });
  }

  const [scheme, token] = authHeader.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      error: "Authorization header must be in 'Bearer <token>' format",
    });
  }

  try {
    const user = await verifyAuth0Token(token);
    req.user = user;
    next();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Invalid or expired token";
    return res.status(401).json({
      error: "Unauthorized",
      details: message,
    });
  }
}
