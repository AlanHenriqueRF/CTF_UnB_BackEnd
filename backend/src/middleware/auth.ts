import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export const JWT_SECRET = process.env.JWT_SECRET || 'sigaa-next-homolog-jwt-key-unb-2026';
export const REQUIRED_GATEWAY_HEADER = 'SGI-v2';

export interface UserSessionPayload {
  userId: number;
  matricula: string;
  loginLinux: string;
  theme: string;
  role: string;
  [key: string]: unknown;
}

declare global {
  namespace Express {
    interface Request {
      userSession?: UserSessionPayload;
    }
  }
}

/**
 * Extrai o token JWT do header Authorization ("Bearer <token>") ou do header "X-Session-Token".
 * Caso o cliente ainda não tenha um token, inicializa uma sessão padrão de visitante/estagiário
 * com role="user" para facilitar a interação pelo Front-end.
 */
export function attachSession(req: Request, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  const customToken = req.headers['x-session-token'] as string | undefined;

  let token: string | undefined;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (customToken) {
    token = customToken;
  }

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as UserSessionPayload;
      req.userSession = decoded;
      return next();
    } catch {
      // Se o token for inválido, cai no perfil default abaixo
    }
  }

  req.userSession = {
    userId: 104,
    matricula: 'STI-2025104',
    loginLinux: 'estagiario_sti',
    theme: 'light',
    role: 'user'
  };
  next();
}
