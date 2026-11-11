import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { attachSession, JWT_SECRET, REQUIRED_GATEWAY_HEADER, UserSessionPayload } from '../../src/middleware/auth';

describe('Testes Unitários — Middleware de Sessão e Autenticação JWT (auth.ts)', () => {
  it('1. Deve inicializar a sessão padrão do estagiario_sti (role="user") quando nenhum token é enviado', () => {
    const req = { headers: {} } as unknown as Request;
    const res = {} as Response;
    let nextCalled = false;

    attachSession(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.ok(req.userSession);
    assert.equal(req.userSession.userId, 104);
    assert.equal(req.userSession.loginLinux, 'estagiario_sti');
    assert.equal(req.userSession.role, 'user');
    assert.equal(req.userSession.theme, 'light');
  });

  it('2. Deve decodificar corretamente um token JWT válido enviado via Header Authorization Bearer', () => {
    const customPayload: UserSessionPayload = {
      userId: 104,
      matricula: 'STI-2025104',
      loginLinux: 'estagiario_sti',
      theme: 'dark',
      role: 'admin'
    };
    const token = jwt.sign(customPayload, JWT_SECRET, { expiresIn: '1h' });

    const req = {
      headers: {
        authorization: `Bearer ${token}`
      }
    } as unknown as Request;
    const res = {} as Response;
    let nextCalled = false;

    attachSession(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.equal(req.userSession?.role, 'admin');
    assert.equal(req.userSession?.theme, 'dark');
  });

  it('3. Deve aceitar token enviado pelo header alternativo X-Session-Token', () => {
    const customPayload: UserSessionPayload = {
      userId: 102,
      matricula: 'STI-2024019',
      loginLinux: 'coord_redes',
      theme: 'dark',
      role: 'admin'
    };
    const token = jwt.sign(customPayload, JWT_SECRET);

    const req = {
      headers: {
        'x-session-token': token
      }
    } as unknown as Request;
    const res = {} as Response;

    attachSession(req, res, () => {});

    assert.equal(req.userSession?.loginLinux, 'coord_redes');
    assert.equal(req.userSession?.role, 'admin');
  });

  it('4. Deve fazer fallback seguro para role="user" quando o token JWT for inválido ou adulterado com chave errada', () => {
    const forgedToken = jwt.sign({ role: 'admin' }, 'chave-secreta-errada');
    const req = {
      headers: {
        authorization: `Bearer ${forgedToken}`
      }
    } as unknown as Request;
    const res = {} as Response;

    attachSession(req, res, () => {});

    assert.equal(req.userSession?.role, 'user');
    assert.equal(req.userSession?.userId, 104);
  });

  it('5. Deve manter a constante do Header do Gateway Interno alinhada com a pista do Banner SSH (SGI-v2)', () => {
    assert.equal(REQUIRED_GATEWAY_HEADER, 'SGI-v2');
  });
});
