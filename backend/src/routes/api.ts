import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import { execSync } from 'child_process';
import { attachSession, JWT_SECRET, REQUIRED_GATEWAY_HEADER, UserSessionPayload } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();

router.use(attachSession);

/**
 * ROTA 0: Status da API e informações públicas do ambiente de homologação
 * GET /api/v1/status
 */
router.get('/status', (_req: Request, res: Response) => {
  res.json({
    service: 'SIGAA-Next REST API (UnB / STI - Homologação)',
    version: '2.1.0-homolog',
    database: 'PostgreSQL 16 (Prisma ORM)',
    gateway_status: 'active',
    docs_hint: 'Consulte o servidor FTP interno para changelogs da migração v1 -> v2.'
  });
});

/**
 * ROTA 1 (VULNERABILIDADE #1 - EXCESSIVE DATA EXPOSURE / OWASP API3:2023):
 * GET /api/v1/staff
 *
 * O Front-end exibe apenas `nome`, `cargo`, `departamento` e `email`.
 * Porém, o Back-end retorna todos os registros do banco e formata o campo `_debug_internal`
 * expondo `login_linux`, `nota_privada`, `draft_endpoint` e `role`.
 */
router.get('/staff', async (_req: Request, res: Response) => {
  try {
    const staffList = await prisma.staff.findMany({
      orderBy: { id: 'asc' }
    });

    const formattedResponse = staffList.map((member) => ({
      id: member.id,
      matricula: member.matricula,
      nome: member.nome,
      cargo: member.cargo,
      departamento: member.departamento,
      email: member.email,
      visivel_front: member.visivelFront,
      // VULNERABILIDADE: Objeto de debug esquecido na serialização do endpoint público
      _debug_internal: {
        login_linux: member.loginLinux,
        role: member.role,
        nota_privada: member.notaPrivada,
        draft_endpoint: member.draftEndpoint
      }
    }));

    res.json({
      total: formattedResponse.length,
      data: formattedResponse
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao consultar quadro de servidores STI.' });
  }
});

/**
 * ROTA DE RASCUNHO (PISTA INTERMEDIÁRIA DESCOBERTA NO _debug_internal DO ID 104):
 * GET /api/v1/users/:id/drafts
 *
 * Ajuda o atacante a entender exatamente como funciona a atualização de perfil (PUT /api/v1/profile),
 * o Header do Gateway (X-Origin-System) e a estrutura do banco PostgreSQL.
 */
router.get('/users/:id/drafts', async (req: Request, res: Response) => {
  const targetId = Number(req.params.id);

  if (targetId !== 104) {
    return res.status(404).json({
      error: 'Nenhum rascunho de desenvolvimento encontrado para este ID de servidor.'
    });
  }

  return res.json({
    author: 'estagiario_sti (Lucas Ferreira)',
    last_modified: '2026-11-08T22:15:00Z',
    todo_notes: [
      '1. Finalizar endpoint PUT /api/v1/profile (atualmente faz Object.assign direto do body JSON na sessão JWT sem filtrar campos como "role").',
      '2. O Coordenador de Redes exigiu que a rota POST /api/v1/admin/system-check valide tanto role="admin" no Token Bearer quanto o header do Gateway (veja o banner do SSH na porta 22).',
      '3. Cuidado com a rota de busca de disciplinas GET /api/v1/courses/search?dept=CIC — a DBA Camila avisou que o $queryRawUnsafe permite injeção SQL no PostgreSQL!'
    ],
    sample_profile_request: {
      method: 'PUT',
      endpoint: '/api/v1/profile',
      headers: { 'Content-Type': 'application/json' },
      body_example: { theme: 'dark' }
    }
  });
});

/**
 * ROTA 2 (VULNERABILIDADE #2 - MASS ASSIGNMENT / BROKEN OBJECT PROPERTY LEVEL AUTH):
 * PUT /api/v1/profile
 *
 * O Front-end possui apenas um seletor de tema que envia `{"theme": "dark"}`.
 * Porém, se o atacante interceptar a requisição (Burp Suite / curl / Fetch no Console)
 * e enviar `{"theme": "dark", "role": "admin"}`, o back-end mescla tudo sem validação
 * (`Object.assign`) e assina um novo JWT com privilégio `role: "admin"`!
 */
router.put('/profile', async (req: Request, res: Response) => {
  const currentSession: UserSessionPayload = req.userSession || {
    userId: 104,
    matricula: 'STI-2025104',
    loginLinux: 'estagiario_sti',
    theme: 'light',
    role: 'user'
  };

  // VULNERABILIDADE INTENCIONAL DE MASS ASSIGNMENT:
  // Copia qualquer propriedade enviada no JSON do body (incluindo "role": "admin")
  const updatedSession: UserSessionPayload = Object.assign({}, currentSession, req.body);

  // Persiste o tema (e role caso enviado) no banco para o usuário 104
  try {
    await prisma.staff.update({
      where: { id: 104 },
      data: {
        theme: String(updatedSession.theme || 'light'),
        role: String(updatedSession.role || 'user')
      }
    });
  } catch {
    // Ignora erro caso o seed ainda não tenha rodado
  }

  const newToken = jwt.sign(updatedSession, JWT_SECRET, { expiresIn: '4h' });

  return res.json({
    message: 'Preferências de perfil atualizadas com sucesso.',
    session: updatedSession,
    token: newToken,
    auth_hint: 'Utilize este token no header "Authorization: Bearer <token>" para chamadas autenticadas.'
  });
});

/**
 * ROTA 2.1: Consulta do perfil atual para o jogador testar seu token JWT
 * GET /api/v1/profile
 */
router.get('/profile', (req: Request, res: Response) => {
  res.json({
    current_session: req.userSession
  });
});

/**
 * ROTA 3 (CAMINHO A - HEADER SPOOFING + ENDPOINT ADMIN / COMMAND INJECTION OPCIONAL):
 * POST /api/v1/admin/system-check
 *
 * Exige:
 *  1. `role === "admin"` (obtido via Mass Assignment no PUT /api/v1/profile ou se o banco foi alterado para role='admin')
 *  2. Header `X-Origin-System: SGI-v2` (descoberto no Banner do SSH na porta 22)
 *
 * Entrega a passphrase da chave SSH do `estagiario_sti` (que está no FTP) e também permite
 * testar conectividade se o parâmetro `diagnostic_cmd` for enviado.
 */
router.post('/admin/system-check', async (req: Request, res: Response) => {
  const originHeader = req.headers['x-origin-system'];

  // Validação 1: Header do Gateway (Pista do SSH Banner)
  if (originHeader !== REQUIRED_GATEWAY_HEADER) {
    return res.status(401).json({
      error: '401 Unauthorized: Gateway Origin Header ausente ou inválido.',
      details: 'Acesso permitido apenas para requisições originadas pelo Gateway Interno homologado (Verifique o aviso de segurança no banner do SSH).'
    });
  }

  // Verifica se o role é admin no JWT OU se o atacante alterou diretamente o role no PostgreSQL (porta 5432 / SQLi)
  let isAdmin = req.userSession?.role === 'admin';
  if (!isAdmin) {
    try {
      const dbUser = await prisma.staff.findUnique({ where: { id: 104 } });
      if (dbUser?.role === 'admin') {
        isAdmin = true;
      }
    } catch {
      // ignora falha de banco
    }
  }

  // Validação 2: Role de Administrador
  if (!isAdmin) {
    return res.status(403).json({
      error: '403 Forbidden: Privilégio insuficiente.',
      current_role: req.userSession?.role || 'user',
      required_role: 'admin',
      hint: 'Sua sessão atual não possui permissão administrativa. Verifique como o perfil é atualizado em PUT /api/v1/profile.'
    });
  }

  // Busca os segredos de manutenção no PostgreSQL
  const vaultSecrets = await prisma.systemVault.findMany();

  // Suporte opcional a execução de comando básico de diagnóstico (caso o jogador tente Command Injection no JSON)
  let commandOutput: string | undefined;
  const { target_host } = req.body || {};
  if (typeof target_host === 'string' && target_host.trim().length > 0) {
    try {
      // Executa ping de 1 pacote permitindo encadeamento de comandos (; id, ; ls, etc.)
      commandOutput = execSync(`ping -c 1 ${target_host}`, {
        timeout: 3000,
        encoding: 'utf-8'
      });
    } catch (err: any) {
      commandOutput = err?.stdout || err?.message || 'Erro ao executar comando de diagnóstico.';
    }
  }

  return res.json({
    status: 'OK — Modo de Diagnóstico Administrativo STI/UnB-Next',
    authenticated_as: req.userSession?.loginLinux || 'estagiario_sti',
    gateway_verified: REQUIRED_GATEWAY_HEADER,
    ssh_maintenance_credentials: {
      ssh_user: 'estagiario_sti',
      ftp_backup_file: 'id_rsa_estagiario_sti.enc',
      vault_records: vaultSecrets.map((s) => ({
        service: s.serviceName,
        username: s.username,
        secret: s.secretValue,
        description: s.description
      }))
    },
    network_diagnostic_output: commandOutput || 'Envie {"target_host": "127.0.0.1"} no body JSON se desejar testar conectividade ICMP/Shell.'
  });
});

/**
 * ROTA 4 (CAMINHO B / RAMIFICAÇÃO SQL INJECTION VIA PRISMA RAW QUERY):
 * GET /api/v1/courses/search?dept=CIC
 *
 * Embora o projeto use Prisma ORM, esta rota de listagem acadêmica utiliza `$queryRawUnsafe`
 * concatenando diretamente a string `dept`.
 *
 * Exemplo de Exploração UNION SQL Injection:
 *   /api/v1/courses/search?dept=CIC' UNION SELECT id, service_name, username, secret_value, description, '2026', 1 FROM sys_maintenance_vault--
 */
router.get('/courses/search', async (req: Request, res: Response) => {
  const dept = (req.query.dept as string) || 'CIC';

  try {
    // VULNERABILIDADE INTENCIONAL (RAMIFICAÇÃO SQL): Uso de $queryRawUnsafe com interpolação direta!
    const rawQuery = `
      SELECT id, codigo, nome, departamento, professor, semestre, vagas
      FROM academic_courses
      WHERE departamento = '${dept}'
      ORDER BY codigo ASC
    `;

    const courses = await prisma.$queryRawUnsafe(rawQuery);

    return res.json({
      query_filter: dept,
      results: courses
    });
  } catch (err: any) {
    // Retorna o erro do PostgreSQL detalhado (Error-Based SQLi helper) para ajudar o jogador a montar o UNION SELECT
    return res.status(400).json({
      error: 'Erro de sintaxe SQL ao consultar catálogo de disciplinas no PostgreSQL.',
      postgres_debug: err?.message,
      hint: 'A tabela consultada possui 7 colunas: (id INT, codigo TEXT, nome TEXT, departamento TEXT, professor TEXT, semestre TEXT, vagas INT).'
    });
  }
});

/**
 * RABBIT HOLE #1 (Credenciais legadas encontradas no FTP):
 * POST /api/v1/auth/legacy-login
 */
router.post('/auth/legacy-login', (req: Request, res: Response) => {
  const { username } = req.body || {};
  return res.status(403).json({
    error: '403 Conta Desativada — Use o Portal v2 (SIGAA-Next)',
    message: `O login legado '${username || 'desconhecido'}' do dump de 2023 foi revogado pela Diretoria de Segurança (STI). A autenticação de API agora utiliza Tokens de Sessão v2 e chaves SSH de manutenção.`
  });
});

export default router;
