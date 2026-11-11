import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('[SEED] Populando banco de dados PostgreSQL do SIGAA-Next (STI/UnB)...');

  await prisma.staff.deleteMany();
  await prisma.course.deleteMany();
  await prisma.systemVault.deleteMany();

  // 1. Equipe STI / UnB-Next (Contém Excessive Data Exposure no endpoint /api/v1/staff)
  await prisma.staff.createMany({
    data: [
      {
        id: 101,
        matricula: 'STI-2024001',
        nome: 'Dra. Helena Vasconcelos',
        cargo: 'Diretora de Governança Digital',
        departamento: 'STI / Diretoria Técnica',
        email: 'helena.vasconcelos@unb-next.edu.br',
        visivelFront: true,
        role: 'director',
        loginLinux: null,
        notaPrivada: 'Reunião com Reitoria sobre migração total do módulo de matrículas.',
        draftEndpoint: null
      },
      {
        id: 102,
        matricula: 'STI-2024019',
        nome: 'Marcos Vinícius Andrade',
        cargo: 'Coordenador de Redes e Infraestrutura',
        departamento: 'STI / Gerência de Segurança e Redes',
        email: 'marcos.andrade@unb-next.edu.br',
        visivelFront: true,
        role: 'admin',
        loginLinux: 'coord_redes',
        notaPrivada: 'Lembrar de bloquear acesso externo direto à porta 5432 e exigir header do Gateway SGI no endpoint de diagnóstico.',
        draftEndpoint: '/api/v1/admin/system-check'
      },
      {
        id: 104,
        matricula: 'STI-2025104',
        nome: 'Lucas Ferreira (Bolsista STI)',
        cargo: 'Estagiário de Desenvolvimento Back-end',
        departamento: 'STI / Divisão de Sistemas Acadêmicos (SIGAA-Next)',
        email: 'lucas.estagiario@unb-next.edu.br',
        visivelFront: true,
        role: 'user',
        loginLinux: 'estagiario_sti',
        notaPrivada: 'Subi meu backup da chave SSH (id_rsa_estagiario_sti.enc) no FTP por precaução. A passphrase ficou salva no cofre do sistema (sys_maintenance_vault) e no diagnóstico de admin (/api/v1/admin/system-check). Meu rascunho de rotas fica em /api/v1/users/104/drafts.',
        draftEndpoint: '/api/v1/users/104/drafts'
      },
      {
        id: 105,
        matricula: 'STI-2023088',
        nome: 'Camila Rocha',
        cargo: 'Analista de Banco de Dados (DBA)',
        departamento: 'STI / Administração de Dados',
        email: 'camila.rocha@unb-next.edu.br',
        visivelFront: false,
        role: 'dba',
        loginLinux: 'dba_homolog',
        notaPrivada: 'ATENÇÃO: A busca legada de turmas (/api/v1/courses/search?dept=...) ainda usa query raw concatenada! Precisamos refatorar para Prisma parametrizado antes do pentest da LabSec.',
        draftEndpoint: '/api/v1/courses/search'
      }
    ]
  });

  // 2. Disciplinas Acadêmicas (Usadas na busca do portal e na ramificação de SQL Injection)
  await prisma.course.createMany({
    data: [
      {
        codigo: 'CIC0201',
        nome: 'Segurança Computacional',
        departamento: 'CIC',
        professor: 'Prof. Pedro / LabSec',
        semestre: '2026.2',
        vagas: 45
      },
      {
        codigo: 'CIC0090',
        nome: 'Estruturas de Dados',
        departamento: 'CIC',
        professor: 'Profa. Roberta',
        semestre: '2026.2',
        vagas: 60
      },
      {
        codigo: 'ENE0334',
        nome: 'Redes de Computadores e Sistemas Distribuídos',
        departamento: 'ENE',
        professor: 'Prof. Carlos',
        semestre: '2026.2',
        vagas: 40
      },
      {
        codigo: 'MAT0025',
        nome: 'Cálculo 1',
        departamento: 'MAT',
        professor: 'Prof. Ricardo',
        semestre: '2026.2',
        vagas: 120
      }
    ]
  });

  // 3. Cofre de Manutenção (Objetivo tanto do Endpoint Admin quanto da Ramificação SQL/Postgres)
  const sshPassphrase = process.env.SSH_KEY_PASSPHRASE || 'UnB_ST1_H0m0l0g_2026!#';
  const sshFallbackPassword = process.env.ESTAGIARIO_SSH_PASS || 'estagiario@sigaa2026';

  await prisma.systemVault.createMany({
    data: [
      {
        serviceName: 'ssh_key_passphrase_estagiario',
        username: 'estagiario_sti',
        secretValue: sshPassphrase,
        description: 'Passphrase para descriptografar o arquivo id_rsa_estagiario_sti.enc armazenado no servidor FTP'
      },
      {
        serviceName: 'ssh_fallback_auth_estagiario',
        username: 'estagiario_sti',
        secretValue: sshFallbackPassword,
        description: 'Credencial de contingência SSH do usuário de manutenção estagiario_sti'
      },
      {
        serviceName: 'legacy_portal_v1_hash',
        username: 'admin_v1_deprecated',
        secretValue: '$2b$12$RabbitHoleFakeHashDoNotCrack99999999999999999999999',
        description: '[RABBIT HOLE] Hash antigo do SIGAA v1 desativado em 2023 (Conta bloqueada no PAM)'
      }
    ]
  });

  console.log('[SEED] Banco populado com sucesso!');
}

main()
  .catch((e) => {
    console.error('[SEED ERROR]', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
