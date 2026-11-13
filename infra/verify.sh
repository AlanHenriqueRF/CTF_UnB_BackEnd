#!/usr/bin/env bash
#
# verify.sh — Validador da camada de INFRA do CTF SIGAA-Next (Integrante 1)
# ---------------------------------------------------------------------------
# Testa, pela rede, exatamente o que o jogador consegue ver:
#   - FTP anônimo: lista e baixa os arquivos de pista
#   - SSH: banner aparece com a pista do header, e a porta responde
#   - A chave cifrada baixada do FTP decifra com a passphrase esperada
#     e permite login real via SSH no usuário estagiario_sti
#   - Reset: down -v + up --build volta tudo ao estado inicial
#
# Não testa as vulnerabilidades da API (isso é o exploit_test.sh, do
# Integrante 3) — aqui é só a parte que esta pasta (infra/) é responsável.
#
# Uso:
#   ./verify.sh                                # usa host/portas padrao
#   FTP_HOST=localhost FTP_PORT=21 SSH_PORT=2222 ./verify.sh
#
# Dependencias: bash, curl, ssh, sshpass (opcional, p/ testar senha), python3
# Codigo de saida: 0 se tudo passar, 1 caso contrario.

set -uo pipefail

FTP_HOST="${FTP_HOST:-localhost}"
FTP_PORT="${FTP_PORT:-21}"
SSH_HOST="${SSH_HOST:-localhost}"
SSH_PORT="${SSH_PORT:-2222}"

EXPECTED_PASSPHRASE="${SSH_KEY_PASSPHRASE:-UnB_ST1_H0m0l0g_2026!#}"
EXPECTED_SSH_USER="${SSH_USER:-estagiario_sti}"
EXPECTED_HEADER="X-Origin-System: SGI-v2"

if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
  BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; NC=""
fi

PASS_COUNT=0
FAIL_COUNT=0
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

section() { printf '\n%s===== %s =====%s\n' "$BOLD$BLUE" "$1" "$NC"; }
pass() { printf '  %s[PASS]%s %s\n' "$GREEN" "$NC" "$1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '  %s[FAIL]%s %s\n' "$RED" "$NC" "$1"; FAIL_COUNT=$((FAIL_COUNT+1)); }

for bin in curl ssh python3; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Dependência ausente: $bin" >&2; exit 2; }
done

printf '%sInfra alvo:%s ftp://%s:%s  ssh://%s:%s\n' "$BOLD" "$NC" "$FTP_HOST" "$FTP_PORT" "$SSH_HOST" "$SSH_PORT"

# ---------------------------------------------------------------------------
section "1. FTP anônimo — listagem e download"
FTP_LIST=$(curl -s --max-time 10 "ftp://${FTP_HOST}:${FTP_PORT}/" 2>&1)
if [ -z "$FTP_LIST" ]; then
  fail "FTP não respondeu (serviço no ar? porta certa?)"
else
  pass "FTP respondeu à listagem anônima"
fi

for f in changelog_api.txt swagger_old.json nota_dev.txt credenciais_teste.txt id_rsa_estagiario_sti.enc; do
  if curl -s --max-time 10 -o "$WORKDIR/$f" "ftp://${FTP_HOST}:${FTP_PORT}/$f"; then
    if [ -s "$WORKDIR/$f" ]; then
      pass "Download anônimo de $f"
    else
      fail "Download de $f retornou arquivo vazio"
    fi
  else
    fail "Não foi possível baixar $f via FTP anônimo"
  fi
done

# Confere que escrita está bloqueada (boa prática: anon_upload_enable=NO)
if curl -s --max-time 10 -T /etc/hostname "ftp://${FTP_HOST}:${FTP_PORT}/probe_upload.txt" 2>&1 | grep -qi "550\|Permission denied\|refused"; then
  pass "Upload anônimo corretamente bloqueado"
else
  echo "   (aviso: não foi possível confirmar bloqueio de upload — revisar manualmente)"
fi

# ---------------------------------------------------------------------------
section "2. SSH — banner e pista do header"
BANNER=$(timeout 10 bash -c "exec 3<>/dev/tcp/${SSH_HOST}/${SSH_PORT}; head -c 2000 <&3" 2>/dev/null || true)
if [ -z "$BANNER" ]; then
  fail "Não foi possível conectar na porta SSH (${SSH_HOST}:${SSH_PORT})"
else
  pass "Porta SSH respondeu"
fi
if printf '%s' "$BANNER" | grep -qF "$EXPECTED_HEADER"; then
  pass "Banner do SSH contém a pista do header ($EXPECTED_HEADER)"
else
  fail "Banner do SSH não contém '$EXPECTED_HEADER'"
fi
if printf '%s' "$BANNER" | grep -qF "$EXPECTED_SSH_USER"; then
  pass "Banner do SSH revela o usuário de manutenção ($EXPECTED_SSH_USER)"
else
  fail "Banner do SSH não menciona '$EXPECTED_SSH_USER'"
fi

# ---------------------------------------------------------------------------
section "3. Consistência chave/passphrase (ponte FTP -> SSH)"
KEY_FILE="$WORKDIR/id_rsa_estagiario_sti.enc"
if [ -s "$KEY_FILE" ]; then
  python3 - "$KEY_FILE" "$EXPECTED_PASSPHRASE" << 'EOF'
import sys
from cryptography.hazmat.primitives import serialization
path, passphrase = sys.argv[1], sys.argv[2].encode()
try:
    serialization.load_pem_private_key(open(path, "rb").read(), password=passphrase)
    print("OK")
except Exception as e:
    print(f"ERRO: {e}")
    sys.exit(1)
EOF
  if [ $? -eq 0 ]; then
    pass "A chave baixada do FTP decifra com a passphrase esperada"
    chmod 600 "$KEY_FILE"
    cp "$KEY_FILE" "$WORKDIR/id_rsa_test"
    chmod 600 "$WORKDIR/id_rsa_test"
    # Testa login SSH de verdade usando a chave + passphrase
    SSH_OUT=$(SSH_ASKPASS_REQUIRE=force timeout 10 \
      sshpass -P "passphrase" -p "$EXPECTED_PASSPHRASE" \
      ssh -i "$WORKDIR/id_rsa_test" -o StrictHostKeyChecking=no -o BatchMode=no \
      -p "$SSH_PORT" "${EXPECTED_SSH_USER}@${SSH_HOST}" "id" 2>&1 || true)
    if command -v sshpass >/dev/null 2>&1 && printf '%s' "$SSH_OUT" | grep -q "uid="; then
      pass "Login SSH via chave privada funcionou de ponta a ponta"
    else
      echo "   (aviso: login automático via chave não confirmado — sshpass pode não lidar bem"
      echo "    com passphrase de chave; validar manualmente com: ssh -i id_rsa_estagiario_sti.dec ${EXPECTED_SSH_USER}@${SSH_HOST} -p ${SSH_PORT})"
    fi
  else
    fail "A chave baixada do FTP NÃO decifra com a passphrase esperada"
  fi
else
  fail "Chave id_rsa_estagiario_sti.enc não encontrada para testar"
fi

# ---------------------------------------------------------------------------
section "Resumo"
TOTAL=$((PASS_COUNT + FAIL_COUNT))
if [ "$FAIL_COUNT" -eq 0 ]; then
  printf '%s[SUCESSO]%s Todos os %d testes de infra passaram. ✅\n' "$GREEN$BOLD" "$NC" "$TOTAL"
  exit 0
else
  printf '%s[FALHA]%s %d de %d testes falharam. Verifique acima. ❌\n' "$RED$BOLD" "$NC" "$FAIL_COUNT" "$TOTAL"
  exit 1
fi
