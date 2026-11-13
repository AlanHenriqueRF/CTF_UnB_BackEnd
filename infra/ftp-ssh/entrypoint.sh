#!/usr/bin/env bash
set -euo pipefail

log() { printf '[entrypoint] %s\n' "$*"; }

# --- 1. Host keys do SSH (geradas uma vez, persistem no volume se houver) ---
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
  log "Gerando host keys do SSH..."
  ssh-keygen -A
fi

# --- 2. Endereço para o modo passivo do FTP ---
# Em redes Docker, o client precisa receber o IP/host correto nas respostas PASV.
# PASV_ADDRESS pode ser definido via docker-compose (ex: nome do serviço ou IP público).
if [ -n "${PASV_ADDRESS:-}" ]; then
  log "Configurando pasv_address=${PASV_ADDRESS}"
  if grep -q '^pasv_address=' /etc/vsftpd.conf; then
    sed -i "s/^pasv_address=.*/pasv_address=${PASV_ADDRESS}/" /etc/vsftpd.conf
  else
    echo "pasv_address=${PASV_ADDRESS}" >> /etc/vsftpd.conf
  fi
fi

# --- 3. Senha de contingência do usuário de manutenção (via env, nunca hardcoded na imagem) ---
if [ -n "${ESTAGIARIO_SSH_PASS:-}" ]; then
  log "Aplicando senha de contingência para estagiario_sti"
  echo "estagiario_sti:${ESTAGIARIO_SSH_PASS}" | chpasswd
fi

# --- 3b. secure_chroot_dir do vsftpd (defensivo) ---
# O vsftpd exige que o diretório de 'secure_chroot_dir' exista, esteja vazio e
# não seja gravável, senão derruba toda sessão com "500 OOPS ... secure_chroot_dir".
# /var/run pode ser tmpfs em alguns runtimes, então recriamos sempre no boot.
mkdir -p /var/run/vsftpd/empty
chmod 555 /var/run/vsftpd/empty

# --- 4. Permissões (defensivo — garante que o build não deixou nada errado) ---
chmod 700 /home/estagiario_sti/.ssh 2>/dev/null || true
chmod 600 /home/estagiario_sti/.ssh/authorized_keys 2>/dev/null || true
chown -R estagiario_sti:estagiario_sti /home/estagiario_sti/.ssh 2>/dev/null || true

chmod -R a-w /srv/ftp
find /srv/ftp -type d -exec chmod a+rx {} \;
find /srv/ftp -type f -exec chmod a+r {} \;

# --- 5. Hook de integração: Integrante 4 (usuários user2/root, privesc, flags) ---
# Qualquer script colocado em /opt/ctf/privesc-init.sh (ver pasta privesc/ do repo)
# é executado aqui, ANTES de subir os serviços. Ele é responsável por criar o
# usuario2, configurar sudoers/cron vulneráveis e plantar as flags TAC{...}.
if [ -x /opt/ctf/privesc-init.sh ]; then
  log "Executando hook de privesc (Integrante 4)..."
  /opt/ctf/privesc-init.sh
else
  log "Nenhum hook de privesc encontrado em /opt/ctf/privesc-init.sh (ok em dev, obrigatório na integração final)"
fi

# --- 6. Serviços em background ---
log "Iniciando cron..."
service cron start

log "Iniciando vsftpd..."
/usr/sbin/vsftpd /etc/vsftpd.conf &

log "Iniciando sshd em foreground..."
exec /usr/sbin/sshd -D -e
