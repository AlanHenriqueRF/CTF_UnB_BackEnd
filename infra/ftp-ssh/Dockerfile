# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        vsftpd \
        openssh-server \
        sudo \
        cron \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/run/sshd /srv/ftp /var/run/vsftpd/empty

# --- Usuário de manutenção (foothold) ---
# A senha de contingência (ESTAGIARIO_SSH_PASS) é aplicada em runtime pelo
# entrypoint.sh via variável de ambiente — nunca fica hardcoded na imagem.
RUN useradd -m -s /bin/bash estagiario_sti \
    && mkdir -p /home/estagiario_sti/.ssh \
    && chmod 700 /home/estagiario_sti/.ssh

# Chave pública correspondente à privada cifrada entregue via FTP
COPY keys/id_rsa_estagiario_sti.pub /home/estagiario_sti/.ssh/authorized_keys
RUN chmod 600 /home/estagiario_sti/.ssh/authorized_keys \
    && chown -R estagiario_sti:estagiario_sti /home/estagiario_sti/.ssh

# --- Conteúdo do FTP anônimo (pistas) ---
COPY ftp-content/ /srv/ftp/

# --- Configurações ---
COPY vsftpd.conf /etc/vsftpd.conf
COPY issue.net /etc/issue.net
COPY sshd_ctf.conf /etc/ssh/sshd_config.d/sshd_ctf.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# --- Ponto de integração do Integrante 4 (privesc / flags) ---
# A pasta privesc/ (neste contexto de build) traz o privesc-init.sh, copiado
# para /opt/ctf/ e executado automaticamente pelo entrypoint (hook de escalada).
COPY privesc/ /opt/ctf/
RUN chmod +x /opt/ctf/privesc-init.sh

# Portas: 21 (FTP controle), 21100-21110 (FTP passivo), 22 (SSH)
EXPOSE 21 22 21100-21110

ENTRYPOINT ["/entrypoint.sh"]
