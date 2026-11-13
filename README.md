[README.md](https://github.com/user-attachments/files/34778316/README.md)
# Infra — SIGAA-Next CTF 

Estrutura 

```
infra/
├── docker-compose.yml          # substitui/estende o compose atual (postgres + backend + ftp-ssh)
├── verify.sh                   # valida a camada de infra (FTP/SSH) de ponta a ponta
├── README.md                   # este arquivo
└── ftp-ssh/
    ├── Dockerfile
    ├── entrypoint.sh
    ├── vsftpd.conf
    ├── issue.net                # banner do SSH (pista do header)
    ├── sshd_ctf.conf             # drop-in de /etc/ssh/sshd_config.d/
    ├── keys/
    │   ├── id_rsa_estagiario_sti.enc   # privada cifrada (mesmo arquivo do FTP)
    │   └── id_rsa_estagiario_sti.pub   # pública -> authorized_keys no container
    └── ftp-content/              # tudo que fica no /srv/ftp (FTP anônimo)
        ├── changelog_api.txt
        ├── swagger_old.json
        ├── nota_dev.txt
        ├── credenciais_teste.txt     # rabbit hole #1
        └── id_rsa_estagiario_sti.enc
```


## Subir o ambiente

```bash
docker compose up --build -d
```

Portas expostas (todas configuráveis via variável de ambiente, pra evitar
conflito na máquina de quem for rodar):

| Serviço | Porta padrão | Variável |
|---|---|---|
| API (front+back) | 3000 | `API_HOST_PORT` |
| FTP | 21 | `FTP_HOST_PORT` |
| SSH | **2222** (não 22, pra não brigar com o SSH do host) | `SSH_HOST_PORT` |

Exemplo: `SSH_HOST_PORT=2022 docker compose up -d`

## Validar a infra

```bash
./infra/verify.sh
# ou, se as portas publicadas forem diferentes do padrão:
FTP_PORT=21 SSH_PORT=2222 ./infra/verify.sh
```

Esse script testa **só a camada de infra**:
FTP anônimo (lista/baixa as pistas, bloqueia upload), banner do SSH com a
pista do header, e se a chave baixada do FTP realmente decifra com a
passphrase e loga por SSH. As vulnerabilidades da API continuam sendo
validadas pelo `exploit_test.sh` — são scripts irmãos,
cada um testando sua própria camada.

## Reset completo (voltar ao estado inicial)

```bash
docker compose down -v
docker compose up --build -d
```

## Pontos que ainda precisam de alinhamento

- **Integrante 4 (privesc/flags):** o `entrypoint.sh` já tem um hook —
  se existir `/opt/ctf/privesc-init.sh` dentro do container `ftp-ssh`,
  ele roda automaticamente antes de subir os serviços. É lá que entram
  a criação do `coord_redes` (user2), a configuração do `sudo -l` /
  cron vulneráveis e o plantio das flags `TAC{...}`. Falta decidir com
  ele se os usuários de privesc moram no mesmo container `ftp-ssh` ou
  em outro — hoje assumi que sim, porque é o container que tem o SSH.
- **Header do banner:** usei `X-Origin-System: SGI-v2`, que é o valor
  real usado no `exploit_test.sh` do Integrante 3 (o diagrama Mermaid
  antigo do planejamento citava `X-Internal-Env`, mas isso já está
  resolvido — o nome oficial é `X-Origin-System`).
- **Porta do Postgres:** removi a publicação da porta 5433 pro host no
  `docker-compose.yml` (o banco só precisa ser acessível *dentro* da
  rede do compose). Se alguém do grupo depende de conectar direto nela
  pra debugar, avisar que dá pra voltar fácil.
- **IP/host de produção do FTP:** se o desafio for publicado com IP ou
  domínio fixo (em vez de testado só em localhost), setar a variável
  `PASV_ADDRESS` no `docker-compose.yml` do serviço `ftp-ssh`, senão o
  modo passivo do FTP pode não funcionar fora da rede local.
