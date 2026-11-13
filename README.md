# SIGAA-Next — CTF (Segurança Computacional / LabSec — UnB)

Máquina vulnerável de **Capture The Flag (CTF)** empacotada em Docker, com
temática de um portal acadêmico de homologação **fictício** ("SIGAA-Next / STI").
Exercício de Red Team **autorizado**, 100% isolado em containers e com **dados
inteiramente fictícios** — nenhum sistema real é envolvido.

---

## 🎯 Objetivo

Você atua como pentester num teste **autorizado** contra o ambiente de
homologação do novo portal acadêmico unificado da universidade. Partindo
**apenas da rede**, faça o reconhecimento dos serviços no ar, descubra e explore
as falhas da aplicação e conquiste acesso ao servidor. O desafio termina com a
captura das flags no formato `TAC{...}`.

> ℹ️ **Sem dicas aqui.** O caminho da exploração é justamente o desafio — este
> README traz só o necessário para **subir** e **atacar** a máquina. Boa caçada.

---

## ▶️ Como subir

Pré-requisitos: **Docker** e **Docker Compose**.

A partir da raiz do repositório:

```bash
docker compose -f infra/docker-compose.yml --project-directory . up -d --build
```

Isso constrói e sobe a máquina-alvo completa. Quando terminar, confirme que o
alvo está no ar abrindo o portal no navegador:

```
http://localhost:3000
```

A partir daí, o alvo é seu — comece pelo reconhecimento de rede.

> As portas publicadas no host são configuráveis por variáveis de ambiente (para
> evitar conflito na máquina de quem roda). Operadores que precisem remapeá-las
> encontram as variáveis no `infra/docker-compose.yml`.

---

## 🔄 Reset (voltar ao estado inicial)

```bash
docker compose -f infra/docker-compose.yml --project-directory . down -v
docker compose -f infra/docker-compose.yml --project-directory . up -d --build
```

O `down -v` remove os volumes, garantindo um banco limpo e re-populado do zero no
próximo start.

---

## ⚠️ Uso autorizado

Ambiente **educacional e autorizado** (disciplina de Tópicos avançados de computação(voltado para copetições do tipo CTF)). Toda a infraestrutura, usuários, credenciais e dados são **fictícios** e
existem apenas dentro dos containers. Não hospede este desafio exposto à internet
pública sem o devido controle de acesso.
```