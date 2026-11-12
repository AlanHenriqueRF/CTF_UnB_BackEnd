/* =====================================================================
 * SIGAA-Next · Portal Discente (STI / UnB-Next) — Homologação
 * app.js — client SPA que consome a API REST em /api/v1/...
 * ---------------------------------------------------------------------
 * NOTA DEV (Lucas / Bolsista STI):
 *   O portal exibe APENAS os dados públicos retornados pela API.
 *   Campos internos (login_linux, role, notas) NÃO são renderizados
 *   na tela — mas o back-end ainda os envia no JSON (ver aba Network).
 *   Pendência: pedir revisão do serializer de /api/v1/staff.
 *
 * Mapa de rotas da API (v2.1.0-homolog):
 *   GET  /api/v1/status
 *   GET  /api/v1/staff
 *   GET  /api/v1/courses/search?dept=CIC   <- usada pela "Consulta Geral
 *                                             de Componentes Curriculares"
 *                                             (Ensino > Consultas Gerais).
 *                                             Query legada concatenada!
 *   GET  /api/v1/profile
 *   PUT  /api/v1/profile            -> body: { "theme": "dark" }
 *
 * // TODO (remover antes de PRODUÇÃO):
 * // Rotas administrativas internas — não listar na navegação pública:
 * //   GET  /api/v1/users/104/drafts          (rascunhos do estagiário)
 * //   POST /api/v1/admin/system-check         (diagnóstico — exige role=admin + header X-Origin-System)
 * // Lembrete do Marcos (Coord. Redes): o system-check só responde se vier
 * // o header do Gateway interno. O valor está documentado no banner do SSH (porta 22).
 * ===================================================================== */

(function () {
  'use strict';

  const API = '/api/v1';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const on = (el, ev, fn) => { if (el) el.addEventListener(ev, fn); };

  const escapeHtml = (s) =>
    String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');

  /* ------------------------------------------------------------------
   * 1) Status da API ("Situação do Sistema" na lateral)
   * ---------------------------------------------------------------- */
  async function loadStatus() {
    try {
      const res = await fetch(`${API}/status`);
      const data = await res.json();
      const apiEl = $('#stat-api');
      if (apiEl) { apiEl.textContent = 'operacional'; apiEl.style.color = 'var(--green)'; }
      if ($('#stat-version')) $('#stat-version').textContent = data.version || '—';
      if ($('#stat-gateway')) $('#stat-gateway').textContent = data.gateway_status || '—';
      if (data.version && $('#footer-version')) $('#footer-version').textContent = 'v' + data.version;
    } catch (e) {
      if ($('#stat-api')) $('#stat-api').textContent = 'offline';
    }
  }

  /* ------------------------------------------------------------------
   * 2) Quadro de Servidores (STI) — tabela de listagem estilo SIGAA.
   *    Renderiza SOMENTE registros públicos (visivel_front === true).
   *    Campos internos do JSON são descartados de propósito na UI.
   * ---------------------------------------------------------------- */
  async function loadStaff() {
    const statusEl = $('#staff-status');
    const table = $('#staff-table');
    const tbody = $('#staff-tbody');
    if (!statusEl || !table || !tbody) return;
    try {
      const res = await fetch(`${API}/staff`);
      const payload = await res.json();
      const list = (payload.data || []).filter((m) => m.visivel_front === true);

      if (!list.length) {
        statusEl.textContent = 'Nenhum servidor público cadastrado.';
        return;
      }

      tbody.innerHTML = list
        .map((m, i) => `
          <tr class="${i % 2 ? 'linhaImpar' : 'linhaPar'}">
            <td class="staff-name">${escapeHtml(m.nome)}</td>
            <td>${escapeHtml(m.matricula)}</td>
            <td>${escapeHtml(m.cargo)}</td>
            <td>${escapeHtml(m.departamento)}</td>
            <td><a href="mailto:${escapeHtml(m.email)}">${escapeHtml(m.email)}</a></td>
          </tr>`)
        .join('');

      statusEl.hidden = true;
      table.hidden = false;
    } catch (e) {
      statusEl.textContent = 'Falha ao carregar o quadro de servidores do STI. Tente novamente mais tarde.';
    }
  }

  /* ------------------------------------------------------------------
   * 3) Consulta Geral de Componentes Curriculares
   *    (Ensino > Consultas Gerais > Consultar Componente Curricular)
   *    GET /courses/search?dept=<texto digitado>
   *    OBS: o valor do campo "Código" vai direto para a querystring
   *    e o back-end legado concatena na SQL — ponto de injeção.
   * ---------------------------------------------------------------- */
  async function searchComponentes(term) {
    const statusEl = $('#comp-status');
    const box = $('#comp-resultado');
    const table = $('#comp-table');
    const tbody = $('#comp-tbody');
    const count = $('#comp-count');
    if (!statusEl || !box || !tbody) return;

    statusEl.hidden = false;
    statusEl.textContent = 'Buscando componentes curriculares…';
    box.hidden = true;

    try {
      const res = await fetch(`${API}/courses/search?dept=${encodeURIComponent(term)}`);
      const data = await res.json();
      const rows = data.results || [];

      if (!Array.isArray(rows) || !rows.length) {
        statusEl.textContent = `Nenhum componente curricular encontrado para "${term}".`;
        return;
      }

      tbody.innerHTML = rows
        .map((c, i) => `
          <tr class="${i % 2 ? 'linhaImpar' : 'linhaPar'}">
            <td><strong>${escapeHtml(c.codigo)}</strong></td>
            <td>${escapeHtml(c.nome)}</td>
            <td>${escapeHtml(c.professor)}</td>
            <td>${escapeHtml(c.semestre)}</td>
            <td>${escapeHtml(c.vagas)}</td>
          </tr>`)
        .join('');

      if (count) count.textContent = String(rows.length);
      statusEl.hidden = true;
      box.hidden = false;
    } catch (e) {
      statusEl.textContent = 'Erro ao consultar os componentes curriculares.';
    }
  }

  /* ------------------------------------------------------------------
   * 4) Tema (claro/escuro) + sincronização com o perfil
   *    PUT /api/v1/profile  body: { theme }
   * ---------------------------------------------------------------- */
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('sigaa_theme', theme); } catch (e) {}
  }
  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') || 'light';
  }
  async function saveThemeToProfile(theme) {
    const feedback = $('#theme-feedback');
    if (feedback) feedback.textContent = 'Sincronizando com o perfil…';
    try {
      // Preferência enviada ao back-end. O front só manda { theme }.
      const res = await fetch(`${API}/profile`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ theme: theme })
      });
      const data = await res.json();
      // Guarda o token de sessão devolvido pela API para chamadas autenticadas.
      if (data.token) { try { sessionStorage.setItem('sigaa_token', data.token); } catch (e) {} }
      if (feedback) feedback.textContent = 'Tema salvo no seu perfil com sucesso.';
    } catch (e) {
      if (feedback) feedback.textContent = 'Não foi possível sincronizar o tema agora.';
    }
  }

  /* ------------------------------------------------------------------
   * 5) Módulo "Administração" (validação APENAS client-side)
   * ---------------------------------------------------------------- */
  function openAdminModal() {
    const modal = $('#admin-modal');
    const text = $('#admin-modal-text');
    if (!modal || !text) return;
    modal.hidden = false;
    text.textContent = 'Validando sua sessão junto ao Gateway interno…';

    const token = (function () {
      try { return sessionStorage.getItem('sigaa_token'); } catch (e) { return null; }
    })();

    fetch(`${API}/admin/system-check`, {
      method: 'POST',
      headers: Object.assign(
        { 'Content-Type': 'application/json' },
        token ? { Authorization: 'Bearer ' + token } : {}
      ),
      body: JSON.stringify({})
    })
      .then((r) => r.json().then((j) => ({ status: r.status, body: j })))
      .then(({ status, body }) => {
        if (status === 200) {
          text.textContent = 'Acesso administrativo concedido. Redirecionando ao painel…';
        } else {
          text.textContent =
            'Acesso negado (' + status + '). Este módulo é restrito à coordenação do STI. ' +
            (body && body.hint ? body.hint : '');
        }
      })
      .catch(() => { text.textContent = 'Não foi possível validar o acesso administrativo no momento.'; });
  }

  /* ------------------------------------------------------------------
   * 6) Navegação entre "telas" (Portal Discente x Consulta)
   * ---------------------------------------------------------------- */
  function showView(name) {
    $$('.view').forEach((v) => (v.hidden = true));
    const bcExtra = $('#bc-extra');
    const bcTxt = $('#bc-extra-txt');
    if (name === 'componentes') {
      $('#view-componentes').hidden = false;
      if (bcExtra && bcTxt) { bcExtra.hidden = false; bcTxt.textContent = 'Consulta Geral de Componentes Curriculares'; }
    } else {
      $('#view-home').hidden = false;
      if (bcExtra) bcExtra.hidden = true;
    }
    closeMenus();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function closeMenus() {
    const se = $('#submenu-ensino');
    const sc = $('#submenu-consultas');
    const li = $('#li-ensino');
    if (se) se.hidden = true;
    if (sc) sc.hidden = true;
    if (li) li.classList.remove('aberto');
  }

  /* ------------------------------------------------------------------
   * Bootstrap
   * ---------------------------------------------------------------- */
  function init() {
    let saved = 'light';
    try { saved = localStorage.getItem('sigaa_theme') || 'light'; } catch (e) {}
    applyTheme(saved);

    loadStatus();
    loadStaff();

    // Tema (contraste) — PUT /profile (Mass Assignment vector)
    on($('#theme-toggle'), 'click', (ev) => {
      ev.preventDefault();
      const next = currentTheme() === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      saveThemeToProfile(next);
    });
    on($('#save-theme'), 'click', (ev) => {
      ev.preventDefault();
      saveThemeToProfile(currentTheme());
    });

    // Menu Ensino (dropdown)
    on($('#menu-ensino-btn'), 'click', (ev) => {
      ev.preventDefault();
      const se = $('#submenu-ensino');
      const li = $('#li-ensino');
      const abrir = se && se.hidden;
      closeMenus();
      if (abrir) { se.hidden = false; if (li) li.classList.add('aberto'); }
    });
    // Submenu "Consultas Gerais"
    on($('#sm-consultas'), 'mouseenter', () => { const sc = $('#submenu-consultas'); if (sc) sc.hidden = false; });
    on($('#sm-consultas'), 'click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      const sc = $('#submenu-consultas');
      if (sc) sc.hidden = false;
    });
    // Abrir a consulta de componente curricular (tela da SQLi)
    on($('#link-consultar-componente'), 'click', (ev) => {
      ev.preventDefault();
      showView('componentes');
    });
    // Voltar ao Portal Discente
    on($('#bc-home'), 'click', (ev) => { ev.preventDefault(); showView('home'); });

    // Fecha menus ao clicar fora
    document.addEventListener('click', (ev) => {
      if (!ev.target.closest('#li-ensino')) closeMenus();
    });

    // Formulário de consulta de componente curricular
    on($('#comp-form'), 'submit', (ev) => {
      ev.preventDefault();
      const codigo = ($('#comp-codigo') ? $('#comp-codigo').value.trim() : '');
      const nome = ($('#comp-nome') ? $('#comp-nome').value.trim() : '');
      const term = codigo || nome || 'CIC';
      searchComponentes(term);
    });
    on($('#comp-cancelar'), 'click', () => showView('home'));

    // Módulo admin (reativável via DevTools — validação é só visual)
    on($('#btn-admin'), 'click', openAdminModal);
    $$('[data-close-modal]').forEach((b) =>
      on(b, 'click', () => { const m = $('#admin-modal'); if (m) m.hidden = true; })
    );

    // Permite abrir a consulta direto via hash (#componentes)
    if (location.hash === '#componentes') showView('componentes');
  }

  document.addEventListener('DOMContentLoaded', init);
})();
