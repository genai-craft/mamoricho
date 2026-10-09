// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// 単体版の殻 (shell): 画面 (ui/mamoricho.js) が組み込み先に求める 8 つの道具 — el / GET・POST… / toast / modal / confirmDialog / fmtTime / openWindow / routedApp — と、ログイン。
//   言箱 OS のデスクトップが持っているものの最小の写し。見た目は shell.css。
(() => {
  const AIOS = window.AIOS = { state: { me: null, ws: null }, apps: {}, windows: new Map() };
  const $ = (s, r = document) => r.querySelector(s);
  const el = (tag, attrs = {}, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) { if (v === undefined || v === null || v === false) continue; if (k === 'class') e.className = v; else if (k === 'style' && typeof v === 'object') Object.assign(e.style, v); else if (k === 'html') e.innerHTML = v; else if (k.startsWith('on') && typeof v === 'function') e[k] = v; else if (k in e && k !== 'list') { try { e[k] = v; } catch { e.setAttribute(k, v); } } else e.setAttribute(k, v === true ? '' : v); }
    const add = (kid) => { if (kid === null || kid === undefined || kid === false || kid === '') return; if (Array.isArray(kid)) return kid.forEach(add); e.append(kid instanceof Node ? kid : document.createTextNode(String(kid))); };
    kids.forEach(add); return e;
  };
  async function api(method, path, body, opts = {}) {
    const headers = { ...(opts.headers || {}) }; let payload = body;
    if (body !== undefined && !(body instanceof Blob) && !(body instanceof FormData)) { headers['content-type'] = 'application/json'; payload = JSON.stringify(body); }
    if (opts.reauth) headers['x-reauth-token'] = opts.reauth;
    const r = await fetch('/api/v1' + path, { method, headers, body: payload, credentials: 'same-origin' });
    const ct = r.headers.get('content-type') || ''; const data = ct.includes('json') ? await r.json() : await r.text();
    if (!r.ok) { if (r.status === 401 && AIOS.state.me) showLogin(); const e = new Error(data?.error?.message || `HTTP ${r.status}`); e.code = data?.error?.code; e.status = r.status; e.extra = data?.error; throw e; }
    return data;
  }
  const GET = (p) => api('GET', p), POST = (p, b, o) => api('POST', p, b, o), PATCH = (p, b) => api('PATCH', p, b), PUT = (p, b) => api('PUT', p, b), DEL = (p) => api('DELETE', p);
  function toast(msg, kind = '') { const t = el('div', { class: 'toast ' + kind }, msg); $('#toasts').append(t); setTimeout(() => t.remove(), kind === 'err' ? 7000 : 4000); }
  function modal(content, { onClose } = {}) { const m = $('#modal'); m.innerHTML = ''; m.classList.remove('hidden'); const d = el('div', { class: 'dialog' }); d.append(content); m.append(d); const close = () => { m.classList.add('hidden'); m.innerHTML = ''; onClose?.(); }; m.onclick = (e) => { if (e.target === m) close(); }; return { close, dialog: d }; }
  function confirmDialog({ title, body, okLabel = '実行する', danger = false, reauth = false }) {
    return new Promise((resolve) => {
      let pw; const c = el('div', {}, el('h2', {}, title), typeof body === 'string' ? el('p', { html: body }) : body);
      if (reauth) c.append(el('label', { class: 'lbl' }, 'この操作にはパスワードの再入力が必要です'), pw = el('input', { class: 'inp', type: 'password', autocomplete: 'current-password', style: { width: '100%' } }));
      const m = modal(c, { onClose: () => resolve(null) });
      c.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px', marginTop: '16px' } }, el('button', { class: 'btn', onclick: () => m.close() }, 'キャンセル'), el('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), onclick: async () => { let token = null; if (reauth) { try { token = (await POST('/auth/reauth', { password: pw.value })).reauth_token; } catch (e) { toast(e.message, 'err'); return; } } $('#modal').onclick = null; $('#modal').classList.add('hidden'); resolve({ ok: true, reauth: token }); } }, okLabel)));
      if (pw) setTimeout(() => pw.focus(), 50);
    });
  }
  const fmtTime = (iso) => { if (!iso) return '-'; const d = new Date(iso); return isNaN(d) ? String(iso) : d.toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }); };
  const prefs = { get: (k, fb) => { try { const v = localStorage.getItem('mamoricho.' + k); return v === null ? fb : JSON.parse(v); } catch { return fb; } }, set: (k, v) => { try { localStorage.setItem('mamoricho.' + k, JSON.stringify(v)); } catch { /* ignore */ } } };
  // 1 つのアプリだけの殻: 左に目次、右に中身 (言箱の routedApp と同じ約束: routes[key] = { label, icon, render(c, params), hidden, sep })
  function routedApp(win, { routes, defaultRoute, title }) {
    const side = el('div', { class: 'sidebar' }); const content = el('div', { class: 'content' }); win.body.append(side, content); const buttons = {};
    const render = (key, params) => { const r = routes[key]; if (!r) return; for (const b of Object.values(buttons)) b.classList.remove('active'); buttons[key]?.classList.add('active'); win.route = key; win.routeParams = params || null; content.innerHTML = ''; document.title = `${title} — ${r.label}`; prefs.set('route', key); const out = r.render(content, params || {}); if (out?.catch) out.catch(e => content.append(el('div', { class: 'notice err' }, e.message))); if (window.innerWidth < 900) side.classList.remove('open'); };
    for (const [key, r] of Object.entries(routes)) { if (r.sep) side.append(el('div', { class: 'sep' })); if (r.hidden) continue; buttons[key] = el('button', { onclick: () => render(key), title: r.label }, el('span', { class: 'ico' }, r.icon || '•'), el('span', { class: 'txt' }, ' ' + r.label)); side.append(buttons[key]); }
    win.navigate = render; win.content = content; render(defaultRoute && routes[defaultRoute] ? defaultRoute : Object.keys(routes)[0]); return { side, content, render };
  }
  function openWindow(appId, opts = {}) { const w = AIOS.windows.get(appId); if (w?.navigate && opts.route) w.navigate(opts.route, opts.params); return w; }
  function showLogin() { $('#login').classList.remove('hidden'); $('#top').classList.add('hidden'); $('#win').classList.add('hidden'); AIOS.state.me = null; }
  async function showApp() {
    $('#login').classList.add('hidden'); $('#top').classList.remove('hidden'); $('#win').classList.remove('hidden'); $('#top-user').textContent = `${AIOS.state.me.display_name || AIOS.state.me.username} (${AIOS.state.me.role})`;
    const body = $('#win'); body.innerHTML = ''; const win = { id: 'mamoricho', el: body, body, title: { set textContent(v) { document.title = v; } } }; AIOS.windows.set('mamoricho', win);
    await AIOS.apps.mamoricho.mount(win, { route: prefs.get('route', 'home') });
  }
  async function boot() {
    $('#login-form').onsubmit = async (e) => { e.preventDefault(); const f = new FormData(e.target); const msg = $('#login-msg'); msg.classList.add('hidden'); try { const r = await POST('/auth/login', { username: f.get('username'), password: f.get('password') }); AIOS.state.me = r.user; await showApp(); } catch (err) { msg.textContent = err.message; msg.classList.remove('hidden'); } };
    $('#logout').onclick = async () => { try { await POST('/auth/logout', {}); } catch { /* ignore */ } showLogin(); };
    try { const r = await GET('/auth/me'); AIOS.state.me = r.user; await showApp(); } catch { showLogin(); }
  }
  Object.assign(AIOS, { $, el, api, GET, POST, PATCH, PUT, DEL, toast, modal, confirmDialog, fmtTime, openWindow, routedApp, prefs, boot, refreshHome: () => {} });
  window.routedApp = routedApp; // ui/mamoricho.js は裸の名前でも呼ぶ
})();
