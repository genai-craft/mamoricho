// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// 単体版の HTTP サーバー: ログイン・/api/v1 の経路 (言箱 OS と同じ道具の並び)・画面 (ui/ + shell)。外部依存なし (node の http だけ)。
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';
import { HttpError, id } from '../util.js';
import { createMamoricho, SETS, ADMIN_RULES, ADMIN_NOTE } from '../index.js';
import { createStandalone } from './ports.mjs';

const HERE = path.dirname(new URL(import.meta.url).pathname); const UI = path.join(HERE, 'ui'); const PKG_UI = path.join(HERE, '..', 'ui');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json' };
const STATIC = { '/': path.join(UI, 'index.html'), '/index.html': path.join(UI, 'index.html'), '/shell.js': path.join(UI, 'shell.js'), '/shell.css': path.join(UI, 'shell.css'), '/mamoricho.js': path.join(PKG_UI, 'mamoricho.js'), '/icon.svg': path.join(UI, 'icon.svg') };

export function createServer({ dataDir, config = {} } = {}) {
  const sa = createStandalone(dataDir, config); const { ports, auth, approvals, notifications } = sa;
  const cfg = { probe: { decision_head: null }, llm: config.llm || {} };
  const mk = createMamoricho(cfg, ports); const { probe, mm, authz, inquiry } = mk;
  const routes = [];
  const route = (method, pattern, handler, opts = {}) => { const keys = []; const re = new RegExp('^' + pattern.replace(/\/:([a-zA-Z_]+)(\.sh)?/g, (m, k, ext) => { keys.push(k); return ext ? '/([^/]+?)\\.sh' : '/([^/]+)'; }) + '/?$'); routes.push({ method, re, keys, handler, opts }); };
  const send = (res, status, body, headers = {}) => { const isObj = body !== null && typeof body === 'object' && !Buffer.isBuffer(body); res.writeHead(status, { 'content-type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-frame-options': 'SAMEORIGIN', 'referrer-policy': 'no-referrer', ...headers }); res.end(isObj ? JSON.stringify(body) : body); };
  const cookie = (req, name) => (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))?.slice(name.length + 1) || null;
  const base = (req) => `${req.headers['x-forwarded-proto'] || (config.tls?.cert ? 'https' : 'http')}://${req.headers.host}`;
  const ipOf = (req) => (req.socket.remoteAddress || '').replace('::ffff:', '');
  const requireReauthToken = (req, actor) => auth.requireReauth(actor, req.headers['x-reauth-token'] || null);

  // ---- 認証 ----
  route('POST', '/api/v1/auth/login', ({ body, req, res }) => { const r = auth.login({ username: body.username, password: body.password, ip: ipOf(req), userAgent: req.headers['user-agent'] }); res.setHeader('set-cookie', `aios_session=${r.token}; Path=/; HttpOnly; SameSite=Lax${config.tls?.cert ? '; Secure' : ''}`); return { user: r.user }; }, { public: true });
  route('POST', '/api/v1/auth/logout', ({ actor, res }) => { auth.logout(actor); res.setHeader('set-cookie', 'aios_session=; Path=/; Max-Age=0'); return { ok: true }; });
  route('GET', '/api/v1/auth/me', ({ actor }) => ({ user: actor }));
  route('POST', '/api/v1/auth/reauth', ({ actor, body }) => auth.reauth(actor, body.password));
  route('GET', '/api/v1/setup', () => ({ needs_setup: auth.users().length === 0 }), { public: true });
  route('GET', '/api/v1/users', ({ actor }) => { ports.requireRole(actor, 'admin'); return { users: auth.users() }; });
  route('POST', '/api/v1/users', ({ actor, body, req }) => { requireReauthToken(req, actor); return auth.createUser(actor, body || {}); }, { role: 'admin' });
  route('GET', '/api/v1/approvals', ({ query }) => approvals.list({ state: query.state || null }));
  route('POST', '/api/v1/approvals/:id/decide', ({ actor, params, body }) => approvals.decide(actor, params.id, body.decision, body.reason), { role: 'operator' });
  route('GET', '/api/v1/notifications', () => ({ notifications: notifications.list() }));
  route('POST', '/api/v1/notifications/:id/read', ({ params }) => { notifications.markRead(params.id); return { ok: true }; });
  route('GET', '/api/v1/system/health', () => ({ ok: true, audit: sa.verifyAuditChain(), llm: ports.llm ? { provider: ports.llm.provider, model: ports.llm.model, local: ports.llm.local } : null }));
  // ---- 調査 (台帳) ----
  route('GET', '/api/v1/probe/targets', ({ actor }) => ({ targets: probe.listTargets(actor) }), { role: 'operator' });
  route('POST', '/api/v1/probe/targets', ({ actor, body, req }) => { requireReauthToken(req, actor); return probe.addTarget(actor, body || {}); }, { role: 'admin' });
  route('PATCH', '/api/v1/probe/targets/:id', ({ actor, params, body }) => probe.updateTarget(actor, params.id, body || {}), { role: 'admin' });
  route('POST', '/api/v1/probe/targets/:id/revoke', ({ actor, params, body }) => probe.markRevoked(actor, params.id, body || {}), { role: 'admin' });
  route('DELETE', '/api/v1/probe/targets/:id', ({ actor, params, query }) => probe.removeTarget(actor, params.id, { purge_runs: query.purge === '1' }), { role: 'admin' });
  route('POST', '/api/v1/probe/enroll', ({ actor, body, req }) => { requireReauthToken(req, actor); const r = probe.enrollStart(actor, body || {}); const scriptUrl = `${base(req)}/api/v1/probe/enroll/${r.token}.sh`; return { ...r, script_url: scriptUrl, one_liner: `curl -fsSL '${scriptUrl}' | sh`, vendor_message: probe.vendorMessage({ name: body?.name || '対象の機械', scriptUrl }) }; }, { role: 'admin' });
  route('POST', '/api/v1/probe/targets/:id/enroll/renew', ({ actor, params, req }) => { const r = probe.enrollRenew(actor, params.id); const t = probe.getTarget(params.id); ports.audit({ actor, action: r.reenroll ? 'probe.reenroll_start' : 'probe.enroll_renew', target: params.id }); const scriptUrl = `${base(req)}/api/v1/probe/enroll/${r.token}.sh`; return { ...r, script_url: scriptUrl, one_liner: `curl -fsSL '${scriptUrl}' | sh`, vendor_message: probe.vendorMessage({ name: t?.name || '対象の機械', scriptUrl }) }; }, { role: 'admin' });
  route('GET', '/api/v1/probe/enroll/:token.sh', ({ params, req, res }) => { res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }); res.end(probe.enrollScript(params.token, base(req))); return null; }, { public: true });
  route('POST', '/api/v1/probe/enroll/:token/done', ({ params, body, req }) => probe.enrollDone(params.token, body || {}, ipOf(req)), { public: true });
  route('GET', '/api/v1/probe/discover', ({ actor }) => probe.discover(actor).then(candidates => ({ candidates })), { role: 'operator' });
  route('POST', '/api/v1/probe/targets/:id/test', ({ actor, params }) => probe.testTarget(actor, params.id), { role: 'operator' });
  route('POST', '/api/v1/probe/classify', ({ actor, body }) => probe.classifyPreview(actor, body || {}), { role: 'operator' });
  route('POST', '/api/v1/probe/run', ({ actor, body }) => probe.run(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/probe/runs', ({ actor, query }) => ({ runs: probe.listRuns(actor, { target_id: query.target_id || null, limit: Math.min(Number(query.limit) || 50, 200) }) }), { role: 'operator' });
  route('GET', '/api/v1/probe/runs/:id/output', ({ actor, params }) => probe.runOutput(actor, params.id), { role: 'operator' });
  // ---- まもり帳 ----
  route('GET', '/api/v1/mamoricho/summary', ({ actor }) => mm.summary(actor));
  route('GET', '/api/v1/mamoricho/brand', () => ({ brand: ports.brand }));
  route('GET', '/api/v1/mamoricho/checklist', ({ actor }) => mm.checklist(actor));
  route('POST', '/api/v1/mamoricho/answer', ({ actor, body }) => mm.answer(actor, body || {}), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/interview', ({ actor, body }) => mm.interview(actor, body || {}), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/consult', ({ actor, body }) => mm.consult(actor, body || {}));
  route('GET', '/api/v1/mamoricho/selfcheck', ({ actor, query }) => mm.selfCheck(actor, { save: query.save === '1' }));
  route('POST', '/api/v1/mamoricho/review/close', ({ actor, body }) => mm.closeReview(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/records', ({ actor, query }) => ({ records: mm.records(actor, { limit: Math.min(Number(query.limit) || 200, 1000), kind: query.kind || null }), chain: mm.verify(actor) }));
  route('GET', '/api/v1/mamoricho/templates', () => ({ templates: mm.templates() }));
  route('POST', '/api/v1/mamoricho/probe/run', ({ actor, body }) => mm.runTemplate(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/emergency', ({ actor }) => ({ settings: mm.settings(), notes: mm.records(actor, { kind: 'incident_note', limit: 100 }) }));
  route('PUT', '/api/v1/mamoricho/emergency', ({ actor, body }) => mm.saveSettings(actor, body || {}), { role: 'admin' });
  route('GET', '/api/v1/mamoricho/deadlines', ({ query }) => mm.deadlines(query.discovered_at));
  route('POST', '/api/v1/mamoricho/incident/note', ({ actor, body }) => mm.addIncidentNote(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/safety', ({ actor }) => mm.safety(actor));
  route('POST', '/api/v1/mamoricho/incident/run', ({ actor, body }) => mm.runIncident(actor, body || {}), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/inquiry', ({ actor, body }) => inquiry.start(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/inquiries', ({ actor }) => inquiry.list(actor));
  route('GET', '/api/v1/mamoricho/inquiry/:id', ({ actor, params }) => inquiry.get(actor, params.id));
  route('POST', '/api/v1/mamoricho/inquiry/:id/run', ({ actor, params }) => inquiry.run(actor, { id: params.id }), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/inquiry/:id/ask', ({ actor, params, body }) => inquiry.ask(actor, { id: params.id, text: body?.text }), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/set/run', ({ actor, body }) => mm.runSet(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/sets', ({ query }) => { const kind = query.kind || 'ssh'; return { kind, sets: Object.entries(SETS).filter(([, d]) => d.kinds.includes(kind)).map(([sid, d]) => ({ id: sid, label: d.label, note: d.note, kinds: d.kinds, count: d.ids(kind).length, ids: d.ids(kind) })) }; });
  route('GET', '/api/v1/mamoricho/snapshots', ({ actor, query }) => ({ snapshots: mm.snapshots(actor, { target_id: query.target_id || null, limit: Math.min(Number(query.limit) || 50, 200) }) }));
  route('GET', '/api/v1/mamoricho/snapshots/compare', ({ actor, query }) => mm.compareSnapshots(actor, { a: query.a, b: query.b }), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/snapshots/:id', ({ actor, params }) => mm.snapshot(actor, params.id));
  route('POST', '/api/v1/mamoricho/incident/report', ({ actor, body }) => mm.draftReport(actor, body || {}), { role: 'operator' });
  // ---- 管理者監視・API 認可 ----
  route('GET', '/api/v1/probe/admin/events', ({ actor, query }) => ({ events: mm.adminEvents(actor, { target_id: query.target_id || null, limit: Math.min(Number(query.limit) || 200, 1000), since: query.since || null }) }));
  route('GET', '/api/v1/probe/admin/findings', ({ actor }) => ({ findings: mm.adminFindings(actor), rules: ADMIN_RULES, note: ADMIN_NOTE }));
  route('POST', '/api/v1/probe/admin/self', ({ actor, body }) => mm.selfAdminCheck(actor, { save: body?.save !== false }), { role: 'operator' });
  route('POST', '/api/v1/probe/admin/analyze', ({ actor, body }) => mm.adminAnalyze(actor, body || {}), { role: 'operator' });
  route('POST', '/api/v1/probe/authz/import', ({ actor, body }) => authz.importSpec(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/probe/authz/operations', ({ actor, query }) => authz.operations(actor, query.target_id));
  route('GET', '/api/v1/probe/authz/actors', ({ actor, query }) => ({ actors: authz.actors(actor, query.target_id) }));
  route('POST', '/api/v1/probe/authz/actors', ({ actor, body, req }) => { requireReauthToken(req, actor); return authz.upsertActor(actor, body || {}); }, { role: 'admin' });
  route('DELETE', '/api/v1/probe/authz/actors/:id', ({ actor, params, query }) => authz.deleteActor(actor, query.target_id, params.id), { role: 'admin' });
  route('GET', '/api/v1/probe/authz/policies', ({ actor, query }) => ({ versions: authz.policies(actor, query.target_id), current: authz.operations(actor, query.target_id).policy }));
  route('POST', '/api/v1/probe/authz/policies', ({ actor, body }) => authz.savePolicy(actor, body || {}), { role: 'admin' });
  route('POST', '/api/v1/probe/authz/suggest', ({ actor, body }) => authz.suggest(actor, body || {}), { role: 'operator' });
  route('POST', '/api/v1/probe/authz/plans', ({ actor, body }) => authz.createPlan(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/probe/authz/plans', ({ actor, query }) => ({ plans: authz.plans(actor, query.target_id) }));
  route('GET', '/api/v1/probe/authz/plans/:id', ({ actor, params }) => authz.plan(actor, params.id));
  route('POST', '/api/v1/probe/authz/runs', ({ actor, body }) => authz.run(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/probe/authz/runs', ({ actor, query }) => ({ runs: authz.runs(actor, { target_id: query.target_id || null, limit: Math.min(Number(query.limit) || 50, 200) }) }));
  route('GET', '/api/v1/probe/authz/runs/:id', ({ actor, params }) => authz.getRun(actor, params.id));
  route('GET', '/api/v1/probe/authz/status', ({ actor, query }) => { ports.requireRole(actor, 'viewer'); return authz.status(query.target_id); });
  route('GET', '/api/v1/probe/security-summary', ({ actor }) => mm.securitySummary(actor));

  async function handle(req, res) {
    const url = new URL(req.url, 'http://x'); const p = url.pathname; const reqId = id('req');
    try {
      if (!p.startsWith('/api/')) { const f = STATIC[p] || (path.extname(p) ? null : STATIC['/']); if (!f || !fs.existsSync(f)) return send(res, 404, 'not found'); res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream', 'cache-control': 'no-cache' }); return fs.createReadStream(f).pipe(res); }
      const r = routes.find(x => x.method === req.method && x.re.test(p)); if (!r) throw new HttpError(404, 'not_found', 'この経路はありません');
      const m = p.match(r.re); const params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])])); const query = Object.fromEntries(url.searchParams);
      let body = {}; if (['POST', 'PUT', 'PATCH'].includes(req.method)) { const chunks = []; let n = 0; for await (const c of req) { n += c.length; if (n > 8 << 20) throw new HttpError(413, 'too_large', '大きすぎます'); chunks.push(c); } const raw = Buffer.concat(chunks).toString('utf8'); if (raw) { try { body = JSON.parse(raw); } catch { throw new HttpError(400, 'bad_json', 'JSON を読めません'); } } }
      const actor = auth.sessionActor(cookie(req, 'aios_session'));
      if (!r.opts.public) { if (!actor) throw new HttpError(401, 'unauthenticated', 'ログインが必要です'); if (r.opts.role) ports.requireRole(actor, r.opts.role); }
      const out = await r.handler({ req, res, actor, params, query, body }); if (out === null) return; send(res, 200, out);
    } catch (e) {
      const isHttp = typeof e?.status === 'number' && typeof e?.code === 'string'; if (!isHttp) console.error(`[${reqId}] ${req.method} ${p}`, e);
      send(res, isHttp ? e.status : 500, { error: { code: e.code || 'internal', message: isHttp ? e.message : '内部エラーが発生しました', ...(e.extra || {}), request_id: reqId } });
    }
  }
  const server = config.tls?.cert ? https.createServer({ cert: fs.readFileSync(config.tls.cert), key: fs.readFileSync(config.tls.key) }, handle) : http.createServer(handle);
  return { server, ports, mm, probe, authz, inquiry, auth, standalone: sa, start() { mm.start(); return this; }, stop() { mm.stop(); server.close(); } };
}
