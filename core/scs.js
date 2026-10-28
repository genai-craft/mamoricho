// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// SCS 評価制度 (サプライチェーン強化に向けたセキュリティ対策評価制度) の★3・★4 の評価基準に沿った点検。
//   基準の原文は core/scs-criteria.js (経済産業省)、ふつうの言葉の質問と手がかりは core/scs-guide.js。
//   1 項目ずつ: 状態 (決めるのは人) と一言・改善の計画 (何を・誰が・いつまでに)・年 1 回 / 月 1 回の点検の実施日。
//   裏づけ: 箱 (OS) 自身の自己点検・まとめて診断の結果・台帳・規程・周知・監査ログ (ID の変更・使われていない ID)・脆弱性情報・管理者の見張り。
//   確認の流れ (★3 は「セキュリティ専門家の確認を経た自己評価」): 写しを固める → 専門家が項目ごとに助言 → 確認 (または差し戻し) → 経営層が宣誓。すべて記録の鎖に残す。
//   これは IPA への提出の様式ではない (様式は制度の開始までに IPA が公表する予定)。★の取得は制度の手続きによる
import { HttpError, id, nowIso, sha256, canonicalJson, J } from '../util.js';
import { SCS_CRITERIA, SCS_SOURCE } from './scs-criteria.js';
import { SCS_GUIDE, SCS_KINDS, SCS_CYCLE_DAYS } from './scs-guide.js';
import { STATUSES, byId as PPC } from './checklist.js';
import { LEDGER_BY_ID } from './ledgers.js';
import { POLICY_BY_ID } from './policy-templates.js';
import { collectFacts } from './scs-facts.js';
import { mdToDocx } from './docx.js';

const DAY = 86400e3;
export const SCS_CATEGORIES = [...new Map(SCS_CRITERIA.map(c => [c.cat_no, { no: c.cat_no, label: c.cat }])).values()];
const ID_ACTIONS = ['user.create', 'user.bulk_create', 'user.role_change', 'user.status_change', 'user.password_reset', 'setup.owner_created', 'user.executive'];
const inLevel = (c, level) => Number(level) >= 4 || c.level === 3;

export class Scs {
  constructor(cfg, ports, { mm, probe = null, ledgers = null, policies = null, notices = null } = {}) { Object.assign(this, { cfg, ports, mm, probe, ledgers, policies, notices }); this._cache = {}; }
  db() { return this.ports.db(); }
  // ---- 会社の情報 (規程のひな形にも使う)・専門家・経営層・取得の日付 ----
  profile() { return J.parse(this.db().prepare("SELECT value FROM mamoricho_settings WHERE key='scs_profile'").get()?.value, {}); }
  saveProfile(actor, patch = {}) {
    this.ports.requireRole(actor, 'admin'); const cur = this.profile(); const s = (v, n = 200) => String(v ?? '').trim().slice(0, n);
    const next = { ...cur };
    for (const k of ['company', 'ceo', 'lead', 'it', 'where', 'scope']) if (k in patch) next[k] = s(patch[k], k === 'scope' ? 2000 : 200);
    if ('target_level' in patch) next.target_level = Number(patch.target_level) === 4 ? 4 : 3;
    if (Array.isArray(patch.experts)) next.experts = patch.experts.slice(0, 10).map(e => ({ user_id: s(e.user_id, 80), name: s(e.name, 80), qualification: s(e.qualification, 80), reg_no: s(e.reg_no, 40), training: s(e.training, 120) })).filter(e => e.user_id || e.name);
    if (Array.isArray(patch.executives)) next.executives = patch.executives.slice(0, 10).map(e => ({ user_id: s(e.user_id, 80), name: s(e.name, 80), title: s(e.title, 80) })).filter(e => e.user_id || e.name);
    if (patch.acquired && typeof patch.acquired === 'object') { next.acquired = { ...(cur.acquired || {}) }; for (const lv of ['3', '4']) if (patch.acquired[lv] !== undefined) { const a = patch.acquired[lv] || {}; const at = s(a.at, 10); next.acquired[lv] = at ? { at, expires_at: s(a.expires_at, 10) || new Date(Date.parse(at) + (lv === '3' ? 365 : 3 * 365) * DAY).toISOString().slice(0, 10) } : null; } }
    this.db().prepare("INSERT INTO mamoricho_settings(key,value) VALUES('scs_profile',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(J.str(next));
    this.mm.record(actor, 'scs_profile', { ...next, experts: (next.experts || []).map(e => ({ ...e })), executives: next.executives || [] }); this.ports.audit({ actor, action: 'mamoricho.scs_profile', target: 'scs' });
    return next;
  }
  experts() { return this.profile().experts || []; }
  isExpert(actor) { return !!actor && this.experts().some(e => e.user_id && e.user_id === actor.id); }
  executives(actor) {
    const p = this.profile(); if (p.executives?.length) return p.executives;
    const tenant = actor?.tenant_id || this.ports.users.firstTenant(); const users = tenant ? this.ports.users.list(tenant) : [];
    return users.filter(u => u.executive || u.role === 'owner').map(u => ({ user_id: u.id, name: u.display_name || u.username, title: u.executive ? '役員' : 'Owner' }));
  }
  // ---- 答え ----
  _answers() { return Object.fromEntries(this.db().prepare('SELECT * FROM mm_scs_answers').all().map(a => [a.criterion_id, { ...a, plan: J.parse(a.plan, null) }])); }
  answer(actor, { id: cid, status, note = '', plan = null } = {}) {
    this.ports.requireRole(actor, 'operator'); const c = SCS_CRITERIA.find(x => x.id === cid); if (!c) throw new HttpError(404, 'not_found', '評価基準が見つかりません');
    if (!STATUSES[status]) throw new HttpError(400, 'bad_status', `status は ${Object.keys(STATUSES).join(' / ')}`);
    const prev = this.db().prepare('SELECT * FROM mm_scs_answers WHERE criterion_id=?').get(cid); const t = nowIso();
    const pl = plan && typeof plan === 'object' ? { action: String(plan.action || '').slice(0, 1000), owner: String(plan.owner || '').slice(0, 100), due: /^\d{4}-\d{2}-\d{2}$/.test(String(plan.due || '')) ? plan.due : '' } : (prev ? J.parse(prev.plan, null) : null);
    this.db().prepare('INSERT INTO mm_scs_answers(criterion_id,status,note,plan,last_done_at,updated_by,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(criterion_id) DO UPDATE SET status=excluded.status, note=excluded.note, plan=excluded.plan, updated_by=excluded.updated_by, updated_at=excluded.updated_at')
      .run(cid, status, String(note).slice(0, 2000), J.str(pl), prev?.last_done_at || null, actor.id, t);
    const rec = this.mm.record(actor, 'scs_answer', { criterion_id: cid, level: c.level, status, note: String(note).slice(0, 2000), plan: pl, previous: prev ? { status: prev.status, updated_at: prev.updated_at } : null });
    this.ports.audit({ actor, action: 'mamoricho.scs_answer', target: cid, detail: { status, previous: prev?.status || null, record: rec.id } }); this._cache = {};
    return { id: cid, status, note, plan: pl, updated_at: t, record_id: rec.id };
  }
  // 年 1 回 / 月 1 回の点検をした (日付つき)
  markDone(actor, { id: cid, note = '', at = null } = {}) {
    this.ports.requireRole(actor, 'operator'); const c = SCS_CRITERIA.find(x => x.id === cid); if (!c) throw new HttpError(404, 'not_found', '評価基準が見つかりません');
    const day = at && /^\d{4}-\d{2}-\d{2}/.test(at) ? String(at).slice(0, 10) : nowIso().slice(0, 10); if (Date.parse(day) > Date.now() + DAY) throw new HttpError(400, 'future', '未来の日付は入れられません');
    const prev = this.db().prepare('SELECT * FROM mm_scs_answers WHERE criterion_id=?').get(cid);
    if (prev) this.db().prepare('UPDATE mm_scs_answers SET last_done_at=?, updated_by=?, updated_at=? WHERE criterion_id=?').run(day, actor.id, nowIso(), cid);
    else this.db().prepare('INSERT INTO mm_scs_answers(criterion_id,status,note,plan,last_done_at,updated_by,updated_at) VALUES(?,?,?,?,?,?,?)').run(cid, 'unknown', '', null, day, actor.id, nowIso());
    const rec = this.mm.record(actor, 'scs_periodic', { criterion_id: cid, done_at: day, note: String(note).slice(0, 1000), previous: prev?.last_done_at || null }); this._cache = {};
    return { id: cid, last_done_at: day, record_id: rec.id };
  }
  // ---- 裏づけ ----
  async _self(actor) {
    if (this._cache.self && Date.now() - this._cache.self.at < 60e3) return this._cache.self.map;
    const r = await this.mm.selfCheck(actor); const map = {}; for (const ch of r.checks) for (const cid of ch.scs || []) (map[cid] ||= []).push({ id: ch.id, label: ch.label, ok: ch.ok, detail: ch.detail, level: ch.level });
    this._cache.self = { at: Date.now(), map }; return map;
  }
  _facts(actor) { if (this._cache.facts && Date.now() - this._cache.facts.at < 60e3) return this._cache.facts.v; let v = null; try { v = collectFacts(actor, this.mm, this.probe); } catch { v = { targets: [], by_criterion: {} }; } this._cache.facts = { at: Date.now(), v }; return v; }
  // 監査ログから: ID の付与・変更の記録 (1 年) と、90 日ログインしていない ID
  _auditEvidence(actor) {
    if (this._cache.audit && Date.now() - this._cache.audit.at < 60e3) return this._cache.audit.v;
    let rows = []; try { rows = this.ports.listAudit({ limit: 20000, since: new Date(Date.now() - 365 * DAY).toISOString() }) || []; } catch { rows = []; }
    const changes = rows.filter(r => ID_ACTIONS.includes(r.action)).map(r => ({ at: r.time, action: r.action, by: r.actor_name || r.actor_id, target: r.target, detail: typeof r.detail === 'string' ? J.parse(r.detail, {}) : (r.detail || {}) })).sort((a, b) => String(b.at).localeCompare(String(a.at)));
    const last = {}; for (const r of rows) if (r.action === 'auth.login' && r.actor_id) last[r.actor_id] = String(r.time) > String(last[r.actor_id] || '') ? r.time : last[r.actor_id];
    const tenant = actor?.tenant_id || this.ports.users.firstTenant(); const users = (tenant ? this.ports.users.list(tenant) : []).filter(u => (u.status || 'active') === 'active' && !['support', 'node'].includes(u.role));
    const cut = Date.now() - 90 * DAY; const idle = users.filter(u => (last[u.id] ? Date.parse(last[u.id]) < cut : (u.created_at ? Date.parse(u.created_at) < cut : false))).map(u => ({ username: u.username, name: u.display_name || u.username, role: u.role, last_login: last[u.id] || null }));
    const v = { available: rows.length > 0, changes: changes.slice(0, 200), change_count: changes.length, idle, users: users.length };
    this._cache.audit = { at: Date.now(), v }; return v;
  }
  _vulns() { if (!this.ports.vulns) return null; try { return this.ports.vulns(); } catch { return null; } }
  _adminSummary(actor) { try { const f = this.mm.adminFindings(actor); return { checked: f.length, last_at: f.map(x => x.at).sort().at(-1) || null, warn: f.reduce((n, x) => n + x.warn, 0), check: f.reduce((n, x) => n + x.check, 0), self: !!f.find(x => x.target_id === 'self') }; } catch { return null; } }
  due(c, a) { const g = SCS_GUIDE[c.id]; const days = SCS_CYCLE_DAYS[g?.k]; if (!days) return null; const last = a?.last_done_at || null; const next = last ? new Date(Date.parse(last) + days * DAY).toISOString().slice(0, 10) : null; return { cycle: g.k, days, last_done_at: last, next_at: next, overdue: !last || Date.parse(next) < Date.now(), never: !last }; }

  async criteria(actor, { level = 3 } = {}) {
    this.ports.requireRole(actor, 'viewer'); const lv = Number(level) >= 4 ? 4 : 3;
    const answers = this._answers(); const self = await this._self(actor); const facts = this._facts(actor); const audit = this._auditEvidence(actor);
    const ledgerCounts = this.ledgers ? this.ledgers.counts() : {}; const reviewed = J.parse(this.db().prepare("SELECT value FROM mamoricho_settings WHERE key='ledger_reviewed'").get()?.value, {});
    const pols = this.policies ? this.policies.byTemplate() : {}; const users = audit.users || 0; const notices = this.notices ? this.notices.byCriterion(users) : {};
    const ppcAns = Object.fromEntries(this.db().prepare('SELECT item_id, status, updated_at FROM mamoricho_answers').all().map(r => [r.item_id, r]));
    const vulns = this._vulns(); const admin = this._adminSummary(actor); const contacts = this.mm.settings()?.contacts || {};
    const items = SCS_CRITERIA.filter(c => inLevel(c, lv)).map(c => {
      const g = SCS_GUIDE[c.id] || { k: 'do', q: c.text }; const a = answers[c.id] || null;
      const ev = {};
      if (self[c.id]) ev.self = self[c.id];
      if (facts.by_criterion?.[c.id]) ev.facts = facts.by_criterion[c.id];
      if (g.ledger) { const k = LEDGER_BY_ID[g.ledger]; ev.ledger = { kind: g.ledger, label: k?.label || g.ledger, rows: ledgerCounts[g.ledger]?.n || 0, updated_at: ledgerCounts[g.ledger]?.at || null, reviewed_at: reviewed[g.ledger] || null }; }
      if (g.policy) { const t = POLICY_BY_ID[g.policy]; const p = pols[g.policy]; ev.policy = { template_id: g.policy, title: t?.title || g.policy, adopted_version: p?.adopted_version || null, adopted_at: p?.adopted_at || null, policy_id: p?.id || null }; }
      if (notices[c.id]) ev.notice = notices[c.id];
      if (g.ppc) ev.ppc = g.ppc.map(pid => ({ id: pid, q: PPC[pid]?.q || pid, status: ppcAns[pid]?.status || null }));
      if (g.audit === 'users' && audit.available) ev.audit = { kind: 'users', label: `ID の付与・変更の記録 (1 年): ${audit.change_count} 件`, recent: audit.changes.slice(0, 5) };
      if (g.audit === 'idle' && audit.available) ev.audit = { kind: 'idle', label: audit.idle.length ? `90 日ログインしていない ID: ${audit.idle.length} 件` : '90 日ログインしていない ID はない', idle: audit.idle.slice(0, 20) };
      if (g.vuln && vulns) ev.vuln = vulns;
      if (g.admin && admin) ev.admin = admin;
      if (g.emergency) ev.emergency = { filled: ['lead', 'it', 'vendor', 'police', 'ppc'].filter(k => contacts[k]).length, of: 5 };
      return { ...c, guide: { ...g, kind_label: SCS_KINDS[g.k] }, answer: a ? { status: a.status, note: a.note, plan: a.plan, last_done_at: a.last_done_at, updated_at: a.updated_at, updated_by: a.updated_by } : null, due: this.due(c, a), evidence: ev, tool: g.k === 'tool' };
    });
    return { source: SCS_SOURCE, level: lv, categories: SCS_CATEGORIES, kinds: SCS_KINDS, statuses: STATUSES, items, profile: this.profile(), facts_note: facts.note || null };
  }
  async summary(actor) {
    this.ports.requireRole(actor, 'viewer'); const answers = this._answers(); const p = this.profile();
    const lv = (n) => { const list = SCS_CRITERIA.filter(c => inLevel(c, n)); const counts = { ok: 0, partial: 0, no: 0, unknown: 0, na: 0, unanswered: 0 }; for (const c of list) counts[answers[c.id]?.status || 'unanswered']++; const base = list.length - counts.na; return { total: list.length, counts, answered: list.length - counts.unanswered, score: base ? Math.round(((counts.ok + counts.partial * 0.5) / base) * 100) : 0 }; };
    const target = p.target_level === 4 ? 4 : 3; const now = Date.now();
    const due = SCS_CRITERIA.filter(c => inLevel(c, target)).map(c => ({ c, d: this.due(c, answers[c.id]) })).filter(x => x.d && x.d.overdue).map(x => ({ id: x.c.id, q: SCS_GUIDE[x.c.id]?.q || x.c.text, cycle: x.d.cycle, last_done_at: x.d.last_done_at, next_at: x.d.next_at, never: x.d.never }));
    const plans = Object.entries(answers).filter(([, a]) => a.plan?.due && a.status !== 'ok' && a.status !== 'na').map(([cid, a]) => ({ id: cid, q: SCS_GUIDE[cid]?.q || cid, owner: a.plan.owner, due: a.plan.due, overdue: Date.parse(a.plan.due) < now, action: a.plan.action })).sort((a, b) => a.due.localeCompare(b.due));
    const tools = SCS_CRITERIA.filter(c => inLevel(c, target) && SCS_GUIDE[c.id]?.k === 'tool').map(c => ({ id: c.id, q: SCS_GUIDE[c.id].q, status: answers[c.id]?.status || null }));
    const rv = this.db().prepare('SELECT id, level, state, requested_at, confirmed_at, declared_at FROM mm_scs_reviews ORDER BY requested_at DESC LIMIT 1').get() || null;
    const acq = p.acquired || {}; const exp = ['3', '4'].map(l => acq[l] ? { level: Number(l), ...acq[l], days_left: Math.floor((Date.parse(acq[l].expires_at) - now) / DAY) } : null).filter(Boolean);
    return { source: SCS_SOURCE, target_level: target, level3: lv(3), level4: lv(4), due, plans: plans.slice(0, 30), tools, review: rv, acquired: exp, profile_ready: !!(p.company && p.lead && p.it), experts: (p.experts || []).length, note: '★の取得は制度の手続き (★3 はセキュリティ専門家の確認を経た自己評価、★4 は評価機関の評価) によります。ここは準備と記録のための道具です' };
  }
  // ---- 改善計画書 (できていない項目と、何を・誰が・いつまでに) ----
  async plan(actor, { level = 3 } = {}) {
    const d = await this.criteria(actor, { level });
    const rows = d.items.filter(i => !i.answer || !['ok', 'na'].includes(i.answer.status)).map(i => ({ id: i.id, level: i.level, cat: i.cat, req_name: i.req_name, q: i.guide.q, text: i.text, status: i.answer?.status || 'unanswered', action: i.answer?.plan?.action || '', owner: i.answer?.plan?.owner || '', due: i.answer?.plan?.due || '', helps: hints(i) }));
    return { level: d.level, rows, total: d.items.length, open: rows.length, profile: d.profile, source: SCS_SOURCE };
  }
  async planCsv(actor, { level = 3 } = {}) {
    const p = await this.plan(actor, { level }); const q = (v) => { const s = String(v ?? ''); return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const head = ['評価基準', '★', '大分類', '要求事項', '状態', 'やること', '担当', '期限', 'まもり帳でできること', '評価基準 (原文)'];
    return '﻿' + [head.join(','), ...p.rows.map(r => [r.id, r.level, r.cat, r.req_name, (STATUSES[r.status] || '未回答'), r.action, r.owner, r.due, r.helps.join(' / '), r.text].map(q).join(','))].join('\r\n') + `\r\n${q(`出典: ${SCS_SOURCE.title} (${SCS_SOURCE.publisher}) ${SCS_SOURCE.url} をもとに作成`)}\r\n`;
  }
  // ---- 確認の流れ: 写しを固める → 専門家の助言・確認 → 経営層の宣誓 ----
  async requestReview(actor, { level = 3, note = '' } = {}) {
    this.ports.requireRole(actor, 'admin'); const lv = Number(level) >= 4 ? 4 : 3;
    const open = this.db().prepare("SELECT id FROM mm_scs_reviews WHERE state IN ('requested','returned','confirmed') AND level=?").get(lv); if (open) throw new HttpError(409, 'open_review', 'まだ終わっていない確認の依頼があります。先にそれを終えるか取り下げてください');
    const d = await this.criteria(actor, { level: lv }); const p = this.profile();
    const snap = { level: lv, company: p.company || '', scope: p.scope || '', source: { title: SCS_SOURCE.title, url: SCS_SOURCE.url, used_at: SCS_SOURCE.used_at }, at: nowIso(), items: d.items.map(i => ({ id: i.id, level: i.level, status: i.answer?.status || 'unanswered', note: i.answer?.note || '', plan: i.answer?.plan || null, last_done_at: i.answer?.last_done_at || null, evidence: evidenceSummary(i) })) };
    const h = sha256(canonicalJson(snap)); const rid = id('scsr'); const t = nowIso();
    this.db().prepare("INSERT INTO mm_scs_reviews(id,level,state,snapshot,snapshot_hash,note,requested_by,requested_by_name,requested_at,comments) VALUES(?,?,?,?,?,?,?,?,?,?)").run(rid, lv, 'requested', J.str(snap), h, String(note).slice(0, 1000), actor.id, actor.display_name || actor.username || '', t, '[]');
    const rec = this.mm.record(actor, 'scs_review_request', { review_id: rid, level: lv, snapshot_hash: h, unanswered: snap.items.filter(x => x.status === 'unanswered').length, not_ok: snap.items.filter(x => !['ok', 'na'].includes(x.status)).length, note: String(note).slice(0, 1000) });
    for (const e of this.experts().filter(e => e.user_id)) this.ports.notify({ user_id: e.user_id, kind: 'mamoricho', severity: 'info', title: `${this.ports.brand.product}: SCS ★${lv} の自己評価の確認の依頼`, body: `${p.company || ''} の自己評価 (${snap.items.length} 項目) の確認をお願いします`, dedupe_key: `mamoricho.scs.review.${rid}`, link: 'mamoricho:scsreview' });
    return { review_id: rid, snapshot_hash: h, record_id: rec.id, items: snap.items.length };
  }
  reviewList(actor) { this.ports.requireRole(actor, 'viewer'); return { reviews: this.db().prepare('SELECT id,level,state,snapshot_hash,requested_by_name,requested_at,expert,confirmed_at,declaration,declared_at FROM mm_scs_reviews ORDER BY requested_at DESC LIMIT 50').all().map(r => ({ ...r, expert: J.parse(r.expert, null), declaration: J.parse(r.declaration, null) })), experts: this.experts(), executives: this.executives(actor), me: { expert: this.isExpert(actor) } }; }
  reviewGet(actor, rid) {
    this.ports.requireRole(actor, 'viewer'); const r = this.db().prepare('SELECT * FROM mm_scs_reviews WHERE id=?').get(rid); if (!r) throw new HttpError(404, 'not_found', '確認の依頼が見つかりません');
    const snap = J.parse(r.snapshot, {}); const byCid = Object.fromEntries(SCS_CRITERIA.map(c => [c.id, c]));
    return { ...r, snapshot: { ...snap, items: (snap.items || []).map(x => ({ ...x, req_name: byCid[x.id]?.req_name || '', text: byCid[x.id]?.text || '', q: SCS_GUIDE[x.id]?.q || '' })) }, comments: J.parse(r.comments, []), expert: J.parse(r.expert, null), declaration: J.parse(r.declaration, null), me: { expert: this.isExpert(actor) }, hash_ok: sha256(canonicalJson(snap)) === r.snapshot_hash };
  }
  comment(actor, { review_id, criterion_id = null, text = '' } = {}) {
    const r = this.reviewGet(actor, review_id); if (!this.isExpert(actor)) this.ports.requireRole(actor, 'admin');
    if (!['requested', 'returned'].includes(r.state)) throw new HttpError(409, 'closed', 'この依頼には、もう助言を足せません');
    const s = String(text).trim(); if (!s) throw new HttpError(400, 'empty', '助言の内容を入れてください');
    const list = r.comments; const c = { id: id('scsc'), criterion_id: criterion_id || null, text: s.slice(0, 2000), by: actor.id, by_name: actor.display_name || actor.username || '', expert: this.isExpert(actor), at: nowIso() }; list.push(c);
    this.db().prepare('UPDATE mm_scs_reviews SET comments=? WHERE id=?').run(J.str(list.slice(-500)), review_id);
    this.mm.record(actor, 'scs_review_comment', { review_id, criterion_id: c.criterion_id, text: c.text, expert: c.expert });
    return c;
  }
  // 専門家だけ: confirm = この写しの内容を確認した (署名)、return = 直してから出し直してほしい
  decide(actor, { review_id, decision, statement = '' } = {}) {
    if (!this.isExpert(actor)) throw new HttpError(403, 'not_expert', '確認・差し戻しは、会社の情報で「セキュリティ専門家」に登録された人だけができます');
    const r = this.reviewGet(actor, review_id); if (r.state !== 'requested') throw new HttpError(409, 'bad_state', r.state === 'returned' ? '差し戻した依頼です。出し直されるのを待ってください' : 'この依頼は確認を終えています');
    if (!r.hash_ok) throw new HttpError(409, 'tampered', '写しの中身がハッシュと合いません (書き換えられています)');
    const e = this.experts().find(x => x.user_id === actor.id); const t = nowIso();
    if (decision === 'return') {
      this.db().prepare("UPDATE mm_scs_reviews SET state='returned' WHERE id=?").run(review_id);
      const rec = this.mm.record(actor, 'scs_expert_return', { review_id, snapshot_hash: r.snapshot_hash, statement: String(statement).slice(0, 2000), expert: e });
      this.ports.notify({ user_id: r.requested_by, kind: 'mamoricho', severity: 'warning', title: `${this.ports.brand.product}: SCS の自己評価が差し戻されました`, body: String(statement).slice(0, 200) || '助言を見て直し、出し直してください', dedupe_key: `mamoricho.scs.return.${review_id}`, link: 'mamoricho:scsreview' });
      return { state: 'returned', record_id: rec.id };
    }
    if (decision !== 'confirm') throw new HttpError(400, 'bad_decision', 'confirm か return');
    const ex = { user_id: actor.id, name: e?.name || actor.display_name || actor.username, qualification: e?.qualification || '', reg_no: e?.reg_no || '', training: e?.training || '', statement: String(statement || '上記の自己評価の内容を確認しました。').slice(0, 2000), at: t };
    const rec = this.mm.record(actor, 'scs_expert_confirm', { review_id, level: r.level, snapshot_hash: r.snapshot_hash, expert: ex });
    this.db().prepare("UPDATE mm_scs_reviews SET state='confirmed', expert=?, confirmed_at=?, confirm_record=? WHERE id=?").run(J.str(ex), t, rec.id, review_id);
    for (const x of this.executives(actor).filter(x => x.user_id)) this.ports.notify({ user_id: x.user_id, kind: 'mamoricho', severity: 'info', title: `${this.ports.brand.product}: SCS ★${r.level} の自己評価に、経営層の宣誓をお願いします`, body: `${ex.name} (${ex.qualification}) が確認しました`, dedupe_key: `mamoricho.scs.declare.${review_id}`, link: 'mamoricho:scsreview' });
    return { state: 'confirmed', expert: ex, record_id: rec.id };
  }
  // 差し戻しのあと、いまの答えで写しを作り直して出し直す
  async resubmit(actor, { review_id, note = '' } = {}) {
    this.ports.requireRole(actor, 'admin'); const r = this.reviewGet(actor, review_id); if (r.state !== 'returned') throw new HttpError(409, 'bad_state', '差し戻された依頼だけ出し直せます');
    this.db().prepare("UPDATE mm_scs_reviews SET state='superseded' WHERE id=?").run(review_id);
    const n = await this.requestReview(actor, { level: r.level, note: note || `出し直し (前回 ${review_id})` }); this.db().prepare('UPDATE mm_scs_reviews SET comments=? WHERE id=?').run(J.str(r.comments.map(c => ({ ...c, from_review: review_id }))), n.review_id); return n;
  }
  withdraw(actor, { review_id } = {}) { this.ports.requireRole(actor, 'admin'); const r = this.reviewGet(actor, review_id); if (!['requested', 'returned'].includes(r.state)) throw new HttpError(409, 'bad_state', '確認を終えた依頼は取り下げられません'); this.db().prepare("UPDATE mm_scs_reviews SET state='withdrawn' WHERE id=?").run(review_id); this.mm.record(actor, 'scs_review_withdraw', { review_id }); return { state: 'withdrawn' }; }
  // 経営層の自己適合宣誓 (専門家の確認のあと)
  declare(actor, { review_id, name = '', title = '', text = '' } = {}) {
    const r = this.reviewGet(actor, review_id); if (r.state !== 'confirmed') throw new HttpError(409, 'bad_state', '専門家の確認のあとに宣誓できます');
    const ex = this.executives(actor); if (!ex.some(x => x.user_id === actor.id) && actor.role !== 'owner') throw new HttpError(403, 'not_executive', '宣誓は、会社の情報で経営層に登録された人 (または Owner) が行います');
    const me = ex.find(x => x.user_id === actor.id); const t = nowIso();
    const dc = { user_id: actor.id, name: String(name || me?.name || actor.display_name || actor.username).slice(0, 80), title: String(title || me?.title || '').slice(0, 80), text: String(text || `当社は、SCS 評価制度の★${r.level}の要求事項・評価基準に照らした上記の自己評価の内容が、事実に基づくものであることを宣誓します。`).slice(0, 2000), at: t };
    const rec = this.mm.record(actor, 'scs_declaration', { review_id, level: r.level, snapshot_hash: r.snapshot_hash, declaration: dc, expert_record: r.confirm_record });
    this.db().prepare("UPDATE mm_scs_reviews SET state='declared', declaration=?, declared_at=?, declare_record=? WHERE id=?").run(J.str(dc), t, rec.id, review_id);
    return { state: 'declared', declaration: dc, record_id: rec.id };
  }
  // 控えの書き出し (Markdown / Word)。IPA の提出様式ではない
  exportReview(actor, { review_id, format = 'docx' } = {}) {
    const r = this.reviewGet(actor, review_id); const s = r.snapshot; const ST = { ...STATUSES, unanswered: '未回答' };
    const cnt = s.items.reduce((m, x) => { m[x.status] = (m[x.status] || 0) + 1; return m; }, {});
    const md = [`# SCS 評価制度 ★${r.level} 自己評価の控え`, '', `会社: ${s.company || '(未入力)'}　作成: ${s.at.slice(0, 10)}　写しのハッシュ: ${r.snapshot_hash}`, '', s.scope ? `適用範囲: ${s.scope}` : '', '',
      '## 1. まとめ', '', `評価基準 ${s.items.length} 項目: ${Object.entries(cnt).map(([k, v]) => `${ST[k] || k} ${v}`).join('・')}`, '',
      '## 2. セキュリティ専門家の確認', '', r.expert ? `${r.expert.name} (${r.expert.qualification}${r.expert.reg_no ? ` 登録番号 ${r.expert.reg_no}` : ''}) ${r.expert.at.slice(0, 10)}: ${r.expert.statement}` : '(まだ確認されていません)', '',
      '## 3. 経営層の宣誓', '', r.declaration ? `${r.declaration.title} ${r.declaration.name} ${r.declaration.at.slice(0, 10)}: ${r.declaration.text}` : '(まだ宣誓されていません)', '',
      '## 4. 評価基準ごとの自己評価', '', '| 番号 | 要求事項 | 状態 | 一言・根拠 | 改善の計画 |', '|---|---|---|---|---|',
      ...s.items.map(x => `| ${x.id} | ${String(x.req_name).replace(/\|/g, '／')} | ${ST[x.status] || x.status} | ${[x.note, ...(x.evidence || [])].filter(Boolean).join(' / ').replace(/\|/g, '／').replace(/\n/g, ' ').slice(0, 300)} | ${x.plan?.action ? `${x.plan.action} (${x.plan.owner || '担当未定'} ${x.plan.due || ''})`.replace(/\|/g, '／') : ''} |`), '',
      '## 5. 助言の記録', '', ...(r.comments.length ? r.comments.map(c => `- ${c.at.slice(0, 10)} ${c.by_name}${c.expert ? ' (専門家)' : ''}${c.criterion_id ? ` [${c.criterion_id}]` : ''}: ${c.text}`) : ['(なし)']), '',
      `出典: 「${SCS_SOURCE.title}」(${SCS_SOURCE.publisher}) ${SCS_SOURCE.url} をもとに${this.ports.brand.product}で作成。この控えは IPA への提出の様式ではありません (様式は制度の開始までに IPA から公表される予定です)。記録はすべて${this.ports.brand.product}の記録の鎖 (署名つき) にあります。`].filter(l => l !== null).join('\n');
    const name = `SCS-star${r.level}-自己評価-${s.at.slice(0, 10)}`;
    return format === 'md' ? { name: `${name}.md`, type: 'text/markdown; charset=utf-8', buffer: Buffer.from(md, 'utf8') } : { name: `${name}.docx`, type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', buffer: mdToDocx(md, { title: `SCS ★${r.level} 自己評価の控え`, author: s.company || '' }) };
  }
  // ---- 定期の知らせ (Mamoricho.tick から 1 日 1 回) ----
  async tick(sys) {
    const s = await this.summary(sys); const ym = new Date().toISOString().slice(0, 7); const B = this.ports.brand;
    const done = s.due.filter(x => !x.never); const never = s.due.filter(x => x.never).length;
    if (done.length) this.ports.notify({ kind: 'mamoricho', severity: 'warning', title: `${B.product}: SCS の定期の点検の期限が過ぎています (${done.length} 件)`, body: done.slice(0, 3).map(x => x.q.slice(0, 40)).join(' / '), dedupe_key: `mamoricho.scs.due.${ym}`, link: 'mamoricho:scs' });
    else if (never && (s.level3.answered || s.level4.answered)) this.ports.notify({ kind: 'mamoricho', severity: 'info', title: `${B.product}: SCS の年 1 回の点検で、まだ一度も記録していないものが ${never} 件`, body: '点検をしたら「点検した」を押して日付を残してください', dedupe_key: `mamoricho.scs.never.${ym}`, link: 'mamoricho:scs' });
    const late = s.plans.filter(x => x.overdue); if (late.length) this.ports.notify({ kind: 'mamoricho', severity: 'info', title: `${B.product}: 改善の計画の期限が過ぎたものが ${late.length} 件`, body: late.slice(0, 3).map(x => `${x.owner || ''} ${x.q.slice(0, 30)}`).join(' / '), dedupe_key: `mamoricho.scs.plan.${ym}`, link: 'mamoricho:scsplan' });
    for (const a of s.acquired) for (const b of [60, 30, 7]) if (a.days_left <= b && a.days_left > (b === 60 ? 30 : b === 30 ? 7 : -9999)) { this.ports.notify({ kind: 'mamoricho', severity: b <= 7 ? 'warning' : 'info', title: `${B.product}: SCS ★${a.level} の有効期限まで ${a.days_left} 日`, body: `期限 ${a.expires_at}。更新の自己評価と確認を早めに`, dedupe_key: `mamoricho.scs.expiry.${a.level}.${a.expires_at}.${b}`, link: 'mamoricho:scsreview' }); break; }
  }
}
// まもり帳でできること (改善計画書・画面の手がかり)
export function hints(i) {
  const g = i.guide || {}; const out = [];
  if (g.k === 'tool') out.push('UTM・EDR・ウイルス対策などの道具が要る項目 (お助け隊サービスなどの監視サービスで満たせることがあります)');
  if (g.policy) out.push(`規程「${POLICY_BY_ID[g.policy]?.title || g.policy}」に書く (ひな形・レビューあり)`);
  if (g.ledger) out.push(`台帳「${LEDGER_BY_ID[g.ledger]?.label || g.ledger}」に書く`);
  if (g.k === 'notice' || /周知/.test(i.text || '')) out.push('「全員に知らせる」で配って確認を集める');
  if (SCS_CYCLE_DAYS[g.k]) out.push(`${g.k === 'monthly' ? '月' : '年'} 1 回の点検 (期限を知らせ、「点検した」の日付を残す)`);
  if (g.facts) out.push('まとめて診断の結果で裏づけを見る');
  if (g.admin) out.push('管理者アカウントの点検 (ログイン・管理者の変化の見張り)');
  if (g.vuln) out.push('脆弱性情報 (署名つきの配布) と突き合わせる');
  if (g.audit) out.push('箱の監査ログ (ID の変更・使われていない ID) を見る');
  if (g.emergency) out.push('「もしものとき」の連絡先に入れる');
  return out;
}
// 写しに残す裏づけの要約 (文字だけ)
function evidenceSummary(i) {
  const e = i.evidence || {}; const out = [];
  for (const s of e.self || []) out.push(`${s.ok ? '✓' : '✗'} ${s.label}: ${s.detail}`);
  for (const f of (e.facts || []).slice(0, 4)) out.push(`${f.level === 'ok' ? '✓' : f.level === 'warn' ? '✗' : '・'} ${f.label}`);
  if (e.ledger?.rows) out.push(`台帳「${e.ledger.label}」${e.ledger.rows} 行${e.ledger.reviewed_at ? ` (見直し ${e.ledger.reviewed_at.slice(0, 10)})` : ''}`);
  if (e.policy?.adopted_version) out.push(`規程「${e.policy.title}」第${e.policy.adopted_version}版 (${String(e.policy.adopted_at || '').slice(0, 10)})`);
  if (e.notice) out.push(`周知「${e.notice.title}」確認 ${e.notice.acks}/${e.notice.audience}`);
  if (e.audit) out.push(e.audit.label);
  if (i.due?.last_done_at) out.push(`点検 ${i.due.last_done_at}`);
  return out.slice(0, 10);
}
