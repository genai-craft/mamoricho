// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// 全員に知らせる (周知) と、読んだことの確認。SCS 評価制度の「周知すること」「参照できるようにすること」「受講状況を記録すること」の材料。
//   知らせは箱の通知 (全員あて) で届き、利用者は「確認しました」を押す。押した人と時刻は表と記録の鎖に残る。
//   確認の口 (/api/v1/mamoricho-ack/…) は、まもり帳を使う許可が無い社員でも使える (読む・押す・規程を見るだけ)
import { HttpError, id, nowIso, J, sha256 } from '../util.js';

const ACTIVE = (u) => (u.status || 'active') === 'active' && !['support', 'node'].includes(u.role);
export class Notices {
  constructor(ports, { mm = null } = {}) { Object.assign(this, { ports, mm }); }
  db() { return this.ports.db(); }
  users(actor) { const tenant = actor?.tenant_id || this.ports.users.firstTenant(); return (tenant ? this.ports.users.list(tenant) : []).filter(ACTIVE); }
  row(r) { return r && { ...r, criteria: J.parse(r.criteria, []) }; }
  create(actor, { title = '', body = '', policy_id = null, policy_version = null, criteria = [], kind = 'notice', ledger_row = null } = {}) {
    this.ports.requireRole(actor, 'operator');
    const t = String(title).trim().slice(0, 120); if (!t) throw new HttpError(400, 'empty', '題名を入れてください');
    const n = { id: id('ntc'), title: t, body: String(body).slice(0, 20000), kind: ['notice', 'training'].includes(kind) ? kind : 'notice', policy_id: policy_id || null, policy_version: policy_version || null, criteria: J.str((Array.isArray(criteria) ? criteria : []).map(String).slice(0, 40)), ledger_row: ledger_row || null, created_by: actor.id, created_by_name: actor.display_name || actor.username || '', created_at: nowIso() };
    this.db().prepare('INSERT INTO mm_notices(id,title,body,kind,policy_id,policy_version,criteria,ledger_row,created_by,created_by_name,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(n.id, n.title, n.body, n.kind, n.policy_id, n.policy_version, n.criteria, n.ledger_row, n.created_by, n.created_by_name, n.created_at);
    this.ports.notify({ kind: 'mamoricho', severity: 'info', title: `${n.kind === 'training' ? '受講の確認' : 'お知らせ'}: ${t}`, body: '開いて読み、「確認しました」を押してください', dedupe_key: `mamoricho.notice.${n.id}`, link: `mamoricho-ack:${n.id}` });
    const rec = this.mm?.record(actor, 'notice', { notice_id: n.id, title: t, kind: n.kind, policy_id: n.policy_id, policy_version: n.policy_version, criteria: J.parse(n.criteria, []), body_sha256: sha256(n.body), audience: this.users(actor).length });
    this.ports.audit({ actor, action: 'mamoricho.notice', target: n.id, detail: { title: t, record: rec?.id || null } });
    return { ...this.row(n), record_id: rec?.id || null };
  }
  list(actor) {
    this.ports.requireRole(actor, 'operator'); const total = this.users(actor).length;
    return { notices: this.db().prepare('SELECT n.*, (SELECT COUNT(*) FROM mm_notice_acks a WHERE a.notice_id=n.id) acks FROM mm_notices n ORDER BY n.created_at DESC LIMIT 300').all().map(r => ({ ...this.row(r), audience: total })), audience: total };
  }
  detail(actor, nid) {
    this.ports.requireRole(actor, 'operator'); const n = this.row(this.db().prepare('SELECT * FROM mm_notices WHERE id=?').get(nid)); if (!n) throw new HttpError(404, 'not_found', 'お知らせが見つかりません');
    const acks = this.db().prepare('SELECT * FROM mm_notice_acks WHERE notice_id=? ORDER BY at').all(nid); const got = new Set(acks.map(a => a.user_id));
    return { ...n, acks, pending: this.users(actor).filter(u => !got.has(u.id)).map(u => ({ id: u.id, username: u.username, display_name: u.display_name || u.username, department: u.department || '' })) };
  }
  remind(actor, nid) {
    const d = this.detail(actor, nid); if (d.closed_at) throw new HttpError(409, 'closed', 'このお知らせは締め切っています');
    this.ports.notify({ kind: 'mamoricho', severity: 'info', title: `もう一度: ${d.title}`, body: `まだ確認していない人が ${d.pending.length} 人います。開いて「確認しました」を押してください`, dedupe_key: `mamoricho.notice.${nid}.${Date.now()}`, link: `mamoricho-ack:${nid}` });
    return { reminded: d.pending.length };
  }
  close(actor, nid) {
    const d = this.detail(actor, nid); this.db().prepare('UPDATE mm_notices SET closed_at=? WHERE id=?').run(nowIso(), nid);
    const rec = this.mm?.record(actor, 'notice_close', { notice_id: nid, title: d.title, acks: d.acks.length, pending: d.pending.length, pending_names: d.pending.map(u => u.display_name).slice(0, 200) });
    return { ok: true, record_id: rec?.id || null };
  }
  // ---- だれでも (まもり帳の許可が無くても) ----
  pending(actor) {
    if (!actor) throw new HttpError(401, 'unauthenticated', 'ログインが必要です');
    return { notices: this.db().prepare('SELECT id,title,kind,created_at,created_by_name FROM mm_notices n WHERE closed_at IS NULL AND NOT EXISTS (SELECT 1 FROM mm_notice_acks a WHERE a.notice_id=n.id AND a.user_id=?) ORDER BY created_at DESC LIMIT 50').all(actor.id) };
  }
  view(actor, nid) {
    if (!actor) throw new HttpError(401, 'unauthenticated', 'ログインが必要です');
    const n = this.row(this.db().prepare('SELECT * FROM mm_notices WHERE id=?').get(nid)); if (!n) throw new HttpError(404, 'not_found', 'お知らせが見つかりません');
    const mine = this.db().prepare('SELECT at FROM mm_notice_acks WHERE notice_id=? AND user_id=?').get(nid, actor.id);
    const pol = n.policy_id ? this.db().prepare('SELECT v.body, v.version, p.title FROM mm_policy_versions v JOIN mm_policies p ON p.id=v.policy_id WHERE v.policy_id=? AND v.version=?').get(n.policy_id, n.policy_version) : null;
    return { id: n.id, title: n.title, body: n.body, kind: n.kind, created_at: n.created_at, created_by_name: n.created_by_name, closed: !!n.closed_at, acked_at: mine?.at || null, policy: pol ? { title: pol.title, version: pol.version, body: pol.body } : null };
  }
  ack(actor, nid) {
    const v = this.view(actor, nid); if (v.acked_at) return { acked_at: v.acked_at, already: true }; if (v.closed) throw new HttpError(409, 'closed', 'このお知らせは締め切られています');
    const at = nowIso(); this.db().prepare('INSERT OR IGNORE INTO mm_notice_acks(notice_id,user_id,user_name,department,at) VALUES(?,?,?,?,?)').run(nid, actor.id, actor.display_name || actor.username || actor.id, actor.department || '', at);
    this.mm?.record(actor, 'notice_ack', { notice_id: nid, title: v.title });
    return { acked_at: at };
  }
  // 採用した (いまの) 規程の一覧と本文 (全員がいつでも見られる: 1-3-1-2)
  adopted(actor) {
    if (!actor) throw new HttpError(401, 'unauthenticated', 'ログインが必要です');
    return { policies: this.db().prepare("SELECT p.id, p.title, p.template_id, v.version, v.adopted_at FROM mm_policies p JOIN mm_policy_versions v ON v.policy_id=p.id AND v.version=p.adopted_version WHERE p.adopted_version IS NOT NULL ORDER BY p.title").all() };
  }
  adoptedOne(actor, pid) {
    if (!actor) throw new HttpError(401, 'unauthenticated', 'ログインが必要です');
    const r = this.db().prepare('SELECT p.id, p.title, v.version, v.adopted_at, v.body FROM mm_policies p JOIN mm_policy_versions v ON v.policy_id=p.id AND v.version=p.adopted_version WHERE p.id=?').get(pid); if (!r) throw new HttpError(404, 'not_found', '規程が見つかりません');
    return r;
  }
  // 評価基準の裏づけ: 基準ごとに、結びついた周知の最新 1 件と確認の数 ({ 基準の番号: {...} })
  byCriterion(total) {
    const out = {};
    for (const r of this.db().prepare('SELECT n.id, n.title, n.created_at, n.closed_at, n.criteria, (SELECT COUNT(*) FROM mm_notice_acks a WHERE a.notice_id=n.id) acks FROM mm_notices n ORDER BY n.created_at DESC LIMIT 300').all())
      for (const cid of J.parse(r.criteria, [])) out[cid] ||= { id: r.id, title: r.title, at: r.created_at, acks: r.acks, audience: total, closed: !!r.closed_at };
    return out;
  }
}
