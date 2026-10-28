// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// SCS 評価制度の点検・台帳・規程・全員に知らせる: データの整合と、答え → 計画 → 確認の流れ → 宣誓、周知と確認、規程の下書き・採用・レビュー (AI の根拠の確かめ)
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createStandalone } from '../standalone/ports.mjs';
import { createMamoricho, SCS_CRITERIA, SCS_GUIDE, LEDGER_KINDS, POLICY_TEMPLATES, docxText, mdToDocx, paragraphs } from '../index.js';
import { unzip, zip } from '../core/zip.js';
import { sshFacts, osEol } from '../core/scs-facts.js';
import { STDERR_MARK } from '../core/output.js';

test('評価基準の原文 (経済産業省) と手がかりの整合', () => {
  assert.equal(SCS_CRITERIA.length, 153); assert.equal(SCS_CRITERIA.filter(c => c.level === 3).length, 81);
  assert.equal(new Set(SCS_CRITERIA.map(c => c.req)).size, 43); assert.equal(new Set(SCS_CRITERIA.filter(c => c.req_in3).map(c => c.req)).size, 26);
  const ids = new Set(SCS_CRITERIA.map(c => c.id)); assert.equal(ids.size, 153, '番号は重ならない');
  for (const c of SCS_CRITERIA) { assert.ok(SCS_GUIDE[c.id], `${c.id} に手がかりがある`); assert.ok(c.text.length > 10 && !/^・/.test(c.text), `${c.id} の原文`); }
  for (const k of Object.keys(SCS_GUIDE)) assert.ok(ids.has(k), `手がかり ${k} は実在の評価基準`);
  const ledgers = new Set(LEDGER_KINDS.map(k => k.id)); const tpls = new Set(POLICY_TEMPLATES.map(t => t.id));
  for (const [k, g] of Object.entries(SCS_GUIDE)) { if (g.ledger) assert.ok(ledgers.has(g.ledger), `${k} の台帳 ${g.ledger}`); if (g.policy) assert.ok(tpls.has(g.policy), `${k} の規程 ${g.policy}`); assert.ok(g.q.length >= 10); }
  for (const t of POLICY_TEMPLATES) for (const e of t.elements) for (const cid of e.criteria) assert.ok(ids.has(cid), `${t.id}.${e.id} の ${cid}`);
  for (const l of LEDGER_KINDS) for (const cid of l.criteria) assert.ok(ids.has(cid), `台帳 ${l.id} の ${cid}`);
  // ★3 の「決まりを作る」項目は、書く先の規程の要素のどれかに入っている (ひな形で抜けない)
  for (const c of SCS_CRITERIA.filter(c => c.level === 3 && SCS_GUIDE[c.id].k === 'rule')) { const t = POLICY_TEMPLATES.find(x => x.id === SCS_GUIDE[c.id].policy); assert.ok(t, `${c.id} に規程`); assert.ok(t.elements.some(e => e.criteria.includes(c.id)), `${c.id} が規程「${t.title}」の要素にある`); }
  // 道具が要る項目 (UTM・EDR・ウイルス対策) は、まもり帳で満たせる顔をしない
  for (const cid of ['5-1-1-1', '5-1-1-3', '4-4-5-1']) assert.equal(SCS_GUIDE[cid].k, 'tool');
});

test('ZIP と Word の読み書き', () => {
  const z = unzip(zip([{ name: 'a.txt', data: 'あいう' }, { name: 'd/b.bin', data: Buffer.alloc(5000, 7) }]));
  assert.deepEqual(z.names, ['a.txt', 'd/b.bin']); assert.equal(z.text('a.txt'), 'あいう'); assert.equal(z.read('d/b.bin').length, 5000);
  const md = '# 規程\n\n## 1. 目的\n本文の **太字** と <記号> & 文字。\n\n- 箇条書き\n\n| 列1 | 列2 |\n|---|---|\n| 値1 | 値2 |\n';
  const t = docxText(mdToDocx(md, { title: '規程' }));
  assert.match(t, /^# 規程/m); assert.match(t, /^## 1\. 目的/m); assert.match(t, /本文の 太字 と <記号> & 文字。/); assert.match(t, /・箇条書き/); assert.match(t, /^値2$/m);
  assert.throws(() => unzip(Buffer.from('not a zip at all, sorry......')), /ZIP/);
});

test('まとめて診断の出力から目安を拾う (OS・更新・管理者・ポート・ファイアウォール・SSH)', () => {
  const outs = { r1: 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\nID=ubuntu\nVERSION_ID="20.04"', r2: 'Listing...\nopenssl/focal-security 1.1.1f-1ubuntu2.24 amd64 [upgradable from: 1.1.1f-1ubuntu2.23]\nvim/focal 2:8.1 amd64 [upgradable from: 2:8.0]', r3: 'Start-Date: 2026-10-01  06:00:00\nCommandline: apt\nStart-Date: 2026-10-20  06:00:01', r4: 'APT::Periodic::Unattended-Upgrade "1";', r5: 'sudo:x:27:alice,bob', r6: 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1))\nLISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\nLISTEN 0 50 [::]:445 [::]:*', r7: 'Status: active', r8: 'PermitRootLogin yes\n#PasswordAuthentication no\nPasswordAuthentication yes' + STDERR_MARK + 'noise' };
  const sec = [{ template_id: 'linux.basic', steps: [{ argv: ['cat', '/etc/os-release'], run_id: 'r1' }] }, { template_id: 'linux.updates', steps: [{ argv: ['apt', 'list', '--upgradable'], run_id: 'r2' }, { argv: ['tail', '-n', '40', '/var/log/apt/history.log'], run_id: 'r3' }, { argv: ['cat', '/etc/apt/apt.conf.d/20auto-upgrades'], run_id: 'r4' }] }, { template_id: 'linux.users', steps: [{ argv: ['getent', 'group', 'sudo'], run_id: 'r5' }] }, { template_id: 'linux.ports', steps: [{ argv: ['ss', '-tlnpH'], run_id: 'r6' }] }, { template_id: 'linux.firewall', steps: [{ argv: ['ufw', 'status', 'verbose'], run_id: 'r7' }] }, { template_id: 'linux.ssh', steps: [{ argv: ['cat', '/etc/ssh/sshd_config'], run_id: 'r8' }] }];
  const f = sshFacts(sec, (id) => outs[id]);
  assert.equal(f.os, 'Ubuntu 20.04.6 LTS'); assert.ok(f.eol, '20.04 は標準のサポートが終了'); assert.equal(f.upgradable, 2); assert.equal(f.upgradable_security, 1); assert.equal(f.last_update, '2026-10-20'); assert.equal(f.auto_updates, true);
  assert.deepEqual(f.admins, ['alice', 'bob']); assert.deepEqual(f.listen, [22, 445]); assert.equal(f.firewall, 'ufw が有効'); assert.deepEqual(f.ssh, { permit_root: 'yes', password_auth: 'yes' });
  assert.equal(osEol('ubuntu', '24.04'), null); assert.equal(osEol('ubuntu', '22.04'), null); assert.ok(osEol('ubuntu', '25.10')); assert.ok(osEol('debian', '10')); assert.equal(osEol('debian', '12'), null);
});

// ---- 単体版のポートで、流れを通す ----
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mamoricho-scs-'));
const sa = createStandalone(dataDir, { llm: false });
let llmReply = null; // テストごとに差し替える偽の AI
sa.ports.llm = { chat: async (msgs) => ({ content: typeof llmReply === 'function' ? llmReply(msgs) : llmReply }), model: 'fake', provider: 'fake', local: true };
const mk = createMamoricho({ probe: { decision_head: null } }, sa.ports);
after(() => { try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* 片付け */ } });
const owner = sa.auth.createUser(null, { username: 'owner', password: 'ownerpass123', role: 'owner', display_name: '社長' });
const op = sa.auth.createUser(null, { username: 'tanto', password: 'tantopass123', role: 'operator', display_name: '担当' });
const ex = sa.auth.createUser(null, { username: 'sensei', password: 'senseipass12', role: 'viewer', display_name: '専門家' });
const staff = sa.auth.createUser(null, { username: 'staff', password: 'staffpass123', role: 'viewer', display_name: '社員' });
const A = (u) => ({ ...sa.auth.users().find(x => x.username === u.username), tenant_id: 'local' });

test('答え・計画・定期の点検 → 要約と改善計画書', async () => {
  const { scs } = mk;
  await assert.rejects(() => Promise.resolve().then(() => scs.answer(A(staff), { id: '1-3-1-1', status: 'ok' })), /権限|forbidden|role/i);
  scs.answer(A(op), { id: '1-3-1-1', status: 'ok', note: '基本方針あり' });
  scs.answer(A(op), { id: '1-2-1-3', status: 'partial', plan: { action: '体制表を作る', owner: '担当', due: '2026-12-01' } });
  const d1 = scs.markDone(A(op), { id: '1-2-1-3', at: '2025-09-01', note: '体制を見直した' }); assert.equal(d1.last_done_at, '2025-09-01');
  const c3 = await scs.criteria(A(op), { level: 3 }); assert.equal(c3.items.length, 81); assert.ok(c3.items.every(i => i.level === 3));
  const it = c3.items.find(i => i.id === '1-2-1-3'); assert.equal(it.due.cycle, 'yearly'); assert.equal(it.due.overdue, true, '前回から 1 年以上'); assert.equal(it.answer.plan.owner, '担当');
  const pol = c3.items.find(i => i.id === '1-3-1-1'); assert.equal(pol.evidence.policy.template_id, 'policy'); assert.equal(pol.evidence.ppc[0].id, 'people.rules');
  assert.ok(c3.items.find(i => i.id === '4-1-5-3').evidence.self?.length, '単体版の自己点検 (ロック) が裏づけ');
  assert.equal((await scs.criteria(A(op), { level: 4 })).items.length, 153);
  const s = await scs.summary(A(op)); assert.equal(s.level3.total, 81); assert.equal(s.level3.answered, 2); assert.ok(s.due.find(x => x.id === '1-2-1-3')); assert.equal(s.plans[0].id, '1-2-1-3'); assert.ok(s.tools.find(x => x.id === '5-1-1-1'));
  const plan = await scs.plan(A(op), { level: 3 }); assert.equal(plan.open, 80); assert.ok(plan.rows.find(r => r.id === '5-1-1-1').helps[0].includes('UTM'));
  const csv = await scs.planCsv(A(op), { level: 3 }); assert.ok(csv.startsWith('﻿評価基準,')); assert.match(csv, /体制表を作る/); assert.match(csv, /経済産業省/);
  const recs = mk.mm.records(A(op), { kind: 'scs_answer' }); assert.equal(recs.length, 2); assert.equal(mk.mm.verify(A(op)).ok, true);
});

test('確認の流れ: 写し → 専門家の助言と確認 → 経営層の宣誓 → 控えの書き出し', async () => {
  const { scs } = mk;
  scs.saveProfile(A(owner), { company: 'みなと精機', ceo: '代表取締役 港 一郎', lead: '取締役 佐藤', it: '総務部 担当', experts: [{ user_id: ex.id, name: '専門 花子', qualification: '情報処理安全確保支援士', reg_no: '000123' }] });
  const rq = await scs.requestReview(A(owner), { level: 3, note: '初回' }); assert.equal(rq.items, 81); assert.match(rq.snapshot_hash, /^[0-9a-f]{64}$/);
  await assert.rejects(() => scs.requestReview(A(owner), { level: 3 }), /終わっていない/);
  assert.throws(() => scs.decide(A(op), { review_id: rq.review_id, decision: 'confirm' }), /専門家/, '専門家でない人は確認できない');
  scs.comment(A(ex), { review_id: rq.review_id, criterion_id: '1-3-1-1', text: '方針の改定日を書いてください' });
  const back = scs.decide(A(ex), { review_id: rq.review_id, decision: 'return', statement: '直してください' }); assert.equal(back.state, 'returned');
  const rq2 = await scs.resubmit(A(owner), { review_id: rq.review_id }); assert.notEqual(rq2.review_id, rq.review_id);
  const g = scs.reviewGet(A(ex), rq2.review_id); assert.equal(g.comments.length, 1, '前の助言を引き継ぐ'); assert.equal(g.hash_ok, true);
  assert.throws(() => scs.declare(A(owner), { review_id: rq2.review_id }), /専門家の確認のあと/);
  const cf = scs.decide(A(ex), { review_id: rq2.review_id, decision: 'confirm' }); assert.equal(cf.state, 'confirmed'); assert.equal(cf.expert.reg_no, '000123');
  assert.throws(() => scs.declare(A(op), { review_id: rq2.review_id }), /経営層/);
  const dc = scs.declare(A(owner), { review_id: rq2.review_id, title: '代表取締役' }); assert.equal(dc.state, 'declared');
  const f = scs.exportReview(A(owner), { review_id: rq2.review_id, format: 'docx' }); const t = docxText(f.buffer);
  assert.match(t, /SCS 評価制度 ★3 自己評価の控え/); assert.match(t, /専門 花子 \(情報処理安全確保支援士 登録番号 000123\)/); assert.match(t, /IPA への提出の様式ではありません/);
  const kinds = mk.mm.records(A(owner), { limit: 500 }).map(r => r.kind); for (const k of ['scs_review_request', 'scs_review_comment', 'scs_expert_return', 'scs_expert_confirm', 'scs_declaration']) assert.ok(kinds.includes(k), k);
  // 写しを書き換えると確認できない
  const r3 = await scs.requestReview(A(owner), { level: 4 }); sa.ports.db().prepare("UPDATE mm_scs_reviews SET snapshot=replace(snapshot,'\"level\":4','\"level\":3') WHERE id=?").run(r3.review_id);
  assert.throws(() => scs.decide(A(ex), { review_id: r3.review_id, decision: 'confirm' }), /ハッシュと合いません/);
});

test('台帳: 必須の列・追加・見直し・CSV・削除 (記録に残る)', () => {
  const { ledgers } = mk;
  assert.throws(() => ledgers.upsert(A(op), { kind: 'secrets', data: { name: '顧客名簿' } }), /入れてください/);
  const r = ledgers.upsert(A(op), { kind: 'secrets', data: { name: '顧客名簿', level: '極秘', manager: '佐藤', dept: '営業', place: 'AI NAS', until: '取引終了後 5 年', contact: '内線 12', extra: 'x' } });
  assert.equal(ledgers.list(A(op), 'secrets').rows.length, 1); assert.equal(ledgers.list(A(op), 'secrets').rows[0].data.extra, undefined, '決まった列だけ');
  ledgers.upsert(A(op), { kind: 'secrets', id: r.id, data: { ...ledgers.list(A(op), 'secrets').rows[0].data, place: '金庫' } }); assert.equal(ledgers.list(A(op), 'secrets').rows[0].data.place, '金庫');
  assert.ok(ledgers.markReviewed(A(op), { kind: 'secrets' }).reviewed_at); assert.match(ledgers.csv(A(op), 'secrets'), /顧客名簿/);
  ledgers.remove(A(op), { kind: 'secrets', id: r.id }); assert.equal(ledgers.list(A(op), 'secrets').rows.length, 0);
  assert.deepEqual(mk.mm.records(A(op), { kind: 'ledger' }).map(x => x.payload.op), ['remove', 'update', 'add']);
  assert.ok(ledgers.suggest(A(owner), 'admins').suggestions.find(s => s.account === 'owner'), '箱の Owner を管理者 ID の候補に');
});

test('全員に知らせる: 知らせ → 社員が読んで確認 → 確認の数が評価基準の裏づけに', async () => {
  const { notices, scs } = mk;
  const n = notices.create(A(op), { title: 'パスワードのルール', body: '8 文字以上・使い回し禁止', criteria: ['4-1-5-5'] });
  assert.ok(notices.pending(A(staff)).notices.find(x => x.id === n.id)); const v = notices.view(A(staff), n.id); assert.equal(v.acked_at, null);
  notices.ack(A(staff), n.id); assert.equal(notices.pending(A(staff)).notices.length, 0); assert.equal(notices.ack(A(staff), n.id).already, true);
  const d = notices.detail(A(op), n.id); assert.equal(d.acks.length, 1); assert.ok(d.pending.find(u => u.username === 'owner'));
  const it = (await scs.criteria(A(op), { level: 3 })).items.find(i => i.id === '4-1-5-5'); assert.equal(it.evidence.notice.acks, 1); assert.equal(it.evidence.notice.audience, 4);
  notices.close(A(op), n.id); assert.throws(() => notices.ack(A(owner), n.id), /締め切/);
});

test('規程: ひな形に会社の情報 → AI で埋める (決まりを変えたら戻す) → 採用 → 全員に知らせる → レビュー (根拠の段落を確かめる)', async () => {
  const { policies, notices } = mk;
  const base = await policies.draft(A(op), { template_id: 'accounts' }); assert.match(base.body, /総務部 担当/); assert.equal(base.source, 'template');
  llmReply = base.body.replace('## 4. パスワード', '## 4. 合言葉'); // 見出しを変えた → ひな形のまま
  const bad = await policies.draft(A(op), { template_id: 'accounts', notes: '社員 10 人', use_ai: true }); assert.equal(bad.source, 'template'); assert.match(bad.ai.note, /見出しが変わった/);
  llmReply = base.body.replace('【要記入: 例: 90 日】', '90 日');
  const good = await policies.draft(A(op), { template_id: 'accounts', notes: '使われていない ID は 90 日で止める', use_ai: true }); assert.equal(good.source, 'ai'); assert.equal(good.ai.filled, 1);
  llmReply = base.body.replace('10 文字以上', '6 文字以上'); const weak = await policies.draft(A(op), { template_id: 'accounts', notes: 'x', use_ai: true }); assert.equal(weak.source, 'template', '数字の決まりを弱めたら戻す');
  llmReply = base.body.replace('【要記入: 例: 90 日】', '60 日'); const ex60 = await policies.draft(A(op), { template_id: 'accounts', notes: '60 日で止める', use_ai: true }); assert.equal(ex60.source, 'ai', '【要記入: 例: …】の中の数字は例なので、メモの数字で埋めてよい');
  const sv = policies.save(A(op), { template_id: 'accounts', body: good.body, source: 'ai' }); assert.equal(sv.version, 1);
  await assert.rejects(() => policies.adopt(A(op), { policy_id: sv.policy_id }), /権限|forbidden|role/i, '採用は Admin 以上');
  const ad = await policies.adopt(A(owner), { policy_id: sv.policy_id, notify: true }); assert.equal(ad.version, 1); assert.ok(ad.notice.criteria.includes('4-1-5-5'));
  assert.equal(notices.adopted(A(staff)).policies[0].version, 1); assert.match(notices.view(A(staff), ad.notice.id).policy.body, /90 日/);
  const sv2 = policies.save(A(op), { policy_id: sv.policy_id, body: good.body + '\n追記' }); assert.equal(sv2.version, 2, '採用済みの次は新しい版');
  const ex2 = policies.exportDoc(A(op), { policy_id: sv.policy_id, format: 'docx' }); assert.match(docxText(ex2.buffer), /ID・パスワード・アクセス権の管理ルール/);
  // レビュー: 手持ちの短い規程。AI は実在しない段落 (99) を挙げる・根拠なしで covered と言う → 外す / 確かめられないにする
  const doc = '# パスワード規程\n\n1. 社員の ID は総務が申請と承認で発行する。\n\n2. パスワードは 8 文字以上とし、使い回しを禁止する。\n\n3. 退職者の ID は退職日に削除する。';
  assert.equal(paragraphs(doc).length, 4);
  llmReply = JSON.stringify({ results: [{ element: 'lifecycle', status: 'covered', paragraphs: [2, 99], comment: '申請と承認あり' }, { element: 'mfa', status: 'covered', paragraphs: [], comment: 'ある' }, { element: 'password', status: 'partial', paragraphs: ['P3'], suggestion: '初期パスワードの変更も書く' }] });
  const rv = await policies.review(A(op), { template_id: 'accounts', text: doc, level: 3 });
  const R = Object.fromEntries(rv.results.map(r => [r.element, r]));
  assert.deepEqual(R.lifecycle.ai.paragraphs.map(p => p.n), [2], '実在しない段落は外す'); assert.equal(R.lifecycle.verdict, 'covered'); assert.match(R.lifecycle.ai.paragraphs[0].text, /申請と承認/);
  assert.equal(R.mfa.verdict, 'unclear', '根拠の無い「書かれている」は認めない'); assert.equal(R.password.verdict, 'partial');
  assert.ok(!R.inventory, '★3 で絞ると ★4 の要素は出ない'); assert.equal(R.remove.verdict, 'found', 'AI が答えなかった要素は言葉の手がかり');
  assert.ok(mk.mm.records(A(op), { kind: 'policy_review' })[0].payload.text_sha256);
  // Word の文書でも
  const rv2 = await policies.review(A(op), { template_id: 'accounts', file_b64: mdToDocx(doc).toString('base64'), name: '規程.docx', level: 3, use_ai: false }); assert.equal(rv2.results.find(r => r.element === 'lifecycle').verdict, 'found');
  await assert.rejects(() => policies.review(A(op), { template_id: 'accounts', file_b64: Buffer.from('%PDF-1.4').toString('base64'), name: 'a.pdf' }), /PDF/);
  assert.equal(mk.mm.verify(A(op)).ok, true, '記録の鎖は正常');
});
