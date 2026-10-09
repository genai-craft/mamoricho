// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// 単体版: 組み込み先 (言箱 OS など) 無しで、ログイン → 画面の API → 記録の鎖 → 再認証つきの登録 → 権限の拒否、が通る
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../standalone/server.mjs';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mamoricho-sa-'));
const app = createServer({ dataDir, config: { llm: false } });
await new Promise(r => app.server.listen(0, '127.0.0.1', r)); const base = `http://127.0.0.1:${app.server.address().port}`;
after(() => app.stop()); // 失敗してもサーバーを閉じる (閉じないとテストが終わらない)
const jar = {}; // 名前 → cookie
async function call(method, p, body, { as = 'owner', headers = {} } = {}) {
  const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...(jar[as] ? { cookie: jar[as] } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const sc = r.headers.get('set-cookie'); if (sc && as) jar[as] = sc.split(';')[0];
  const ct = r.headers.get('content-type') || ''; return { status: r.status, data: ct.includes('json') ? await r.json() : await r.text() };
}
test('単体版: 初期設定 → ログイン → 画面の API', async () => {
  assert.equal((await call('GET', '/api/v1/setup', undefined, { as: null })).data.needs_setup, true);
  app.auth.createUser(null, { username: 'owner', password: 'ownerpass123', role: 'owner' });
  assert.equal((await call('GET', '/api/v1/auth/me', undefined, { as: null })).status, 401, 'ログイン前は 401');
  assert.equal((await call('POST', '/api/v1/auth/login', { username: 'owner', password: 'wrong' }, { as: 'x' })).status, 401);
  const lg = await call('POST', '/api/v1/auth/login', { username: 'owner', password: 'ownerpass123' }); assert.equal(lg.status, 200); assert.equal(lg.data.user.role, 'owner'); assert.ok(jar.owner.startsWith('aios_session='));
  assert.equal((await call('GET', '/api/v1/auth/me')).data.user.username, 'owner');
  const brand = (await call('GET', '/api/v1/mamoricho/brand')).data.brand; assert.equal(brand.os, 'まもり帳'); assert.equal(brand.vendor, 'genai-craft');
  const sum = (await call('GET', '/api/v1/mamoricho/summary')).data; assert.equal(sum.total, 42); assert.equal(sum.answered, 0); assert.ok(sum.self.total >= 3, '単体版の自己点検 (https / ロック / AI / docker)');
  const sec = (await call('GET', '/api/v1/probe/security-summary')).data; assert.equal(sec.steps.length, 7); assert.equal(sec.priority.route, 'emergency');
  const sf = (await call('GET', '/api/v1/mamoricho/safety')).data; assert.ok(sf.items.find(i => i.id === 'inside').ok, 'AI 無し = 外に出ない');
  const a = await call('POST', '/api/v1/mamoricho/answer', { item_id: 'entry.password', status: 'partial', note: '文字数だけ' }); assert.equal(a.status, 200); assert.ok(a.data.record_id);
  const rec = (await call('GET', '/api/v1/mamoricho/records')).data; assert.equal(rec.chain.ok, true); assert.equal(rec.chain.signed, true); assert.equal(rec.records[0].kind, 'answer');
  const home = await call('GET', '/', undefined, { as: null }); assert.equal(home.status, 200); assert.match(home.data, /<title>まもり帳<\/title>/);
  assert.match((await call('GET', '/mamoricho.js', undefined, { as: null })).data, /const B = \{ product: 'まもり帳'/); assert.match((await call('GET', '/shell.js', undefined, { as: null })).data, /routedApp/);
  assert.equal((await call('GET', '/api/v1/nothing')).status, 404);
});
test('単体版: 再認証つきの対象の登録、権限の拒否、承認は admin 以上、監査ログの鎖', async () => {
  const no = await call('POST', '/api/v1/probe/targets', { name: 'HP', kind: 'web', host: 'example.jp', attested: true }); assert.equal(no.status, 403); assert.equal(no.data.error.code, 'reauth_required');
  const ra = await call('POST', '/api/v1/auth/reauth', { password: 'ownerpass123' }); assert.ok(ra.data.reauth_token);
  const add = await call('POST', '/api/v1/probe/targets', { name: 'HP', kind: 'web', host: 'example.jp', attested: true }, { headers: { 'x-reauth-token': ra.data.reauth_token } }); assert.equal(add.status, 200, JSON.stringify(add.data)); assert.equal(add.data.kind, 'web');
  assert.equal((await call('GET', '/api/v1/probe/targets')).data.targets.length, 1);
  // 一般の閲覧者は答えられない・台帳も見られない
  app.auth.createUser(null, { username: 'viewer1', password: 'viewerpass1', role: 'viewer' }); await call('POST', '/api/v1/auth/login', { username: 'viewer1', password: 'viewerpass1' }, { as: 'viewer' });
  assert.equal((await call('POST', '/api/v1/mamoricho/answer', { item_id: 'entry.password', status: 'ok' }, { as: 'viewer' })).status, 403);
  assert.equal((await call('GET', '/api/v1/probe/targets', undefined, { as: 'viewer' })).status, 403);
  assert.equal((await call('GET', '/api/v1/mamoricho/summary', undefined, { as: 'viewer' })).status, 200, '閲覧はできる');
  // 承認: probe:authz は admin 以上。operator は決められない
  const ap = app.standalone.approvals.create({ action: 'probe:authz', summary: 't', detail: { plan_id: 'p1' }, requested_by: { id: 'u' } }); assert.equal(ap.state, 'pending');
  app.auth.createUser(null, { username: 'oper', password: 'operatorpass1', role: 'operator' }); await call('POST', '/api/v1/auth/login', { username: 'oper', password: 'operatorpass1' }, { as: 'op' });
  assert.equal((await call('POST', `/api/v1/approvals/${ap.id}/decide`, { decision: 'approve' }, { as: 'op' })).status, 403);
  const ok = await call('POST', `/api/v1/approvals/${ap.id}/decide`, { decision: 'approve' }); assert.equal(ok.data.state, 'approved'); assert.equal(ok.data.approver_id, app.auth.users().find(u => u.username === 'owner').id);
  // 金庫: 入れたものは画面に出ず、使うときだけ戻る
  const c = app.ports.vault.store({ id: 'u' }, { provider: 'test', name: 'x', secret: 'top-secret' }); assert.equal(app.ports.vault.use(c.id), 'top-secret'); assert.ok(!JSON.stringify(app.ports.db().prepare('SELECT * FROM credentials').all()).includes('top-secret'));
  // ログイン失敗の連続でロック
  for (let i = 0; i < 5; i++) await call('POST', '/api/v1/auth/login', { username: 'owner', password: 'bad' }, { as: 'z' });
  assert.equal((await call('POST', '/api/v1/auth/login', { username: 'owner', password: 'ownerpass123' }, { as: 'z' })).status, 429);
  const h = (await call('GET', '/api/v1/system/health')).data; assert.equal(h.audit.ok, true); assert.equal(h.llm, null);
});
