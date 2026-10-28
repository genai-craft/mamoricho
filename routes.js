// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// SCS 評価制度の点検・台帳・規程・周知の HTTP の経路。言箱 OS (src/server.js) と単体版 (standalone/server.mjs) が同じ一覧を登録する。
//   route(method, pattern, handler, { role }) は組み込み先の登録関数。handler は ({ actor, params, query, body, res }) を受け、自分で応答したら null を返す。
//   /api/v1/mamoricho-ack/… は、まもり帳を使う許可が無い社員でも使う口 (お知らせを読む・確認を押す・採用した規程を見る)
const file = (res, f) => { res.writeHead(200, { 'content-type': f.type, 'content-disposition': `attachment; filename*=UTF-8''${encodeURIComponent(f.name)}`, 'content-length': f.buffer.length, 'cache-control': 'no-store' }); res.end(f.buffer); return null; };
const csv = (res, name, text) => file(res, { name, type: 'text/csv; charset=utf-8', buffer: Buffer.from(text, 'utf8') });

export function registerExtRoutes(route, { scs, ledgers, policies, notices }) {
  // ---- SCS の点検 ----
  route('GET', '/api/v1/mamoricho/scs/summary', ({ actor }) => scs.summary(actor));
  route('GET', '/api/v1/mamoricho/scs/criteria', ({ actor, query }) => scs.criteria(actor, { level: query.level }));
  route('POST', '/api/v1/mamoricho/scs/answer', ({ actor, body }) => scs.answer(actor, body || {}), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/scs/done', ({ actor, body }) => scs.markDone(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/scs/profile', ({ actor }) => ({ profile: scs.profile(), executives: scs.executives(actor) }));
  route('PUT', '/api/v1/mamoricho/scs/profile', ({ actor, body }) => scs.saveProfile(actor, body || {}), { role: 'admin' });
  route('GET', '/api/v1/mamoricho/scs/users', ({ actor }) => { scs.ports.requireRole(actor, 'admin'); const tenant = actor.tenant_id || scs.ports.users.firstTenant(); return { users: (tenant ? scs.ports.users.list(tenant) : []).filter(u => (u.status || 'active') === 'active').map(u => ({ id: u.id, username: u.username, display_name: u.display_name || u.username, role: u.role, executive: !!u.executive })) }; }, { role: 'admin' });
  route('GET', '/api/v1/mamoricho/scs/plan.csv', async ({ actor, query, res }) => csv(res, `SCS-star${Number(query.level) >= 4 ? 4 : 3}-改善計画書.csv`, await scs.planCsv(actor, { level: query.level })));
  route('GET', '/api/v1/mamoricho/scs/plan', ({ actor, query }) => scs.plan(actor, { level: query.level }));
  route('GET', '/api/v1/mamoricho/scs/reviews', ({ actor }) => scs.reviewList(actor));
  route('POST', '/api/v1/mamoricho/scs/reviews', ({ actor, body }) => scs.requestReview(actor, body || {}), { role: 'admin' });
  route('GET', '/api/v1/mamoricho/scs/reviews/:id/export', ({ actor, params, query, res }) => file(res, scs.exportReview(actor, { review_id: params.id, format: query.format === 'md' ? 'md' : 'docx' })));
  route('GET', '/api/v1/mamoricho/scs/reviews/:id', ({ actor, params }) => scs.reviewGet(actor, params.id));
  route('POST', '/api/v1/mamoricho/scs/reviews/:id/comment', ({ actor, params, body }) => scs.comment(actor, { ...(body || {}), review_id: params.id }));
  route('POST', '/api/v1/mamoricho/scs/reviews/:id/decide', ({ actor, params, body }) => scs.decide(actor, { ...(body || {}), review_id: params.id }));
  route('POST', '/api/v1/mamoricho/scs/reviews/:id/declare', ({ actor, params, body }) => scs.declare(actor, { ...(body || {}), review_id: params.id }));
  route('POST', '/api/v1/mamoricho/scs/reviews/:id/resubmit', ({ actor, params, body }) => scs.resubmit(actor, { ...(body || {}), review_id: params.id }), { role: 'admin' });
  route('POST', '/api/v1/mamoricho/scs/reviews/:id/withdraw', ({ actor, params }) => scs.withdraw(actor, { review_id: params.id }), { role: 'admin' });
  // ---- 台帳 ----
  route('GET', '/api/v1/mamoricho/ledgers', ({ actor }) => { scs.ports.requireRole(actor, 'viewer'); return { kinds: ledgers.kinds(), counts: ledgers.counts() }; });
  route('GET', '/api/v1/mamoricho/ledgers/:kind/csv', ({ actor, params, res }) => csv(res, `${ledgers.kind(params.kind).label}.csv`, ledgers.csv(actor, params.kind)));
  route('GET', '/api/v1/mamoricho/ledgers/:kind/suggest', ({ actor, params }) => ledgers.suggest(actor, params.kind, ['servers', 'netdevices', 'admins'].includes(params.kind) ? scs._facts(actor) : null), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/ledgers/:kind/reviewed', ({ actor, params, body }) => ledgers.markReviewed(actor, { kind: params.kind, note: body?.note || '' }), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/ledgers/:kind', ({ actor, params }) => ledgers.list(actor, params.kind));
  route('POST', '/api/v1/mamoricho/ledgers/:kind', ({ actor, params, body }) => ledgers.upsert(actor, { ...(body || {}), kind: params.kind }), { role: 'operator' });
  route('DELETE', '/api/v1/mamoricho/ledgers/:kind/:id', ({ actor, params }) => ledgers.remove(actor, { kind: params.kind, id: params.id }), { role: 'operator' });
  // ---- 規程 ----
  route('GET', '/api/v1/mamoricho/policies/templates', ({ actor }) => policies.templates(actor));
  route('POST', '/api/v1/mamoricho/policies/draft', ({ actor, body }) => policies.draft(actor, body || {}), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/policies/review', ({ actor, body }) => policies.review(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/policies/reviews', ({ actor, query }) => policies.reviews(actor, { template_id: query.template_id || null }));
  route('GET', '/api/v1/mamoricho/policies/reviews/:id', ({ actor, params }) => policies.reviewOne(actor, params.id));
  route('GET', '/api/v1/mamoricho/policies', ({ actor }) => policies.list(actor));
  route('POST', '/api/v1/mamoricho/policies', ({ actor, body }) => policies.save(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/policies/:id/export', ({ actor, params, query, res }) => file(res, policies.exportDoc(actor, { policy_id: params.id, version: query.version || null, format: query.format === 'md' ? 'md' : 'docx' })));
  route('POST', '/api/v1/mamoricho/policies/:id/adopt', ({ actor, params, body }) => policies.adopt(actor, { ...(body || {}), policy_id: params.id }), { role: 'admin' });
  route('GET', '/api/v1/mamoricho/policies/:id', ({ actor, params }) => policies.get(actor, params.id));
  // ---- 全員に知らせる ----
  route('GET', '/api/v1/mamoricho/notices', ({ actor }) => notices.list(actor), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/notices', ({ actor, body }) => notices.create(actor, body || {}), { role: 'operator' });
  route('GET', '/api/v1/mamoricho/notices/:id', ({ actor, params }) => notices.detail(actor, params.id), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/notices/:id/remind', ({ actor, params }) => notices.remind(actor, params.id), { role: 'operator' });
  route('POST', '/api/v1/mamoricho/notices/:id/close', ({ actor, params }) => notices.close(actor, params.id), { role: 'operator' });
  // ---- だれでも: お知らせを読む・確認を押す・採用した規程を見る ----
  route('GET', '/api/v1/mamoricho-ack/pending', ({ actor }) => notices.pending(actor));
  route('GET', '/api/v1/mamoricho-ack/notice/:id', ({ actor, params }) => notices.view(actor, params.id));
  route('POST', '/api/v1/mamoricho-ack/notice/:id', ({ actor, params }) => notices.ack(actor, params.id));
  route('GET', '/api/v1/mamoricho-ack/policies', ({ actor }) => notices.adopted(actor));
  route('GET', '/api/v1/mamoricho-ack/policies/:id', ({ actor, params }) => notices.adoptedOne(actor, params.id));
}
