// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳が「外の世界」に求めるもの (ポート)。パッケージの中からは、ここに書いたものと node の標準モジュールにしか触らない
// (test/mamoricho-boundary.test.js が import を見張る)。言箱 OS では src/mamoricho-adapter.js が、単体版では standalone/ がこれを実装する。
//   必須: db / audit / requireRole / vault / approvals / signer。残りは無くても動く (無い機能は「この環境では確認できない」と出す)。
const REQUIRED = ['db', 'audit', 'requireRole', 'vault', 'approvals', 'signer'];
export const DEFAULT_BRAND = { product: 'まもり帳', os: 'この箱', os_en: 'Mamoricho', vendor: '', ua: 'Mamoricho', image: 'mamoricho-probe:1', user: 'mamoricho', ai: 'ローカルの AI', store: 'この箱の保存先' };
export function makePorts(p = {}) {
  for (const k of REQUIRED) if (!p[k]) throw new Error(`mamoricho: ports.${k} が要ります`);
  for (const k of ['store', 'use', 'delete']) if (typeof p.vault[k] !== 'function') throw new Error(`mamoricho: ports.vault.${k} が要ります`);
  for (const k of ['create', 'get']) if (typeof p.approvals[k] !== 'function') throw new Error(`mamoricho: ports.approvals.${k} が要ります`);
  return {
    db: p.db,                                   // () => node:sqlite の DatabaseSync (表は schema.js の ensureSchema で用意する)
    audit: p.audit,                             // ({ actor, action, target, detail, ip }) => void。監査ログ (改ざん検知つきが望ましい)
    listAudit: p.listAudit || (() => []),       // ({ limit, since }) => [{ id, time, actor_id, actor_name, action, target, detail, ip, result, hash }]。言箱自身の管理者監視に使う
    requireRole: p.requireRole,                 // (actor, 'viewer' | 'operator' | 'admin' | 'owner') => 権限が無ければ throw
    users: { list: () => [], firstTenant: () => null, ...(p.users || {}) }, // list(tenant_id) → [{ id, username, display_name, role, status, mfa_factors }]
    sharedWorkspace: p.sharedWorkspace || (() => null), // (actor) => 調査の出力を保存する共有の置き場の id (無ければ null)
    apiKeys: p.apiKeys || (() => []),           // () => [{ id, name, prefix, revoked_at }]。言箱自身の管理者監視 (トークンの一覧)
    vault: p.vault,                             // { store(actor, { provider, name, secret, scope, expires_at }) → { id }, use(id) → 秘密, delete(actor, id) }
    approvals: p.approvals,                     // { create({ action, summary, detail, requested_by, ttl_min }) → { id }, get(id) → { id, state, action, detail, approver_id, expires_at, requested_by } }
    signer: p.signer,                           // { privateKey() → crypto.KeyObject | null }。記録の鎖の署名
    notify: p.notify || (() => {}),             // ({ kind, severity, title, body, dedupe_key, link }) => void
    selfChecks: p.selfChecks || null,           // async (actor) => [{ id, label, item, ok, detail, level }]。箱 (OS) 自身の自己点検。無ければ空
    externalAi: p.externalAi || (() => !!(p.llm && p.llm.local === false)), // () => AI が箱の外か
    brand: { ...DEFAULT_BRAND, ...(p.brand || {}) },
    llm: p.llm || null,                         // { chat(messages, { temperature, max_tokens, json }) → { content }, model, provider, local }。llm/providers.js の createLlm で作れる
    akigrid: p.akigrid || null,                 // 任意: OpenVons 型の選択肢判断 ({ req(path, { method, body, tenant, timeout_ms }) })。無ければ logprobs か無し
    nas: p.nas || null,                         // 任意: { ingest(actor, { workspace_id, name, buffer, folder, tags, origin }) → { id } }
    netops: p.netops || null,                   // 任意: { listDevices() → [{ mgmt_ip, name, vendor }] }
    rag: p.rag || null,                         // 任意: { ask(actor, { workspace_id, question, k, answer }) → { hits } }
  };
}
