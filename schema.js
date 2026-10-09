// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳が使う表。何度呼んでも同じ結果 (CREATE IF NOT EXISTS + 足りない列だけ ALTER)。言箱 OS の既存の DB (別の移行で作られた表) の上でも、単体版のまっさらな DB でも同じに動く。
const TABLES = [
  // 調べてよい対象の台帳と、1 回ずつの調査 (承認・判定・出力のハッシュ・伏せ字ずみの出力)
  `CREATE TABLE IF NOT EXISTS probe_targets (id TEXT PRIMARY KEY, name TEXT, kind TEXT, host TEXT, port INTEGER, username TEXT, credential_id TEXT, credential_expires_at TEXT, host_keys TEXT, verify TEXT,
    excluded INTEGER DEFAULT 0, notes TEXT, revoke_requested_at TEXT, revoked_at TEXT, created_by TEXT, created_at TEXT, updated_at TEXT, state TEXT DEFAULT 'ready', enroll_token_hash TEXT, enroll_expires_at TEXT, attested_by TEXT, enrolled_hostname TEXT)`,
  `CREATE TABLE IF NOT EXISTS probe_runs (id TEXT PRIMARY KEY, target_id TEXT, template_id TEXT, argv TEXT, explanation TEXT, reason TEXT, class TEXT, classification TEXT, ai TEXT, approval_id TEXT,
    state TEXT, requested_by TEXT, approved_by TEXT, created_at TEXT, started_at TEXT, finished_at TEXT, exit_code INTEGER, output_path TEXT, output_sha256 TEXT, output_bytes INTEGER, error TEXT, output TEXT)`,
  'CREATE INDEX IF NOT EXISTS idx_probe_runs_target ON probe_runs(target_id, created_at)',
  'CREATE INDEX IF NOT EXISTS idx_probe_runs_approval ON probe_runs(approval_id)',
  // 点検の答え・記録の鎖 (1 件ごとに前のハッシュを含めて署名)・設定 (もしものときのカードなど)
  'CREATE TABLE IF NOT EXISTS mamoricho_answers (item_id TEXT PRIMARY KEY, status TEXT, note TEXT, evidence TEXT, updated_by TEXT, updated_at TEXT)',
  'CREATE TABLE IF NOT EXISTS mamoricho_records (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE, kind TEXT, payload TEXT, by_id TEXT, by_name TEXT, at TEXT, prev_hash TEXT, hash TEXT, sig TEXT, baseline TEXT)',
  'CREATE INDEX IF NOT EXISTS idx_mamoricho_records_kind ON mamoricho_records(kind, seq)',
  'CREATE TABLE IF NOT EXISTS mamoricho_settings (key TEXT PRIMARY KEY, value TEXT)',
  // 管理者監視の正規化したイベント (原本は probe_runs / 監査ログ)
  'CREATE TABLE IF NOT EXISTS admin_events (id TEXT PRIMARY KEY, source TEXT, target_id TEXT, ts TEXT, actor_id TEXT, actor_role TEXT, actor_ip TEXT, action TEXT, result TEXT, details TEXT, evidence TEXT, created_at TEXT)',
  'CREATE INDEX IF NOT EXISTS idx_admin_events_target ON admin_events(target_id, ts)',
  // API 認可検査: 仕様・主体・期待権限の版・計画・実行
  'CREATE TABLE IF NOT EXISTS authz_specs (id TEXT PRIMARY KEY, target_id TEXT, name TEXT, source TEXT, spec_hash TEXT, operations TEXT, created_by TEXT, created_at TEXT)',
  'CREATE TABLE IF NOT EXISTS authz_actors (id TEXT PRIMARY KEY, target_id TEXT, label TEXT, role TEXT, tenant TEXT, params TEXT, credential_id TEXT, auth_kind TEXT, header_name TEXT, created_by TEXT, created_at TEXT, updated_at TEXT)',
  'CREATE TABLE IF NOT EXISTS authz_policies (id TEXT PRIMARY KEY, target_id TEXT, version INTEGER, matrix TEXT, note TEXT, approved_by TEXT, created_at TEXT)',
  'CREATE TABLE IF NOT EXISTS authz_plans (id TEXT PRIMARY KEY, target_id TEXT, spec_id TEXT, policy_id TEXT, cases TEXT, skipped TEXT, pinned TEXT, plan_hash TEXT, state TEXT, approval_id TEXT, created_by TEXT, created_at TEXT)',
  'CREATE TABLE IF NOT EXISTS authz_runs (id TEXT PRIMARY KEY, plan_id TEXT, target_id TEXT, state TEXT, results TEXT, totals TEXT, record_id TEXT, requested_by TEXT, approved_by TEXT, started_at TEXT, finished_at TEXT, error TEXT)',
  'CREATE INDEX IF NOT EXISTS idx_authz_runs_target ON authz_runs(target_id, started_at)',
];
// 古い DB (表はあるが列が足りない) に足す列
const COLUMNS = { probe_targets: { state: "TEXT DEFAULT 'ready'", enroll_token_hash: 'TEXT', enroll_expires_at: 'TEXT', attested_by: 'TEXT', enrolled_hostname: 'TEXT' }, probe_runs: { output: 'TEXT' } };
export function ensureSchema(db) {
  for (const s of TABLES) db.exec(s);
  for (const [t, cols] of Object.entries(COLUMNS)) { const have = new Set(db.prepare(`PRAGMA table_info(${t})`).all().map(c => c.name)); for (const [c, def] of Object.entries(cols)) if (!have.has(c)) db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} ${def}`); }
  return db;
}
