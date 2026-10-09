// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳の API 認可検査 — 決まりと純粋な計算 (docs/MAMORICHO_DESIGN.md「API の権限を確かめる」)。
//   OpenAPI / 利用者の一覧 → 操作の一覧、期待権限の表 (人が承認) → 検査の計画 (操作 × 主体 × 誰のデータか)、応答 → 4 つの結果。
//   ここには通信も DB も無い (試験しやすく、AI が触れない)。実行は api-authz.js (台帳・承認・使い捨てコンテナ)。
import { HttpError } from '../util.js';

// 実行の決まり (初期値)。公開 HP 診断の GET/HEAD 型とは別の、API 認可検査専用の方針
export const LIMITS = { rps: 1, max_requests: 100, max_5xx: 5, methods: ['GET', 'HEAD'], timeout_s: 15, max_body: 200000 };
export const RESULTS = { ok: '想定どおり', suspect: '認可不備の疑い', unclear: '判断できない', skipped: '未検査' };
export const CHECKS = { 'AUTHZ-01': '未認証で管理 API を使えない', 'AUTHZ-02': '一般ユーザーで管理 API を使えない', 'AUTHZ-03': '他のユーザーのデータを見られない', 'AUTHZ-04': '他のテナントのデータを見られない', 'AUTHZ-05': '権限のない主体から書き換えられない', 'AUTHZ-06': '前回まで拒否された操作が許されるようになっていない' };
export const ROLES = { anon: '未ログイン', user: '一般ユーザー', admin: '管理者' };
export const EXPECTED = ['allow', 'deny', 'unknown'];
const PATH_RE = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/{}-]*$/;
const METHODS = ['get', 'head', 'post', 'put', 'patch', 'delete', 'options'];

// OpenAPI 3 / Swagger 2 の JSON (オブジェクト) → 操作の一覧。YAML はこの版では読まない (依存を増やさない)。$ref は追わない (引数の名前が取れないだけ)
export function parseOpenApi(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new HttpError(400, 'bad_spec', 'OpenAPI は JSON のオブジェクトで入れてください (YAML はこの版では読めません。変換してから)');
  const paths = doc.paths; if (!paths || typeof paths !== 'object') throw new HttpError(400, 'bad_spec', 'OpenAPI に paths がありません');
  const base = typeof doc.basePath === 'string' ? doc.basePath.replace(/\/$/, '') : '';
  const ops = []; const ids = new Set(); const globalSec = Array.isArray(doc.security) && doc.security.length > 0;
  for (const [p, item] of Object.entries(paths)) {
    if (!item || typeof item !== 'object' || !/^\//.test(p)) continue; const common = Array.isArray(item.parameters) ? item.parameters : [];
    for (const m of METHODS) {
      const o = item[m]; if (!o || typeof o !== 'object') continue;
      const params = [...common, ...(Array.isArray(o.parameters) ? o.parameters : [])].filter(x => x && typeof x === 'object' && x.name).map(x => ({ name: String(x.name).slice(0, 60), in: String(x.in || 'query').slice(0, 10), required: !!x.required }));
      let oid = String(o.operationId || `${m}_${(base + p).replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '')}`).slice(0, 120); let n = 2; const b = oid; while (ids.has(oid)) oid = `${b}_${n++}`; ids.add(oid);
      const path = (base + p).slice(0, 300); if (!PATH_RE.test(path)) continue;
      ops.push({ operation_id: oid, method: m.toUpperCase(), path, summary: String(o.summary || o.description || '').replace(/\s+/g, ' ').slice(0, 200), tags: Array.isArray(o.tags) ? o.tags.map(String).slice(0, 5) : [], params, secured: o.security !== undefined ? (Array.isArray(o.security) && o.security.length > 0) : globalSec });
    }
  }
  if (!ops.length) throw new HttpError(400, 'bad_spec', 'OpenAPI に操作 (paths の get/post …) がありません');
  return { title: String(doc.info?.title || '').slice(0, 120), version: String(doc.info?.version || '').slice(0, 40), operations: ops.slice(0, 500), truncated: ops.length > 500 };
}
// 利用者が書いた一覧: 1 行に「GET /api/users/{id} 説明」(配列 [{method,path,summary}] でも)
export function parseManualList(input) {
  const rows = Array.isArray(input) ? input : String(input || '').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')).map(l => { const m = l.match(/^([A-Za-z]+)\s+(\S+)(?:\s+(.*))?$/); return m ? { method: m[1], path: m[2], summary: m[3] || '' } : null; }).filter(Boolean);
  const ops = []; const ids = new Set();
  for (const r of rows.slice(0, 500)) {
    const method = String(r?.method || '').toUpperCase(); const path = String(r?.path || '').slice(0, 300); if (!METHODS.includes(method.toLowerCase()) || !PATH_RE.test(path)) continue;
    const params = [...path.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map(m => ({ name: m[1], in: 'path', required: true }));
    let oid = `${method.toLowerCase()}_${path.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '')}`.slice(0, 120); let n = 2; const b = oid; while (ids.has(oid)) oid = `${b}_${n++}`; ids.add(oid);
    ops.push({ operation_id: oid, method, path, summary: String(r.summary || '').replace(/\s+/g, ' ').slice(0, 200), tags: [], params, secured: true });
  }
  if (!ops.length) throw new HttpError(400, 'bad_list', '読める行がありません (1 行に「GET /api/users/{id} 説明」の形で)');
  return { title: '', version: '', operations: ops, truncated: false };
}
// path の {name} を主体のテスト用データで埋める。足りない名前は missing に。値は URL 用に符号化し、記号で範囲を逸脱させない
export function substitutePath(path, params = {}) {
  const missing = [];
  const out = String(path).replace(/\{([A-Za-z0-9_]+)\}/g, (m, k) => { const v = params?.[k]; if (v === undefined || v === null || v === '') { missing.push(k); return m; } return encodeURIComponent(String(v)).replace(/%2F/gi, ''); });
  return { path: out, missing };
}
const markers = (params = {}) => Object.values(params || {}).map(v => String(v)).filter(v => v.length >= 2);
const hasPath = (op) => /\{[A-Za-z0-9_]+\}/.test(op.path);

// 計画: 操作 × 主体 (× 誰のデータか) → 検査の 1 件ずつ。期待権限は matrix[operation_id][actor_id] (allow / deny / unknown)。unknown は確認待ち (未検査)
//   他人のデータ (AUTHZ-03/04): path に引数がある操作で、別の主体のテスト用データを入れる。期待は deny (管理者が allow の操作で同じテナントなら allow)
//   GET/HEAD 以外 (AUTHZ-05) は初期状態では実行しない (ステージング・使い捨てデータ・復元手段を備えたときに別途承認)
export function buildPlan({ operations = [], actors = [], matrix = {}, limits = LIMITS } = {}) {
  const cases = []; const skipped = []; const act = actors.filter(a => a && a.id);
  const skip = (c, reason) => skipped.push({ ...c, result: RESULTS.skipped, reason });
  const exp = (op, a) => { const v = matrix?.[op.operation_id]?.[a.id]; return EXPECTED.includes(v) ? v : (a.role === 'anon' && op.secured ? 'deny' : 'unknown'); };
  const owners = act.filter(a => a.role !== 'anon' && Object.keys(a.params || {}).length);
  for (const op of operations) {
    const write = !limits.methods.includes(op.method);
    for (const a of act) {
      const e = exp(op, a); const base = { operation_id: op.operation_id, method: op.method, path: op.path, summary: op.summary || '', actor_id: a.id, actor_label: a.label || a.id, actor_role: a.role, owner_id: a.id, owner_label: a.label || a.id, expected: e, check: null, url_path: null, marker: [], own_marker: markers(a.params) };
      if (write) { skip({ ...base, check: 'AUTHZ-05' }, 'GET/HEAD 以外は初期状態では実行しません (ステージング環境・使い捨てデータ・復元手段を備えたときに別途承認)'); continue; }
      if (e === 'unknown') { skip(base, '期待する権限が未確定です (確認待ち)。「期待する権限」の表で allow か deny を決めてください'); continue; }
      // 自分のデータ (または引数の要らない操作)。未ログインには引数が無いので、誰かのデータで試す
      const owner = a.role === 'anon' && hasPath(op) ? owners[0] : a; const sub = substitutePath(op.path, owner?.params || {});
      if (sub.missing.length) { skip(base, `テスト用データが足りません (${sub.missing.join(', ')})。主体の「テスト用データ」に入れてください`); }
      else cases.push({ ...base, owner_id: owner?.id || a.id, owner_label: owner?.label || base.owner_label, url_path: sub.path, marker: owner && owner.id !== a.id ? markers(owner.params) : [], check: a.role === 'anon' ? 'AUTHZ-01' : (a.role === 'user' && e === 'deny') ? 'AUTHZ-02' : null });
      // 他の主体のデータ
      if (hasPath(op) && a.role !== 'anon') for (const o of owners) {
        if (o.id === a.id) continue; const s2 = substitutePath(op.path, o.params); if (s2.missing.length) continue;
        const cross = !!(o.tenant && a.tenant && o.tenant !== a.tenant); const expected = a.role === 'admin' && e === 'allow' && !cross ? 'allow' : 'deny';
        cases.push({ ...base, owner_id: o.id, owner_label: o.label || o.id, expected, check: cross ? 'AUTHZ-04' : 'AUTHZ-03', url_path: s2.path, marker: markers(o.params) });
      }
    }
  }
  const over = cases.splice(limits.max_requests); for (const c of over) skip(c, `1 回の上限 (${limits.max_requests} リクエスト) を超えた分。主体や操作を絞るか、回を分けてください`);
  return { cases, skipped, total_requests: cases.length };
}
// 応答 → 結果。状態コードだけでなく、対象データの識別子 (他の主体のテスト用データの値) が本文にあるかを見る
export function evaluate(c, resp) {
  if (!resp || resp.error || !resp.status) return { result: RESULTS.unclear, reason: `応答がありません (${resp?.error || '接続できない・時間切れ'})` };
  const s = Number(resp.status); const body = String(resp.body || ''); const has = (vals) => (vals || []).some(v => v && body.includes(v));
  if (s >= 500) return { result: RESULTS.unclear, reason: `サーバーのエラー (HTTP ${s})` };
  if (s === 429) return { result: RESULTS.unclear, reason: '回数の制限にかかりました (HTTP 429)' };
  if (s >= 300 && s < 400) return { result: RESULTS.unclear, reason: `転送 (HTTP ${s})。転送先は追いません (範囲の逸脱を防ぐため)` };
  const denied = s === 401 || s === 403 || s === 404 || s === 405;
  if (c.expected === 'deny') {
    if (denied) return { result: RESULTS.ok, reason: `拒否されました (HTTP ${s})` };
    if (s >= 200 && s < 300) {
      if (c.owner_id !== c.actor_id && c.marker?.length) { if (has(c.marker)) return { result: RESULTS.suspect, reason: `他の主体 (${c.owner_label}) のデータの識別子が本文にあります (HTTP ${s})` }; if (has(c.own_marker)) return { result: RESULTS.ok, reason: `自分のデータが返りました (他の主体の識別子を指定しても、HTTP ${s})` }; return { result: RESULTS.unclear, reason: `HTTP ${s} ですが、対象データの識別子を本文で確かめられませんでした` }; }
      return { result: RESULTS.suspect, reason: `拒否されるべき操作が使えました (HTTP ${s})` };
    }
    return { result: RESULTS.unclear, reason: `想定外の応答 (HTTP ${s})` };
  }
  if (s >= 200 && s < 300) { if (c.marker?.length && !has(c.marker)) return { result: RESULTS.unclear, reason: `HTTP ${s} ですが、期待したデータの識別子が本文にありません` }; return { result: RESULTS.ok, reason: `使えました (HTTP ${s})` }; }
  if (denied) return { result: RESULTS.unclear, reason: `使えるはずの操作が拒否されました (HTTP ${s})。資格情報の期限切れか、期待する権限の誤り` };
  return { result: RESULTS.unclear, reason: `想定外の応答 (HTTP ${s})` };
}
export const caseKey = (c) => `${c.operation_id}|${c.actor_id}|${c.owner_id}`;
// 前回の結果との比較 (AUTHZ-06): 前回は拒否 (想定どおり・期待 deny) だったものが、今回は認可不備の疑い
export function compareRuns(prev = [], cur = []) {
  const P = new Map((prev || []).map(c => [caseKey(c), c])); const regressions = [], fixed = [];
  for (const c of cur || []) { const p = P.get(caseKey(c)); if (!p) continue; if (p.expected === 'deny' && p.result === RESULTS.ok && c.result === RESULTS.suspect) regressions.push({ ...c, check: 'AUTHZ-06', previous_reason: p.reason }); if (p.result === RESULTS.suspect && c.result === RESULTS.ok) fixed.push(c); }
  return { regressions, fixed };
}
// 期待権限の表の差 (版の履歴に残す)
export function matrixDiff(a = {}, b = {}) {
  const out = []; const ops = new Set([...Object.keys(a || {}), ...Object.keys(b || {})]);
  for (const op of ops) { const A = a?.[op] || {}, B = b?.[op] || {}; for (const k of new Set([...Object.keys(A), ...Object.keys(B)])) if ((A[k] || 'unknown') !== (B[k] || 'unknown')) out.push({ operation_id: op, actor_id: k, from: A[k] || 'unknown', to: B[k] || 'unknown' }); }
  return out;
}
const HEADER_RE = /^[A-Za-z0-9-]{1,40}$/;
export const sq = (x) => `'${String(x).replace(/'/g, "'\\''")}'`;
// 使い捨てコンテナで動かす 1 リクエスト。host・port・IP は計画の時点で固定 (--resolve で DNS を引き直さない)、転送は追わない (--max-redirs 0 で -L なし)、
// 資格情報は環境変数から (argv・記録に出ない)。本文は上限まで読み、末尾に状態コードと content-type を添える
export function curlScript({ host, port, ip, method = 'GET', path, auth_env = null, header_name = 'Authorization', limits = LIMITS, ua = 'Mamoricho' }) {
  if (!HEADER_RE.test(header_name)) throw new HttpError(400, 'bad_header', 'ヘッダ名は英数字とハイフンだけです');
  if (!['GET', 'HEAD'].includes(method)) throw new HttpError(400, 'bad_method', 'この版で実行できるのは GET / HEAD だけです');
  if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/.test(path)) throw new HttpError(400, 'bad_path', 'パスに使えない文字があります');
  const scheme = Number(port) === 80 ? 'http' : 'https'; const url = `${scheme}://${host}:${port}${path}`;
  const hdr = auth_env ? ` -H "${header_name}: $${auth_env}"` : '';
  return `exec curl -sS${method === 'HEAD' ? ' -I' : ''} --max-redirs 0 --max-time ${limits.timeout_s} --max-filesize ${limits.max_body} --resolve ${sq(`${host}:${port}:${ip}`)} -A ${sq(ua + ' (authz)')}${hdr} -w '\\n<<mamoricho-meta>> %{http_code} %{content_type}' ${sq(url)}`;
}
// コンテナの出力 → { status, content_type, body }
export function parseCurlOutput(out, stderrMark = '--- エラー出力 ---') {
  const o = String(out || '').split(stderrMark)[0]; const mi = o.lastIndexOf('<<mamoricho-meta>>');
  if (mi < 0) return { status: 0, content_type: '', body: '', error: (String(out || '').split(stderrMark)[1] || String(out || '')).trim().slice(0, 200) || '応答なし' };
  const meta = o.slice(mi + '<<mamoricho-meta>>'.length).trim().split(/\s+/); return { status: Number(meta[0]) || 0, content_type: meta[1] || '', body: o.slice(0, mi) };
}
