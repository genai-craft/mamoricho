// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳の管理者監視 — ルール ADMIN-01〜10 と時系列の相関 (docs/MAMORICHO_DESIGN.md「管理者監視」)。
//   入力は admin-events.js の正規化したイベントと状態 (今回・前回)。判定は決まった規則だけ (AI は使わない。AI は後で説明する役)。
//   warn = 説明がつかなければ疑う / check = 正規の運用でも出るので確かめる。取れない材料のものは「問題なし」ではなく「確認できなかった」(unavailable)。
import { ACTION_JA, fmtEvent, stateDiff } from './admin-events.js';

export const ADMIN_RULES = [
  { id: 'ADMIN-01', level: 'warn', label: '前回より管理者 (と同じ権限のアカウント) が増えた', why: '攻撃者が自分用の管理者を作るのは乗っ取りの定番。自分で足した覚えがあるか確かめてください' },
  { id: 'ADMIN-02', level: 'warn', label: '新しい鍵・ログイン手段が足された', why: 'authorized_keys の鍵・sudo の決まり・公開 URL などの「入口」が増えています。心当たりが無ければ裏口のおそれ' },
  { id: 'ADMIN-03', level: 'check', label: '管理者が見慣れない住所 (IP) からログインした', why: '前回までの記録に無い接続元です。出張先や新しい回線なら問題ありません' },
  { id: 'ADMIN-04', level: 'check', label: '多要素認証の登録・削除・再設定', why: '本人の端末変更でも起きますが、乗っ取りの最初の一手でもあります。本人に確かめてください' },
  { id: 'ADMIN-05', level: 'warn', label: '多要素認証を変えた直後 (30 分以内) に重要な操作', why: '乗っ取った直後に、認証手段を自分のものに変えてから権限や鍵を足す手口の典型です' },
  { id: 'ADMIN-06', level: 'warn', label: '権限を上げた直後 (60 分以内) に新しいトークン・鍵', why: '権限を得てすぐ、長く使える入口 (API キー・鍵) を作るのは居座りの手口です' },
  { id: 'ADMIN-07', level: 'check', label: '短時間に続くログイン失敗', why: '総当たりや、盗んだパスワードの試行です。そのあとに成功があれば特に確かめてください' },
  { id: 'ADMIN-08', level: 'check', label: 'API キー・長期トークンの新規作成', why: '自動化で正規に作ることも多いですが、誰が何のために作ったかを確かめてください' },
  { id: 'ADMIN-09', level: 'warn', label: '管理者による大量のデータ取得', why: '持ち出しの典型です (この版では取得できる対象が限られます)' },
  { id: 'ADMIN-10', level: 'warn', label: '権限の変更・多要素認証の変更・トークン作成が連なった', why: '1 つずつは正規でも、短時間に連なるのは乗っ取り後の「居座り」の流れに似ています' },
];
const RULE = Object.fromEntries(ADMIN_RULES.map(r => [r.id, r]));
export const ADMIN_NOTE = '管理者の操作に対する機械的な目安です。warn は「侵害が確定」ではなく「説明がつかなければ疑う」、check は正規の運用でも出るので「本人に確かめる」です。取れない材料は「確認できなかった」と出します (= 問題なし ではありません)';
const IMPORTANT = new Set(['admin.user_added', 'admin.role_changed', 'privilege.escalation', 'token.created', 'auth.key_added', 'auth.method_added', 'auth.password_changed', 'auth.mfa_removed', 'auth.mfa_reset', 'account.created', 'auth.sessions_revoked']);
const MFA = new Set(['auth.mfa_enrolled', 'auth.mfa_removed', 'auth.mfa_reset']);
const PRIV = new Set(['privilege.escalation', 'admin.role_changed', 'admin.user_added']);
const TOKEN = new Set(['token.created', 'auth.key_added', 'auth.method_added']);
const KIND = (a) => (MFA.has(a) ? 'mfa' : PRIV.has(a) ? 'priv' : TOKEN.has(a) ? 'token' : a === 'account.created' ? 'account' : null);
const MIN = 60e3;
const sameWho = (a, b) => (a.actor?.id && a.actor.id === b.actor?.id) || (a.details?.subject && (a.details.subject === b.details?.subject || a.details.subject === b.actor?.id)) || (b.details?.subject && b.details.subject === a.actor?.id);
const who = (e) => e.actor?.id || e.details?.subject || '?';

// events: 正規化したイベント (時刻順でなくてよい)。since: この時刻以降が「今回」(前回の記録の時刻)。相関は 2 時間前まで文脈に入れるが、報告は今回に 1 つ以上あるものだけ
export function adminRules({ events = [], state = null, prevState = null, coverage = {}, since = null, now = Date.now() } = {}) {
  const signs = []; const unavailable = [];
  const add = (rid, lines, evidence, why = null, level = null) => { if (!lines.length) return; const r = RULE[rid]; signs.push({ level: level || r.level, rule_id: rid, label: r.label, why: why || r.why, lines: lines.slice(0, 20), count: lines.length, evidence_ids: [...new Set(evidence.filter(Boolean))].slice(0, 60), template_id: null }); };
  const na = (rid, reason) => unavailable.push({ rule_id: rid, label: RULE[rid].label, reason });
  const all = [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const sinceMs = since ? Date.parse(since) : now - 30 * 86400e3; const sinceIso = new Date(sinceMs).toISOString();
  const ctx = all.filter(e => Date.parse(e.timestamp) >= sinceMs - 120 * MIN && e.details?.detected_by !== 'diff'); const win = all.filter(e => e.timestamp >= sinceIso); // 差分で気づいたもの (時刻は検知時) は相関の文脈に入れない
  const inWin = (e) => e.timestamp >= sinceIso;
  const baseline = !prevState;
  // ADMIN-01 / 02: 状態の差分 (前回の記録が要る)
  if (!coverage.state) { na('ADMIN-01', '管理者の一覧 (getent / UID 0) が読めませんでした'); na('ADMIN-02', '鍵・sudo の一覧が読めませんでした (root の読み取りが無い対象では、root の鍵と sudoers は読めません)'); }
  else if (baseline) { /* 今回が基準 */ }
  else {
    const d = stateDiff(prevState, state);
    add('ADMIN-01', d.admins_added.map(u => `増えた: ${u}`), win.filter(e => e.action === 'admin.user_added').map(e => e.id));
    const added = [...d.keys_added.map(k => `鍵: ${k.file || ''} ${k.type} ${k.comment || '(注釈なし)'}`), ...d.sudoers_added.map(s => `sudo: ${s.slice(0, 100)}`), ...d.methods_added.map(m => `入口: ${m}`)];
    add('ADMIN-02', added, win.filter(e => ['auth.key_added', 'privilege.escalation', 'auth.method_added'].includes(e.action)).map(e => e.id));
  }
  // ADMIN-03: 管理者の、前回までに無い接続元
  if (!coverage.logins) na('ADMIN-03', 'ログインの記録 (last / 監査ログ) が読めませんでした');
  else if (!baseline) {
    const known = new Set(prevState?.ips || []); const seen = new Map();
    for (const e of win) if (e.action === 'auth.login_success' && e.actor?.role === 'administrator' && e.actor.ip && !known.has(e.actor.ip)) { const k = `${e.actor.id}@${e.actor.ip}`; if (!seen.has(k)) seen.set(k, e); }
    add('ADMIN-03', [...seen.values()].map(fmtEvent), [...seen.values()].map(e => e.id));
  }
  // ADMIN-04: 多要素認証の変更
  if (!coverage.mfa) na('ADMIN-04', 'この対象では多要素認証の記録を取れません (OS 自身・クラウドで評価します)');
  else { const m = win.filter(e => MFA.has(e.action)); add('ADMIN-04', m.map(fmtEvent), m.map(e => e.id)); }
  // ADMIN-05: 多要素認証の変更 → 30 分以内の重要な操作 (同じ人・同じ対象)
  const pairs05 = new Set(), pairs06 = new Set();
  if (coverage.mfa) {
    const lines = [], ev = [];
    // 同じ時刻 (ミリ秒まで同じ監査の行) もあり得るので dt は 0 を含める (x.id !== m.id で自分自身は除く)
    for (const m of ctx.filter(e => MFA.has(e.action))) for (const x of ctx) { const dt = Date.parse(x.timestamp) - Date.parse(m.timestamp); if (dt < 0 || dt > 30 * MIN || !IMPORTANT.has(x.action) || MFA.has(x.action) || x.id === m.id || !sameWho(m, x) || !(inWin(m) || inWin(x))) continue; lines.push(`${fmtEvent(m)} → ${fmtEvent(x)}`); ev.push(m.id, x.id); pairs05.add(`${m.id}|${x.id}`); }
    add('ADMIN-05', lines, ev);
  }
  // ADMIN-06: 権限の上昇 → 60 分以内のトークン・鍵・入口
  if (!coverage.tokens && !coverage.state) na('ADMIN-06', '権限とトークンの記録が読めませんでした');
  else { const lines = [], ev = []; for (const p of ctx.filter(e => PRIV.has(e.action))) for (const x of ctx) { const dt = Date.parse(x.timestamp) - Date.parse(p.timestamp); if (dt < 0 || dt > 60 * MIN || !TOKEN.has(x.action) || x.id === p.id || !sameWho(p, x) || !(inWin(p) || inWin(x))) continue; lines.push(`${fmtEvent(p)} → ${fmtEvent(x)}`); ev.push(p.id, x.id); pairs06.add(`${p.id}|${x.id}`); } add('ADMIN-06', lines, ev); }
  // ADMIN-07: 10 分以内に 5 回以上の失敗 (同じ接続元、または同じ名前)。そのあと 30 分以内に成功があれば warn
  if (!coverage.logins && !coverage.authlog) na('ADMIN-07', 'ログイン失敗の記録 (lastb / auth.log / 監査ログ) が読めませんでした');
  else {
    const fails = win.filter(e => e.action === 'auth.login_failed' || e.action === 'auth.login_locked'); const groups = new Map();
    for (const e of fails) for (const k of [e.actor?.ip ? `ip:${e.actor.ip}` : null, e.actor?.id ? `user:${e.actor.id}` : null].filter(Boolean)) { if (!groups.has(k)) groups.set(k, []); groups.get(k).push(e); }
    const lines = [], ev = []; let worst = 'check'; const done = new Set();
    for (const [k, list] of groups) {
      let i = 0; while (i < list.length) { let j = i; while (j + 1 < list.length && Date.parse(list[j + 1].timestamp) - Date.parse(list[i].timestamp) <= 10 * MIN) j++; const burst = list.slice(i, j + 1);
        if (burst.length >= 5) { const key = burst.map(e => e.id).join(','); if (!done.has(key)) { done.add(key); const users = [...new Set(burst.map(e => e.actor?.id).filter(Boolean))]; const ips = [...new Set(burst.map(e => e.actor?.ip).filter(Boolean))]; const end = Date.parse(burst.at(-1).timestamp);
          const succ = all.find(e => e.action === 'auth.login_success' && Date.parse(e.timestamp) > end && Date.parse(e.timestamp) - end <= 30 * MIN && ((e.actor?.ip && ips.includes(e.actor.ip)) || (e.actor?.id && users.includes(e.actor.id))));
          lines.push(`${burst[0].timestamp.slice(0, 16).replace('T', ' ')}〜${burst.at(-1).timestamp.slice(11, 16)} ${k.replace(/^ip:/, '接続元 ').replace(/^user:/, '名前 ')} で ${burst.length} 回失敗${users.length ? ` (${users.slice(0, 5).join(', ')})` : ''}${succ ? ` → その後 ${succ.timestamp.slice(11, 16)} に ${who(succ)}${succ.actor?.ip ? '@' + succ.actor.ip : ''} のログイン成功` : ''}`); ev.push(...burst.map(e => e.id)); if (succ) { ev.push(succ.id); worst = 'warn'; } } }
        i = j + 1; }
    }
    add('ADMIN-07', lines, ev, worst === 'warn' ? '失敗が続いたあとに成功しています。総当たりや盗んだパスワードで入られたおそれ。本人の操作か確かめてください' : null, worst);
  }
  // ADMIN-08: トークンの新規作成
  if (!coverage.tokens) na('ADMIN-08', 'この対象では API キー・トークンの記録を取れません (OS 自身・クラウドで評価します)');
  else { const t = win.filter(e => e.action === 'token.created'); add('ADMIN-08', t.map(fmtEvent), t.map(e => e.id)); }
  // ADMIN-09: 大量のデータ取得
  if (!coverage.bulk) na('ADMIN-09', 'この版では大量のデータ取得の記録を取れません (取得できる対象が増えたら評価します)');
  else { const b = win.filter(e => e.action === 'data.bulk_export'); add('ADMIN-09', b.map(fmtEvent), b.map(e => e.id)); }
  // ADMIN-10: 2 時間以内に、権限・多要素認証・トークン・アカウント作成のうち 2 種類以上 (05/06 で出した組み合わせだけのものは除く)
  {
    const lines = [], ev = []; const seen = new Set();
    const kinded = ctx.filter(e => KIND(e.action)).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    for (let i = 0; i < kinded.length; i++) {
      const chain = [kinded[i]]; for (let j = i + 1; j < kinded.length; j++) { if (Date.parse(kinded[j].timestamp) - Date.parse(kinded[i].timestamp) > 120 * MIN) break; if (chain.some(c => sameWho(c, kinded[j]))) chain.push(kinded[j]); }
      const kinds = new Set(chain.map(e => KIND(e.action))); if (kinds.size < 2 || !chain.some(inWin)) continue;
      const key = chain.map(e => e.id).join(','); if (seen.has(key) || [...seen].some(k => k.includes(key))) continue;
      if (chain.length === 2 && (pairs05.has(`${chain[0].id}|${chain[1].id}`) || pairs06.has(`${chain[0].id}|${chain[1].id}`))) continue;
      seen.add(key); lines.push(chain.map(fmtEvent).join(' → ')); ev.push(...chain.map(e => e.id));
    }
    add('ADMIN-10', lines, ev);
  }
  signs.sort((a, b) => (a.level === b.level ? 0 : a.level === 'warn' ? -1 : 1));
  return { title: '管理者アカウントの乗っ取りの兆候', note: ADMIN_NOTE, baseline, since: sinceIso, signs, unavailable, warn: signs.filter(x => x.level === 'warn').length, check: signs.filter(x => x.level === 'check').length, events_in_window: win.length, action_ja: ACTION_JA };
}
