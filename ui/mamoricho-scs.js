// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳の画面 (続き): SCS 評価制度の点検・改善計画書・確認と宣誓・会社の情報・規程 (作成補助とレビュー)・台帳・全員に知らせる・お知らせの確認。
//   ui/mamoricho.js の後に読み、AIOS.mamorichoExt.routes をまもり帳のメニューに足す。AIOS.mamorichoAck は、箱の通知 (mamoricho-ack:…) から開く確認の画面
(() => {
const { el, GET, POST, PUT, DEL, toast, modal, confirmDialog, fmtTime } = AIOS;
const role = () => AIOS.state.me?.role; const isOp = () => ['owner', 'admin', 'operator'].includes(role()); const isAdmin = () => ['owner', 'admin'].includes(role());
const CARD = { padding: '14px 16px', border: '1px solid var(--line, #e5e7eb)', borderRadius: '12px', background: 'var(--card, #fff)', marginBottom: '12px' };
const ST = { ok: ['できている', '#16a34a'], partial: ['一部できている', '#d97706'], no: ['できていない', '#dc2626'], unknown: ['分からない', '#6b7280'], na: ['対象外', '#94a3b8'], unanswered: ['未回答', '#cbd5e1'] };
const dot = (s) => el('span', { style: { display: 'inline-block', width: '10px', height: '10px', borderRadius: '50%', background: (ST[s] || ST.unanswered)[1], marginRight: '6px', verticalAlign: '-1px' } });
const pill = (s) => el('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', padding: '2px 8px', borderRadius: '999px', background: 'rgba(15,23,42,.06)', whiteSpace: 'nowrap' } }, dot(s), (ST[s] || ST.unanswered)[0]);
const tag = (t, color = '#475569', bg = 'rgba(15,23,42,.06)') => el('span', { style: { fontSize: '11px', fontWeight: 700, color, background: bg, borderRadius: '6px', padding: '1px 6px', whiteSpace: 'nowrap' } }, t);
const star = (lv) => tag(`★${lv}`, lv === 3 ? '#047857' : '#4338ca', lv === 3 ? '#d1fae5' : '#e0e7ff');
const bar = (pct, color = '#16a34a') => el('div', { style: { height: '10px', borderRadius: '999px', background: 'rgba(15,23,42,.08)', overflow: 'hidden' } }, el('div', { style: { width: `${Math.max(0, Math.min(100, pct))}%`, height: '100%', background: color } }));
const sub = (t, extra = {}) => el('div', { class: 'sub', style: { margin: '2px 0 0', fontSize: '12px', ...extra } }, t);
const day = (iso) => (iso ? new Date(iso).toLocaleDateString('ja-JP') : '-');
const closeModal = () => document.getElementById('modal')?.classList.add('hidden');
// 広い窓 (規程の編集・本文の表示)。modal の窓の幅は OS と単体版で決まっているので、開いたあとで広げる
const wide = (content, w = 980) => { const m = modal(content); if (m?.dialog) m.dialog.style.width = `min(${w}px, 96vw)`; return m; };
// ダウンロード (CSV・Word・Markdown)。cookie で認証された同じ origin の API を blob で受ける
async function download(path, fallbackName) {
  try { const r = await fetch('/api/v1' + path, { credentials: 'same-origin' }); if (!r.ok) { let m = `HTTP ${r.status}`; try { m = (await r.json()).error?.message || m; } catch { /* 文字でない */ } throw new Error(m); }
    const cd = r.headers.get('content-disposition') || ''; const name = decodeURIComponent((/filename\*=UTF-8''([^;]+)/.exec(cd) || [])[1] || '') || fallbackName;
    const a = document.createElement('a'); a.href = URL.createObjectURL(await r.blob()); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  } catch (e) { toast(e.message, 'err'); }
}
// 規程の本文 (Markdown の小さな部分: 見出し・箇条書き・表・太字) を画面に
function md(text) {
  const box = el('div', { class: 'mm-md', style: { fontSize: '14px', lineHeight: 1.75 } }); const lines = String(text || '').split('\n');
  const inline = (s) => String(s).split(/(\*\*[^*]+\*\*|【要記入[^】]*】)/).filter(Boolean).map(x => x.startsWith('**') ? el('b', {}, x.slice(2, -2)) : x.startsWith('【要記入') ? el('mark', { style: { background: '#fef3c7', padding: '0 2px' } }, x) : x);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/^\s*\|/.test(l)) { const rows = []; while (i < lines.length && /^\s*\|/.test(lines[i])) { const r = lines[i].trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim()); if (!r.every(c => /^:?-{2,}:?$/.test(c))) rows.push(r); i++; } i--; const t = el('table', { class: 'tbl', style: { margin: '6px 0' } }); rows.forEach((r, k) => t.append(el('tr', {}, ...r.map(c => el(k ? 'td' : 'th', {}, ...inline(c)))))); box.append(el('div', { style: { overflow: 'auto' } }, t)); continue; }
    const h = /^(#{1,3})\s+(.*)$/.exec(l); if (h) { box.append(el(h[1].length === 1 ? 'h2' : 'h3', { style: { margin: '12px 0 4px' } }, ...inline(h[2]))); continue; }
    if (!l.trim()) continue; box.append(el('p', { style: { margin: '4px 0', paddingLeft: /^\s*(-|\d+\.)\s/.test(l) ? '12px' : 0 } }, ...inline(l)));
  }
  return box;
}
const SRC = (s) => sub(`出典: 「${s.title}」(${s.publisher}) ${s.url} (${s.used_at}に利用・${s.license})。評価基準は原文のまま。ふつうの言葉の質問と手がかりは生成AI工房が作成したもので、国の公式の文言ではありません。`, { marginTop: '10px' });

// ---------- SCS 評価制度の点検 ----------
const KIND_COLOR = { rule: '#2563eb', notice: '#7c3aed', yearly: '#0891b2', monthly: '#0891b2', record: '#0d9488', ledger: '#0d9488', do: '#475569', tool: '#b45309', physical: '#475569' };
async function renderScs(c, p, win) {
  let s; try { s = await GET('/mamoricho/scs/summary'); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  let level = Number(p?.level) || s.target_level || 3;
  c.append(el('h1', {}, 'SCS 評価制度 (★3・★4) の準備'), el('p', { class: 'sub' }, '取引先に「セキュリティの対策の状況」を聞かれたときに、すぐ出せる記録を作ります。経済産業省の「サプライチェーン強化に向けたセキュリティ対策評価制度」の評価基準に沿って、1 項目ずつ確かめ、根拠と日付を残します。'));
  c.append(el('div', { class: 'notice info', style: { fontSize: '13px' } }, s.note, ' ', el('span', {}, '制度の申請の受付は 2026 年度末ごろ (予定) からです。くわしい評価のやり方と様式は IPA から公表されます。')));
  const top = el('div', { style: CARD }); c.append(top);
  const L = level === 4 ? s.level4 : s.level3; const color = L.score >= 80 ? '#16a34a' : L.score >= 50 ? '#d97706' : '#dc2626';
  top.append(el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', alignItems: 'center' } }, ...[3, 4].map(lv => el('button', { class: 'btn sm' + (lv === level ? ' primary' : ''), onclick: () => win.navigate('scs', { level: lv }) }, `★${lv} (${lv === 3 ? '81' : '153'} 項目)`)), el('span', { class: 'sub', style: { margin: '0 0 0 auto', fontSize: '12px' } }, `目標: ★${s.target_level}`)),
    el('div', { class: 'row', style: { alignItems: 'baseline', gap: '12px', margin: '10px 0 6px', flexWrap: 'wrap' } }, el('span', { style: { fontSize: '34px', fontWeight: 800, color } }, L.answered ? `${L.score}` : '—'), el('span', { class: 'sub', style: { margin: 0 } }, L.answered ? '点 (できている=1、一部=0.5。目安)' : 'まだ答えていません'), el('span', { style: { marginLeft: 'auto' } }, `${L.answered} / ${L.total} 項目に回答`)),
    bar(L.score, color), el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', marginTop: '8px' } }, ...['ok', 'partial', 'no', 'unknown', 'na', 'unanswered'].map(k => el('span', {}, pill(k), ` ${L.counts[k]}`))),
    el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', marginTop: '12px' } }, el('button', { class: 'btn', onclick: () => win.navigate('scsplan', { level }) }, '📝 改善計画書'), el('button', { class: 'btn', onclick: () => win.navigate('scsreview') }, `🖋 確認と宣誓${s.review ? ` (${REVIEW_STATE[s.review.state]?.[0] || s.review.state})` : ''}`), el('button', { class: 'btn', onclick: () => win.navigate('rules') }, '📘 規程'), el('button', { class: 'btn', onclick: () => win.navigate('ledgers') }, '🗂 台帳'), el('button', { class: 'btn', onclick: () => win.navigate('notices') }, '📣 全員に知らせる'), el('button', { class: 'btn', onclick: () => win.navigate('scsprofile') }, '🏢 会社の情報')));
  if (!s.profile_ready) c.append(el('div', { class: 'notice warn' }, '会社の情報 (会社名・統括する役員・担当部署) がまだです。規程のひな形と控えに使います。', el('button', { class: 'btn sm', style: { marginLeft: '8px' }, onclick: () => win.navigate('scsprofile') }, '入れる')));
  for (const a of s.acquired) c.append(el('div', { class: 'notice ' + (a.days_left < 30 ? 'warn' : 'ok') }, `★${a.level} 取得 ${a.at}・有効期限 ${a.expires_at} (残り ${a.days_left} 日)。${a.level === 3 ? '更新には、年次の自己評価と専門家の確認が要ります。' : '有効期間の間は毎年の自己評価が要ります。'}`));
  const alerts = el('div', { class: 'grid', style: { gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', marginBottom: '12px' } });
  if (s.due.length) alerts.append(el('div', { style: { ...CARD, marginBottom: 0, borderColor: '#0891b2' } }, el('b', {}, `🔁 定期の点検 (${s.due.length} 件)`), sub('年 1 回 (一部は月 1 回) 点検する項目です。点検したら「点検した」で日付を残します。'), el('ul', { style: { margin: '6px 0 0 18px', fontSize: '13px' } }, ...s.due.slice(0, 5).map(x => el('li', {}, el('a', { href: '#', onclick: (e) => { e.preventDefault(); focus(x.id); } }, x.id), ` ${x.q.slice(0, 40)}… `, x.never ? tag('まだ記録なし') : tag(`期限 ${x.next_at}`, '#dc2626'))))));
  if (s.plans.length) alerts.append(el('div', { style: { ...CARD, marginBottom: 0 } }, el('b', {}, `📝 改善の計画 (${s.plans.length} 件)`), el('ul', { style: { margin: '6px 0 0 18px', fontSize: '13px' } }, ...s.plans.slice(0, 5).map(x => el('li', { style: { color: x.overdue ? '#dc2626' : undefined } }, `${x.due} ${x.owner || ''}: ${x.action || x.q}`.slice(0, 80))))));
  if (s.tools.length) alerts.append(el('div', { style: { ...CARD, marginBottom: 0, borderColor: '#f59e0b' } }, el('b', {}, `🧰 道具が要る項目 (${s.tools.length} 件)`), sub('外からの侵入をその場で見つけて止める仕組み (UTM・EDR) やウイルス対策は、まもり帳では満たせません。お助け隊サービスなどの監視サービスで満たせることがあります。入れたものは台帳「セキュリティの道具」に書きます。'), el('div', { style: { marginTop: '6px' } }, el('button', { class: 'btn sm', onclick: () => win.navigate('ledgers', { kind: 'tools' }) }, '台帳「セキュリティの道具」'))));
  if (alerts.childNodes.length) c.append(alerts);
  // 一覧
  let d; try { d = await GET(`/mamoricho/scs/criteria?level=${level}`); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  const filt = { cat: p?.cat || null, kind: p?.kind || null, status: p?.status || null };
  const chips = el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', marginBottom: '8px' } }); const chips2 = el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', marginBottom: '12px' } }); const list = el('div'); c.append(chips, chips2, list, SRC(d.source));
  function focus(cid) { const it = d.items.find(x => x.id === cid); if (!it) return; filt.cat = it.cat_no; filt.kind = null; filt.status = null; draw(); setTimeout(() => document.getElementById('scs-' + cid)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 60); }
  const draw = () => {
    chips.innerHTML = ''; chips2.innerHTML = '';
    chips.append(el('button', { class: 'btn sm' + (!filt.cat ? ' primary' : ''), onclick: () => { filt.cat = null; draw(); } }, `すべて ${d.items.filter(i => i.answer).length}/${d.items.length}`));
    for (const k of d.categories) { const its = d.items.filter(i => i.cat_no === k.no); if (!its.length) continue; chips.append(el('button', { class: 'btn sm' + (filt.cat === k.no ? ' primary' : ''), onclick: () => { filt.cat = k.no; draw(); } }, `${k.no}. ${k.label} ${its.filter(i => i.answer).length}/${its.length}`)); }
    const kinds = [['', 'どの型も'], ...Object.entries(d.kinds)]; const sts = [['', 'どの状態も'], ['unanswered', '未回答'], ['notok', 'できていない・一部・分からない'], ['ok', 'できている']];
    chips2.append(el('select', { class: 'inp', style: { width: 'auto' }, onchange: (e) => { filt.kind = e.target.value || null; draw(); } }, ...kinds.map(([v, l]) => el('option', { value: v, selected: (filt.kind || '') === v }, l))), el('select', { class: 'inp', style: { width: 'auto' }, onchange: (e) => { filt.status = e.target.value || null; draw(); } }, ...sts.map(([v, l]) => el('option', { value: v, selected: (filt.status || '') === v }, l))));
    list.innerHTML = '';
    const its = d.items.filter(i => (!filt.cat || i.cat_no === filt.cat) && (!filt.kind || i.guide.k === filt.kind) && (!filt.status || (filt.status === 'unanswered' ? !i.answer : filt.status === 'ok' ? i.answer?.status === 'ok' : i.answer && ['no', 'partial', 'unknown'].includes(i.answer.status))));
    let lastReq = null;
    for (const it of its) { if (it.req !== lastReq) { lastReq = it.req; list.append(el('div', { style: { margin: '14px 0 6px', fontWeight: 700 } }, `${it.req} ${it.req_name} `, star(it.req_in3 ? 3 : 4), sub(it.req_text))); } list.append(criterionCard(it, d, win)); }
    if (!its.length) list.append(el('div', { class: 'notice info' }, 'この絞り込みに当てはまる項目はありません。'));
  };
  draw();
}
function evidenceLine(it, win) {
  const e = it.evidence || {}; const out = el('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '6px', margin: '6px 0' } });
  const chip = (label, color, onclick, title = '') => out.append(el(onclick ? 'button' : 'span', { class: onclick ? 'btn sm' : '', title, onclick, style: { fontSize: '12px', padding: '2px 8px', borderRadius: '999px', border: `1px solid ${color}`, color, background: 'transparent', cursor: onclick ? 'pointer' : 'default' } }, label));
  for (const x of e.self || []) chip(`${x.ok ? '✓' : '✗'} ${AIOS_B().os}: ${x.label}`, x.ok ? '#16a34a' : '#dc2626', null, x.detail);
  for (const f of (e.facts || []).slice(0, 6)) chip(`${f.level === 'ok' ? '✓' : f.level === 'warn' ? '⚠' : f.level === 'check' ? '👀' : '・'} ${f.label}`, f.level === 'ok' ? '#16a34a' : f.level === 'warn' ? '#dc2626' : f.level === 'check' ? '#d97706' : '#475569', null, f.detail);
  if (e.ledger) chip(`🗂 台帳「${e.ledger.label}」${e.ledger.rows ? `${e.ledger.rows} 行` : 'まだ空'}${e.ledger.reviewed_at ? ` ・見直し ${day(e.ledger.reviewed_at)}` : ''}`, e.ledger.rows ? '#0d9488' : '#94a3b8', () => win.navigate('ledgers', { kind: e.ledger.kind }));
  if (e.policy) chip(`📘 規程「${e.policy.title}」${e.policy.adopted_version ? `第${e.policy.adopted_version}版 (${day(e.policy.adopted_at)})` : 'まだ無い → 作る'}`, e.policy.adopted_version ? '#2563eb' : '#94a3b8', () => win.navigate('rules', { template: e.policy.template_id }));
  if (e.notice) chip(`📣 「${e.notice.title}」確認 ${e.notice.acks}/${e.notice.audience}`, e.notice.acks >= e.notice.audience ? '#16a34a' : '#7c3aed', () => win.navigate('notices', { id: e.notice.id }));
  else if (it.guide.k === 'notice') chip('📣 全員に知らせる', '#94a3b8', () => win.navigate('notices', { criteria: it.id }));
  for (const x of e.ppc || []) chip(`☑ 近い点検: ${x.q.slice(0, 24)}… ${x.status ? ST[x.status][0] : '未回答'}`, x.status === 'ok' ? '#16a34a' : '#94a3b8', () => win.navigate('check', { item: x.id }));
  if (e.audit) chip(`📜 ${e.audit.label}`, e.audit.kind === 'idle' && e.audit.idle?.length ? '#d97706' : '#475569', () => auditDialog(e.audit));
  if (e.vuln) chip(`🧯 脆弱性情報 ${e.vuln.version || 'なし'}: 対象に関係しそう ${e.vuln.related} 件${e.vuln.exploited ? ` (悪用あり ${e.vuln.exploited})` : ''}`, e.vuln.exploited ? '#dc2626' : '#475569', () => vulnDialog(e.vuln));
  if (e.admin) chip(`🔑 管理者の点検 ${e.admin.last_at ? day(e.admin.last_at) : 'まだ'}${e.admin.warn ? ` 疑い ${e.admin.warn}` : ''}`, e.admin.warn ? '#dc2626' : e.admin.last_at ? '#16a34a' : '#94a3b8', () => win.navigate('admin', { target: 'self' }));
  if (e.emergency) chip(`🚨 もしものときの連絡先 ${e.emergency.filled}/${e.emergency.of}`, e.emergency.filled >= 3 ? '#16a34a' : '#94a3b8', () => win.navigate('emergency'));
  return out.childNodes.length ? out : '';
}
const AIOS_B = () => AIOS.mamorichoBrand || { os: '言箱', product: 'まもり帳' };
function auditDialog(a) {
  const c = el('div', {}, el('h2', {}, a.label));
  if (a.kind === 'users') { const t = el('table', { class: 'tbl' }, el('tr', {}, el('th', {}, '日時'), el('th', {}, '操作'), el('th', {}, '誰が'), el('th', {}, '対象'))); for (const r of a.recent || []) t.append(el('tr', {}, el('td', {}, fmtTime(r.at)), el('td', {}, r.action), el('td', {}, r.by || ''), el('td', {}, String(r.detail?.username || r.target || '')))); c.append(sub('箱の監査ログ (改ざんを検知できる記録) から。申請と承認そのものは、台帳「管理者 ID」の「付与の承認」や申請の記録で残してください。'), t); }
  else { const t = el('table', { class: 'tbl' }, el('tr', {}, el('th', {}, 'ID'), el('th', {}, '名前'), el('th', {}, '役割'), el('th', {}, '最後のログイン'))); for (const u of a.idle || []) t.append(el('tr', {}, el('td', {}, u.username), el('td', {}, u.name), el('td', {}, u.role), el('td', {}, u.last_login ? day(u.last_login) : '記録なし'))); c.append(sub('監査ログで 90 日ログインしていない ID です。要らなければ止めてください (System の利用者)。'), t); }
  wide(c, 820);
}
function vulnDialog(v) {
  const t = el('table', { class: 'tbl' }, el('tr', {}, el('th', {}, ''), el('th', {}, '内容'), el('th', {}, '関係しそうな対象'), el('th', {}, '日付')));
  for (const x of v.items || []) t.append(el('tr', {}, el('td', {}, x.exploited ? '⚠' : ''), el('td', {}, `${x.id} ${x.title}`), el('td', {}, (x.targets || []).join(', ')), el('td', {}, x.date || '')));
  wide(el('div', {}, el('h2', {}, '脆弱性情報との突き合わせ'), sub(`${v.source || ''}・版 ${v.version || '-'}${v.age_days != null ? ` (${v.age_days} 日前)` : ''}。製品名の言葉で突き合わせた目安です。対応したら台帳「脆弱性への対応」に記録します。`), (v.items || []).length ? t : el('p', {}, '関係しそうなものはありません。')), 820);
}
function criterionCard(it, d, win) {
  const a = it.answer; const g = it.guide; const card = el('div', { id: 'scs-' + it.id, style: { ...CARD, borderLeft: `4px solid ${KIND_COLOR[g.k] || '#94a3b8'}` } });
  const head = el('div', { class: 'row', style: { alignItems: 'flex-start', gap: '10px' } }, el('div', { style: { flex: 1 } }, el('div', { class: 'row', style: { gap: '6px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '4px' } }, el('code', { style: { fontSize: '12px' } }, it.id), star(it.level), tag(g.kind_label, KIND_COLOR[g.k]), it.tool ? tag('まもり帳では満たせない (道具が要る)', '#b45309', '#fef3c7') : ''), el('div', { style: { fontWeight: 700, fontSize: '15px' } }, g.q)), pill(a?.status || 'unanswered'));
  const orig = el('details', { style: { margin: '6px 0', fontSize: '13px' } }, el('summary', { style: { cursor: 'pointer', color: '#475569' } }, '評価基準 (原文)'), el('div', { style: { whiteSpace: 'pre-wrap', padding: '6px 10px', background: 'rgba(15,23,42,.045)', borderRadius: '8px', marginTop: '4px' } }, it.text));
  const note = el('input', { class: 'inp', value: a?.note || '', placeholder: '記録に残す一言・根拠 (例: 規程「基本方針」第 2 版を 2026-10 に周知、確認 15/15)', style: { width: '100%' }, disabled: !isOp() });
  const plan = a?.plan || {}; const pAct = el('input', { class: 'inp', value: plan.action || '', placeholder: 'やること', style: { flex: 2, minWidth: '160px' } }), pOwn = el('input', { class: 'inp', value: plan.owner || '', placeholder: '担当', style: { flex: 1, minWidth: '80px' } }), pDue = el('input', { class: 'inp', type: 'date', value: plan.due || '', style: { width: 'auto' } });
  const save = async (status) => { try { const r = await POST('/mamoricho/scs/answer', { id: it.id, status, note: note.value, plan: { action: pAct.value.trim(), owner: pOwn.value.trim(), due: pDue.value } }); it.answer = { ...(it.answer || {}), status: r.status, note: r.note, plan: r.plan, updated_at: r.updated_at }; toast('記録しました', 'ok'); card.replaceWith(criterionCard(it, d, win)); } catch (e) { toast(e.message, 'err'); } };
  const btns = el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', margin: '6px 0' } }, ...['ok', 'partial', 'no', 'unknown', 'na'].map(s => el('button', { class: 'btn sm' + (a?.status === s ? ' primary' : ''), disabled: !isOp(), onclick: () => save(s) }, dot(s), ST[s][0])));
  const planBox = el('details', { open: !!(a && ['no', 'partial', 'unknown'].includes(a.status) && !plan.action), style: { margin: '4px 0' } }, el('summary', { style: { cursor: 'pointer', fontSize: '13px' } }, plan.action ? `改善の計画: ${plan.action} (${plan.owner || '担当未定'} ${plan.due || ''})` : '改善の計画 (何を・誰が・いつまでに)'), el('div', { class: 'row', style: { gap: '6px', marginTop: '6px', flexWrap: 'wrap' } }, pAct, pOwn, pDue, isOp() ? el('button', { class: 'btn sm', onclick: () => save(a?.status || 'no') }, '計画を保存') : ''));
  const due = it.due ? el('div', { class: 'row', style: { gap: '8px', alignItems: 'center', flexWrap: 'wrap', fontSize: '13px', margin: '6px 0', padding: '6px 10px', background: it.due.overdue ? '#fef2f2' : '#ecfeff', borderRadius: '8px' } }, el('span', {}, `🔁 ${it.due.cycle === 'monthly' ? '月' : '年'} 1 回の点検: `, it.due.last_done_at ? `前回 ${it.due.last_done_at}・次 ${it.due.next_at}` : 'まだ記録がありません'), it.due.overdue ? tag(it.due.never ? '未実施' : '期限切れ', '#dc2626', '#fee2e2') : tag('期限内', '#0e7490', '#cffafe'), isOp() ? (() => { const dt = el('input', { class: 'inp', type: 'date', value: new Date().toISOString().slice(0, 10), style: { width: 'auto' } }); return el('span', { class: 'row', style: { gap: '6px', alignItems: 'center' } }, dt, el('button', { class: 'btn sm primary', onclick: async () => { try { const r = await POST('/mamoricho/scs/done', { id: it.id, at: dt.value, note: note.value }); it.answer = { ...(it.answer || { status: 'unknown' }), last_done_at: r.last_done_at }; it.due = { ...it.due, last_done_at: r.last_done_at, next_at: new Date(Date.parse(r.last_done_at) + it.due.days * 86400e3).toISOString().slice(0, 10), overdue: false, never: false }; toast('点検の日付を残しました', 'ok'); card.replaceWith(criterionCard(it, d, win)); } catch (e) { toast(e.message, 'err'); } } }, '点検した')); })() : '') : '';
  const hints = []; if (g.k === 'tool') hints.push('UTM・EDR・ウイルス対策などの道具が要る項目です。入れているものを台帳「セキュリティの道具」に書き、状態を選んでください (お助け隊サービスなどの監視サービスで満たせることがあります)。');
  card.append(head, orig, evidenceLine(it, win), due, btns, note, planBox, hints.length ? el('div', { class: 'notice warn', style: { fontSize: '12px', marginTop: '6px' } }, hints.join(' ')) : '', a?.updated_at ? sub(`最終更新 ${fmtTime(a.updated_at)}`) : '');
  note.addEventListener('change', () => { if (it.answer?.status) save(it.answer.status); });
  return card;
}

// ---------- 改善計画書 ----------
async function renderPlan(c, p, win) {
  const level = Number(p?.level) || 3; let d; try { d = await GET(`/mamoricho/scs/plan?level=${level}`); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  c.append(el('h1', {}, `改善計画書 (★${level})`), el('p', { class: 'sub' }, `できていない・一部・分からない・未回答の ${d.open} 項目 (全 ${d.total} 項目のうち) と、何を・誰が・いつまでにやるか。点検の画面で計画を入れると、ここに並びます。`),
    el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', marginBottom: '10px' } }, ...[3, 4].map(lv => el('button', { class: 'btn sm' + (lv === level ? ' primary' : ''), onclick: () => win.navigate('scsplan', { level: lv }) }, `★${lv}`)), el('button', { class: 'btn', onclick: () => download(`/mamoricho/scs/plan.csv?level=${level}`, `SCS-star${level}-改善計画書.csv`) }, '⬇ CSV で書き出す (Excel)'), el('button', { class: 'btn', onclick: () => printPlan(d) }, '🖨 印刷する'), el('button', { class: 'btn', onclick: () => win.navigate('scs', { level }) }, '点検に戻る')));
  const t = el('table', { class: 'tbl' }, el('tr', {}, el('th', {}, '番号'), el('th', {}, '要求事項'), el('th', {}, 'いまの状態'), el('th', {}, 'やること'), el('th', {}, '担当'), el('th', {}, '期限'), el('th', {}, 'まもり帳でできること')));
  for (const r of d.rows) t.append(el('tr', {}, el('td', {}, el('a', { href: '#', onclick: (e) => { e.preventDefault(); win.navigate('scs', { level, cat: Number(r.id.split('-')[0]) }); } }, r.id), ' ', star(r.level)), el('td', {}, el('div', { style: { fontWeight: 600 } }, r.req_name), sub(r.q)), el('td', {}, pill(r.status)), el('td', {}, r.action || el('span', { class: 'sub' }, '(未定)')), el('td', {}, r.owner), el('td', { style: { color: r.due && Date.parse(r.due) < Date.now() ? '#dc2626' : undefined } }, r.due), el('td', { style: { fontSize: '12px' } }, el('ul', { style: { margin: 0, paddingLeft: '16px' } }, ...r.helps.map(h => el('li', {}, h))))));
  c.append(el('div', { style: { overflow: 'auto' } }, t), SRC(d.source));
}
function printPlan(d) {
  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
  const w = window.open('', '_blank'); if (!w) return toast('印刷の窓を開けませんでした (ポップアップを許可してください)', 'err');
  w.document.write(`<!doctype html><meta charset="utf-8"><title>改善計画書 ★${d.level}</title><style>body{font-family:sans-serif;font-size:11pt;margin:16mm}table{border-collapse:collapse;width:100%}th,td{border:1px solid #888;padding:4px 6px;vertical-align:top;font-size:9.5pt}th{background:#eef2f7}h1{font-size:15pt}.s{color:#555;font-size:8.5pt}</style><h1>SCS 評価制度 ★${d.level} 改善計画書</h1><p>${esc(d.profile.company || '')}　作成 ${new Date().toLocaleDateString('ja-JP')}　対象 ${d.open} / ${d.total} 項目</p><table><tr><th>番号</th><th>要求事項・質問</th><th>状態</th><th>やること</th><th>担当</th><th>期限</th></tr>${d.rows.map(r => `<tr><td>${esc(r.id)}</td><td><b>${esc(r.req_name)}</b><br><span class="s">${esc(r.q)}</span></td><td>${esc((ST[r.status] || ST.unanswered)[0])}</td><td>${esc(r.action)}</td><td>${esc(r.owner)}</td><td>${esc(r.due)}</td></tr>`).join('')}</table><p class="s">出典: 「${esc(d.source.title)}」(${esc(d.source.publisher)}) ${esc(d.source.url)} をもとに作成。質問は生成AI工房による言い換えです。</p>`);
  w.document.close(); setTimeout(() => w.print(), 300);
}

// ---------- 確認と宣誓 ----------
const REVIEW_STATE = { requested: ['確認待ち', '#d97706'], returned: ['差し戻し', '#dc2626'], confirmed: ['専門家が確認 (宣誓待ち)', '#2563eb'], declared: ['宣誓済み', '#16a34a'], withdrawn: ['取り下げ', '#94a3b8'], superseded: ['出し直し済み', '#94a3b8'] };
async function renderReview(c, p, win) {
  let d; try { d = await GET('/mamoricho/scs/reviews'); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  c.append(el('h1', {}, '確認と宣誓 (★3 の自己評価)'), el('p', { class: 'sub' }, '★3 は「セキュリティ専門家の確認を経た自己評価」です。いまの答えの写しを固め、専門家 (情報処理安全確保支援士・公認情報セキュリティ監査人・CISSP など、制度の研修を受けた人) が項目ごとに助言して確認し、経営層が宣誓します。すべて署名つきの記録に残ります。IPA への提出の様式ではありません (様式は制度の開始までに公表される予定)。'));
  c.append(el('div', { class: 'grid', style: { gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px', marginBottom: '12px' } }, ...[['1', '写しを固める', '管理者が「確認を依頼する」を押すと、その時点の答え・根拠・計画を固め、ハッシュを残します'], ['2', '専門家が確認', '専門家は項目ごとに助言し、「確認する」(署名) か「差し戻す」を選びます'], ['3', '経営層が宣誓', '経営層 (または Owner) が、内容が事実に基づくことを宣誓します']].map(([n, h, b]) => el('div', { style: { ...CARD, marginBottom: 0 } }, el('div', { style: { fontWeight: 800 } }, `${n}. ${h}`), sub(b)))));
  const ex = d.experts || []; c.append(el('div', { class: 'notice ' + (ex.length ? 'info' : 'warn') }, ex.length ? `登録した専門家: ${ex.map(e => `${e.name} (${e.qualification}${e.reg_no ? ` ${e.reg_no}` : ''})`).join('、')}` : '専門家がまだ登録されていません。会社の情報で、専門家の利用者 (この箱のアカウント) と資格を登録してください。', el('button', { class: 'btn sm', style: { marginLeft: '8px' }, onclick: () => win.navigate('scsprofile') }, '会社の情報')));
  if (isAdmin()) c.append(el('div', { class: 'row', style: { gap: '8px', marginBottom: '12px' } }, ...[3, 4].map(lv => el('button', { class: 'btn' + (lv === 3 ? ' primary' : ''), onclick: async () => { const s = await GET('/mamoricho/scs/summary'); const L = lv === 4 ? s.level4 : s.level3; const ok = await confirmDialog({ title: `★${lv} の自己評価の確認を依頼しますか`, body: `いまの答え (${L.answered} / ${L.total} 項目に回答${L.counts.unanswered ? `・未回答 ${L.counts.unanswered}` : ''}) の写しを固めて、専門家に知らせます。`, okLabel: '依頼する' }); if (!ok) return; try { const r = await POST('/mamoricho/scs/reviews', { level: lv }); toast('依頼しました', 'ok'); win.navigate('scsreview', { id: r.review_id }); } catch (e) { toast(e.message, 'err'); } } }, `★${lv} の確認を依頼する`))));
  const list = el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, '依頼の一覧'));
  if (!d.reviews.length) list.append(sub('まだ依頼はありません。'));
  for (const r of d.reviews) { const st = REVIEW_STATE[r.state] || [r.state, '#475569']; list.append(el('div', { class: 'row', style: { gap: '10px', alignItems: 'center', padding: '6px 0', borderTop: '1px solid var(--line, #eee)', cursor: 'pointer' }, onclick: () => win.navigate('scsreview', { id: r.id }) }, star(r.level), tag(st[0], st[1]), el('span', {}, `${fmtTime(r.requested_at)} ${r.requested_by_name}`), r.expert ? sub(`確認 ${r.expert.name} ${day(r.confirmed_at)}`) : '', r.declaration ? sub(`宣誓 ${r.declaration.name} ${day(r.declared_at)}`) : '')); }
  c.append(list);
  if (p?.id) c.append(await reviewDetail(p.id, win));
}
async function reviewDetail(rid, win) {
  const box = el('div', { style: CARD }); let r; try { r = await GET(`/mamoricho/scs/reviews/${rid}`); } catch (e) { box.append(el('div', { class: 'notice err' }, e.message)); return box; }
  const st = REVIEW_STATE[r.state] || [r.state, '#475569']; const me = AIOS.state.me;
  box.append(el('div', { class: 'row', style: { gap: '8px', alignItems: 'center', flexWrap: 'wrap' } }, el('h2', { style: { margin: 0 } }, `★${r.level} 自己評価の写し`), tag(st[0], st[1]), el('span', { style: { marginLeft: 'auto' } }, el('button', { class: 'btn sm', onclick: () => download(`/mamoricho/scs/reviews/${rid}/export?format=docx`, 'SCS-自己評価.docx') }, '⬇ Word'), ' ', el('button', { class: 'btn sm', onclick: () => download(`/mamoricho/scs/reviews/${rid}/export?format=md`, 'SCS-自己評価.md') }, '⬇ Markdown'))),
    sub(`${fmtTime(r.requested_at)} ${r.requested_by_name} が依頼・写しのハッシュ ${r.snapshot_hash.slice(0, 16)}… ${r.hash_ok ? '(中身と一致)' : '⚠ 中身と合いません'}`));
  if (r.expert) box.append(el('div', { class: 'notice ok' }, `専門家の確認: ${r.expert.name} (${r.expert.qualification}${r.expert.reg_no ? ` 登録番号 ${r.expert.reg_no}` : ''}) ${fmtTime(r.expert.at)} — ${r.expert.statement}`));
  if (r.declaration) box.append(el('div', { class: 'notice ok' }, `経営層の宣誓: ${r.declaration.title} ${r.declaration.name} ${fmtTime(r.declaration.at)} — ${r.declaration.text}`));
  const acts = el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', margin: '8px 0' } });
  if (r.me.expert && r.state === 'requested') { const stm = el('input', { class: 'inp', placeholder: '確認の言葉 (空なら「上記の自己評価の内容を確認しました。」)', style: { flex: 1, minWidth: '240px' } }); acts.append(stm, el('button', { class: 'btn primary', onclick: async () => { const ok = await confirmDialog({ title: 'この写しの内容を確認しますか', body: '確認 (署名) は記録の鎖に残り、取り消せません。', okLabel: '確認する' }); if (!ok) return; try { await POST(`/mamoricho/scs/reviews/${rid}/decide`, { decision: 'confirm', statement: stm.value.trim() }); toast('確認しました', 'ok'); win.navigate('scsreview', { id: rid }); } catch (e) { toast(e.message, 'err'); } } }, '✔ 確認する (署名)'), el('button', { class: 'btn danger', onclick: async () => { if (!stm.value.trim()) return toast('差し戻す理由を入れてください', 'err'); try { await POST(`/mamoricho/scs/reviews/${rid}/decide`, { decision: 'return', statement: stm.value.trim() }); toast('差し戻しました', 'ok'); win.navigate('scsreview', { id: rid }); } catch (e) { toast(e.message, 'err'); } } }, '↩ 差し戻す')); }
  if (r.state === 'confirmed') { const nm = el('input', { class: 'inp', value: me?.display_name || '', placeholder: '氏名', style: { width: '160px' } }), tt = el('input', { class: 'inp', placeholder: '役職 (例: 代表取締役)', style: { width: '180px' } }); acts.append(nm, tt, el('button', { class: 'btn primary', onclick: async () => { const ok = await confirmDialog({ title: '宣誓しますか', body: `当社は、SCS 評価制度の★${r.level}の要求事項・評価基準に照らした上記の自己評価の内容が、事実に基づくものであることを宣誓します。`, okLabel: '宣誓する' }); if (!ok) return; try { await POST(`/mamoricho/scs/reviews/${rid}/declare`, { name: nm.value.trim(), title: tt.value.trim() }); toast('宣誓しました', 'ok'); win.navigate('scsreview', { id: rid }); } catch (e) { toast(e.message, 'err'); } } }, '🖋 経営層として宣誓する')); }
  if (isAdmin() && r.state === 'returned') acts.append(el('button', { class: 'btn primary', onclick: async () => { try { const n = await POST(`/mamoricho/scs/reviews/${rid}/resubmit`, {}); toast('出し直しました', 'ok'); win.navigate('scsreview', { id: n.review_id }); } catch (e) { toast(e.message, 'err'); } } }, '直したので出し直す'));
  if (isAdmin() && ['requested', 'returned'].includes(r.state)) acts.append(el('button', { class: 'btn', onclick: async () => { try { await POST(`/mamoricho/scs/reviews/${rid}/withdraw`, {}); win.navigate('scsreview'); } catch (e) { toast(e.message, 'err'); } } }, '取り下げる'));
  if (acts.childNodes.length) box.append(acts);
  // 全体への助言
  const canComment = (r.me.expert || isAdmin()) && ['requested', 'returned'].includes(r.state);
  const general = r.comments.filter(x => !x.criterion_id);
  if (general.length || canComment) { const g = el('div', { style: { margin: '8px 0' } }, el('b', {}, '全体への助言')); for (const x of general) g.append(sub(`${fmtTime(x.at)} ${x.by_name}${x.expert ? ' (専門家)' : ''}: ${x.text}`, { fontSize: '13px' })); if (canComment) g.append(commentBox(rid, null, win)); box.append(g); }
  const t = el('table', { class: 'tbl' }, el('tr', {}, el('th', {}, '番号'), el('th', {}, '要求事項・質問'), el('th', {}, '状態'), el('th', {}, '一言・根拠'), el('th', {}, '助言')));
  for (const x of r.snapshot.items) { const cs = r.comments.filter(cm => cm.criterion_id === x.id); t.append(el('tr', {}, el('td', { style: { whiteSpace: 'nowrap' } }, x.id), el('td', {}, el('div', { style: { fontWeight: 600 } }, x.req_name), sub(x.q)), el('td', {}, pill(x.status)), el('td', { style: { fontSize: '12px' } }, x.note ? el('div', {}, x.note) : '', ...(x.evidence || []).map(e => el('div', { class: 'sub', style: { margin: 0 } }, e)), x.plan?.action ? el('div', { style: { color: '#b45309' } }, `計画: ${x.plan.action} (${x.plan.owner || ''} ${x.plan.due || ''})`) : ''), el('td', { style: { fontSize: '12px', minWidth: '160px' } }, ...cs.map(cm => el('div', {}, `${cm.by_name}: ${cm.text}`)), canComment ? commentBox(rid, x.id, win, true) : ''))); }
  box.append(el('div', { style: { overflow: 'auto', marginTop: '8px' } }, t));
  return box;
}
function commentBox(rid, cid, win, small = false) {
  const inp = el('input', { class: 'inp', placeholder: cid ? '助言' : '全体への助言', style: { width: small ? '100%' : '60%' } });
  return el('div', { class: 'row', style: { gap: '4px', marginTop: '4px' } }, inp, el('button', { class: 'btn sm', onclick: async () => { if (!inp.value.trim()) return; try { await POST(`/mamoricho/scs/reviews/${rid}/comment`, { criterion_id: cid, text: inp.value.trim() }); toast('助言を残しました', 'ok'); win.navigate('scsreview', { id: rid }); } catch (e) { toast(e.message, 'err'); } } }, '残す'));
}

// ---------- 会社の情報 ----------
async function renderProfile(c, p, win) {
  let d, users = []; try { d = await GET('/mamoricho/scs/profile'); if (isAdmin()) users = (await GET('/mamoricho/scs/users')).users; } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  const pf = d.profile || {}; c.append(el('h1', {}, '会社の情報 (SCS・規程)'), el('p', { class: 'sub' }, '規程のひな形・改善計画書・自己評価の控えに差し込む情報と、確認する専門家・宣誓する経営層・★を取得した日です。保存は Admin 以上。'));
  const f = {}; const box = el('div', { style: CARD });
  for (const [k, l, ph] of [['company', '会社名', '株式会社みなと精機'], ['ceo', '代表者 (役職と氏名)', '代表取締役 港 一郎'], ['lead', 'セキュリティを統括する役員', '取締役 佐藤 花子'], ['it', '担当部署・担当者', '総務部 情報システム担当 (田中)'], ['where', '規程の置き場', `${AIOS_B().os}の AI NAS「規程」フォルダ`]]) { f[k] = el('input', { class: 'inp', value: pf[k] || '', placeholder: ph, disabled: !isAdmin(), style: { width: '100%' } }); box.append(el('label', { class: 'lbl' }, l), f[k]); }
  f.scope = el('textarea', { class: 'inp', rows: 2, value: pf.scope || '', placeholder: '適用範囲 (例: 本社と工場の IT 基盤。工場の制御システムは除く)', disabled: !isAdmin(), style: { width: '100%' } }); box.append(el('label', { class: 'lbl' }, '適用範囲'), f.scope);
  f.target = el('select', { class: 'inp', style: { width: 'auto' }, disabled: !isAdmin() }, el('option', { value: '3', selected: pf.target_level !== 4 }, '★3 を目指す'), el('option', { value: '4', selected: pf.target_level === 4 }, '★4 を目指す')); box.append(el('label', { class: 'lbl' }, '目標'), f.target);
  c.append(box);
  const opt = (sel) => [el('option', { value: '' }, '(この箱のアカウントを選ぶ)'), ...users.map(u => el('option', { value: u.id, selected: u.id === sel }, `${u.display_name} (${u.username}・${u.role})`))];
  const exBox = el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, 'セキュリティ専門家 (★3 の確認をする人)'), sub('情報処理安全確保支援士 (登録セキスペ)・公認情報セキュリティ監査人・CISSP・CISM・CISA・ISO27001 主任審査員などの資格を持ち、制度の研修を受けた人。社外の専門家には、この箱のアカウントを作って登録します (確認と助言だけに使います)。'));
  const exRows = []; const addEx = (e = {}) => { const r = { user: el('select', { class: 'inp', style: { width: 'auto' }, disabled: !isAdmin() }, ...opt(e.user_id)), name: el('input', { class: 'inp', value: e.name || '', placeholder: '氏名', style: { width: '120px' } }), qual: el('input', { class: 'inp', value: e.qualification || '', placeholder: '資格 (例: 情報処理安全確保支援士)', style: { width: '220px' } }), reg: el('input', { class: 'inp', value: e.reg_no || '', placeholder: '登録番号', style: { width: '110px' } }), tr: el('input', { class: 'inp', value: e.training || '', placeholder: '制度の研修 (受講日など)', style: { width: '180px' } }) }; exRows.push(r); exBox.append(el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', marginTop: '6px' } }, r.user, r.name, r.qual, r.reg, r.tr)); };
  (pf.experts?.length ? pf.experts : [{}]).forEach(addEx); if (isAdmin()) exBox.append(el('button', { class: 'btn sm', style: { marginTop: '6px' }, onclick: (e) => { e.target.remove(); addEx(); } }, '＋ 専門家を足す'));
  const exeBox = el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, '経営層 (宣誓をする人)'), sub(`空のときは、利用者の「経営層」の印がある人と Owner が宣誓できます (いま: ${(d.executives || []).map(x => x.name).join('、') || 'なし'})。`));
  const exeRows = []; const addExe = (e = {}) => { const r = { user: el('select', { class: 'inp', style: { width: 'auto' }, disabled: !isAdmin() }, ...opt(e.user_id)), name: el('input', { class: 'inp', value: e.name || '', placeholder: '氏名', style: { width: '140px' } }), title: el('input', { class: 'inp', value: e.title || '', placeholder: '役職', style: { width: '160px' } }) }; exeRows.push(r); exeBox.append(el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', marginTop: '6px' } }, r.user, r.name, r.title)); };
  (pf.executives?.length ? pf.executives : [{}]).forEach(addExe);
  const acq = pf.acquired || {}; const aBox = el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, '★を取得した日'), sub('取得したら入れてください。有効期限 (★3 は 1 年・★4 は 3 年) の前に知らせます。')); const af = {};
  for (const lv of ['3', '4']) { af[lv] = { at: el('input', { class: 'inp', type: 'date', value: acq[lv]?.at || '', disabled: !isAdmin(), style: { width: 'auto' } }), exp: el('input', { class: 'inp', type: 'date', value: acq[lv]?.expires_at || '', disabled: !isAdmin(), style: { width: 'auto' } }) }; aBox.append(el('div', { class: 'row', style: { gap: '8px', alignItems: 'center', marginTop: '6px' } }, star(Number(lv)), '取得日', af[lv].at, '有効期限', af[lv].exp)); }
  c.append(exBox, exeBox, aBox);
  if (isAdmin()) c.append(el('button', { class: 'btn primary', onclick: async () => {
    const body = { ...Object.fromEntries(['company', 'ceo', 'lead', 'it', 'where', 'scope'].map(k => [k, f[k].value])), target_level: Number(f.target.value),
      experts: exRows.map(r => ({ user_id: r.user.value, name: r.name.value || r.user.selectedOptions[0]?.textContent?.split(' (')[0] || '', qualification: r.qual.value, reg_no: r.reg.value, training: r.tr.value })).filter(e => e.user_id || e.name.trim()),
      executives: exeRows.map(r => ({ user_id: r.user.value, name: r.name.value || r.user.selectedOptions[0]?.textContent?.split(' (')[0] || '', title: r.title.value })).filter(e => e.user_id),
      acquired: Object.fromEntries(['3', '4'].map(lv => [lv, af[lv].at.value ? { at: af[lv].at.value, expires_at: af[lv].exp.value } : null])) };
    try { await PUT('/mamoricho/scs/profile', body); toast('保存しました (記録にも残ります)', 'ok'); win.navigate('scs'); } catch (e) { toast(e.message, 'err'); }
  } }, '保存'));
}

// ---------- 規程 (作成補助とレビュー) ----------
const VERDICT = { covered: ['書かれている', '#16a34a'], partial: ['一部・あいまい', '#d97706'], missing: ['書かれていない', '#dc2626'], unclear: ['根拠を確かめられない', '#6b7280'], found: ['言葉はある (中身は人が確認)', '#0891b2'], not_found: ['言葉が見つからない', '#dc2626'] };
async function renderRules(c, p, win) {
  let d; try { d = await GET('/mamoricho/policies/templates'); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  c.append(el('h1', {}, '規程 (作成とレビュー)'), el('p', { class: 'sub' }, `SCS 評価制度の「決まりを作る」項目を、15 の規程にまとめたひな形から作れます。会社の情報を差し込み、【要記入】を埋めて採用します。採用すると記録に残り、${AIOS_B().os}の AI NAS「規程」フォルダに Word で置き、全員に知らせられます。手持ちの規程は「レビュー」で、足りないところを確かめられます。ひな形は生成AI工房が作成したもので、公式のひな形ではありません。`));
  const rv = el('div', { style: CARD }); c.append(rv); reviewForm(rv, d.templates, p?.template || null, win);
  const grid = el('div', { class: 'grid', style: { gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '12px' } }); c.append(grid);
  for (const t of d.templates) {
    const pol = t.policy; const stx = pol?.adopted_version ? `採用 第${pol.adopted_version}版 (${day(pol.adopted_at)})${pol.latest > pol.adopted_version ? `・下書き 第${pol.latest}版` : ''}` : pol ? `下書き 第${pol.latest}版` : 'まだ作っていない';
    const card = el('div', { id: 'tpl-' + t.id, style: { ...CARD, marginBottom: 0, borderColor: p?.template === t.id ? '#2563eb' : undefined, borderWidth: p?.template === t.id ? '2px' : undefined } },
      el('div', { class: 'row', style: { gap: '6px', alignItems: 'center' } }, star(t.level), el('b', { style: { fontSize: '15px' } }, t.title)), sub(t.purpose), el('div', { style: { margin: '6px 0', fontSize: '13px', color: pol?.adopted_version ? '#16a34a' : '#6b7280', fontWeight: 600 } }, stx), t.last_review_at ? sub(`最後のレビュー ${day(t.last_review_at)}`) : '',
      el('details', { style: { fontSize: '12px', margin: '4px 0' } }, el('summary', { style: { cursor: 'pointer' } }, `書くべきこと (${t.elements.length})`), el('ul', { style: { margin: '4px 0 0 16px' } }, ...t.elements.map(e => el('li', {}, e.label, ' ', el('span', { class: 'sub' }, e.criteria.join(' '))))) ),
      el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', marginTop: '6px' } }, isOp() ? el('button', { class: 'btn sm primary', onclick: () => editor(t, pol, win) }, pol ? '開く・直す' : 'ひな形から作る') : (pol ? el('button', { class: 'btn sm', onclick: () => editor(t, pol, win) }, '見る') : ''), pol ? el('button', { class: 'btn sm', onclick: () => download(`/mamoricho/policies/${pol.id}/export?format=docx`, `${t.title}.docx`) }, '⬇ Word') : '', pol?.adopted_version && isOp() ? el('button', { class: 'btn sm', onclick: () => win.navigate('notices', { policy: pol.id, title: t.title }) }, '📣 全員に知らせる') : ''));
    grid.append(card);
  }
  if (p?.template) setTimeout(() => document.getElementById('tpl-' + p.template)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 60);
}
function reviewForm(box, templates, preset, win) {
  box.append(el('h2', { style: { marginTop: 0 } }, '手持ちの規程をレビューする'), sub('Word (.docx)・文字 (.txt / .md) のファイル、または貼り付けた文章を、選んだ規程のひな形の「書くべきこと」と照らします。AI は根拠の段落の番号を挙げ、まもり帳がその段落が実在するかを確かめます (根拠の無い「書かれている」は出しません)。AI が無いときは言葉の手がかりで探します。PDF は箱によって読めます。'));
  const sel = el('select', { class: 'inp', style: { width: 'auto' } }, ...templates.map(t => el('option', { value: t.id, selected: t.id === preset }, `${t.title} (★${t.level})`)));
  const lv = el('select', { class: 'inp', style: { width: 'auto' } }, el('option', { value: '3' }, '★3 の要素だけ'), el('option', { value: '4', selected: true }, '★4 まで'));
  const file = el('input', { type: 'file', accept: '.docx,.txt,.md,.pdf' }); const ta = el('textarea', { class: 'inp', rows: 4, placeholder: 'または、規程の文章を貼り付ける', style: { width: '100%', marginTop: '6px' } }); const out = el('div');
  box.append(el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', alignItems: 'center', marginTop: '8px' } }, '規程の種類', sel, lv, file), ta,
    el('div', { style: { marginTop: '6px' } }, isOp() ? el('button', { class: 'btn primary', onclick: async () => {
      let body = { template_id: sel.value, level: Number(lv.value) };
      if (file.files[0]) { const f = file.files[0]; if (f.size > 8 << 20) return toast('ファイルが大きすぎます (8MB まで)', 'err'); const b64 = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(',')[1] || ''); r.onerror = rej; r.readAsDataURL(f); }); body = { ...body, file_b64: b64, name: f.name }; }
      else if (ta.value.trim()) body = { ...body, text: ta.value, name: '貼り付けた文章' }; else return toast('ファイルを選ぶか、文章を貼り付けてください', 'err');
      out.innerHTML = ''; out.append(el('div', { class: 'notice info' }, '⏳ 読んでいます (AI で 1〜2 分かかることがあります)…'));
      try { const r = await POST('/mamoricho/policies/review', body); out.innerHTML = ''; out.append(reviewResult(r)); } catch (e) { out.innerHTML = ''; out.append(el('div', { class: 'notice err' }, e.message)); }
    } }, 'レビューする') : sub('レビューは Operator 以上が行えます。')), out);
}
function reviewResult(r) {
  const box = el('div', { style: { marginTop: '10px' } }); const c = r.counts || {};
  box.append(el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', alignItems: 'center' } }, el('b', {}, `${r.title}: ${r.name || ''} (${r.paragraphs} 段落)`), ...Object.entries(VERDICT).filter(([k]) => c[k]).map(([k, v]) => tag(`${v[0]} ${c[k]}`, v[1]))));
  if (r.note) box.append(el('div', { class: 'notice warn' }, r.note)); box.append(sub(r.caution));
  for (const x of r.results) {
    const v = VERDICT[x.verdict] || [x.verdict, '#475569']; const card = el('div', { style: { ...CARD, borderLeft: `4px solid ${v[1]}`, marginTop: '8px', marginBottom: 0 } }, el('div', { class: 'row', style: { gap: '6px', alignItems: 'center', flexWrap: 'wrap' } }, tag(v[0], v[1]), star(x.level), el('b', {}, x.label), el('span', { class: 'sub', style: { margin: 0, fontSize: '11px' } }, x.criteria.join(' '))));
    if (x.ai?.comment) card.append(sub(`AI: ${x.ai.comment}`, { fontSize: '13px' }));
    if (x.ai?.suggestion) card.append(el('div', { class: 'row', style: { gap: '6px', alignItems: 'flex-start', marginTop: '4px' } }, el('div', { style: { flex: 1, fontSize: '13px', background: '#f0f9ff', padding: '6px 8px', borderRadius: '6px' } }, `書き足す案: ${x.ai.suggestion}`), el('button', { class: 'btn sm', onclick: async () => { try { await navigator.clipboard.writeText(x.ai.suggestion); toast('写しました', 'ok'); } catch { toast('写せませんでした', 'err'); } } }, '写す')));
    const quotes = x.ai?.paragraphs?.length ? x.ai.paragraphs : x.kw; if (quotes.length) card.append(el('details', { style: { marginTop: '4px', fontSize: '12px' }, open: x.verdict === 'partial' }, el('summary', { style: { cursor: 'pointer' } }, `${x.ai?.paragraphs?.length ? 'AI が挙げた根拠' : '言葉が見つかった段落'} (${quotes.length})`), ...quotes.map(q => el('div', { style: { padding: '4px 8px', borderLeft: '3px solid #cbd5e1', margin: '4px 0', whiteSpace: 'pre-wrap' } }, el('b', {}, `P${q.n} `), q.text))));
    box.append(card);
  }
  return box;
}
async function editor(t, pol, win) {
  let d = null; if (pol) { try { d = await GET(`/mamoricho/policies/${pol.id}`); } catch (e) { return toast(e.message, 'err'); } }
  const latest = d?.versions?.[0] || null; const c = el('div');
  const ta = el('textarea', { class: 'inp', rows: 22, style: { width: '100%', fontFamily: 'ui-monospace, monospace', fontSize: '13px' }, disabled: !isOp() }); const preview = el('div', { style: { maxHeight: '420px', overflow: 'auto', border: '1px solid var(--line, #e5e7eb)', borderRadius: '8px', padding: '8px 12px', display: 'none' } }); const msg = el('div');
  let source = latest ? 'edit' : 'template';
  if (latest) ta.value = latest.body; else { try { ta.value = (await POST('/mamoricho/policies/draft', { template_id: t.id })).body; } catch (e) { return toast(e.message, 'err'); } }
  const left = () => (ta.value.match(/【要記入/g) || []).length; const leftInfo = el('span', { class: 'sub', style: { margin: 0 } }); const upd = () => { leftInfo.textContent = `【要記入】あと ${left()} か所`; }; ta.addEventListener('input', () => { source = 'edit'; upd(); }); upd();
  const notes = el('textarea', { class: 'inp', rows: 3, placeholder: '会社についてのメモ (AI が【要記入】を埋める材料。例: 社員 12 人の製造業。本社と工場の 2 拠点。メールは Microsoft 365。パソコンは Windows 11 が 15 台。ウイルス対策は ○○。保守は △△ 社。夜間の連絡は社長の携帯)', style: { width: '100%' } });
  c.append(el('div', { class: 'row', style: { gap: '8px', alignItems: 'center', flexWrap: 'wrap' } }, el('h2', { style: { margin: 0 } }, t.title), star(t.level), latest ? tag(`第${latest.version}版 ${latest.state === 'adopted' ? '採用' : latest.state === 'draft' ? '下書き' : '旧版'}`) : tag('新しい下書き'), leftInfo, el('span', { style: { marginLeft: 'auto' } }, el('button', { class: 'btn sm', onclick: () => { const on = preview.style.display === 'none'; preview.innerHTML = ''; if (on) preview.append(md(ta.value)); preview.style.display = on ? 'block' : 'none'; ta.style.display = on ? 'none' : 'block'; } }, '見た目で見る / 文字に戻す'))), sub(t.purpose), ta, preview);
  if (isOp()) c.append(el('details', { style: { margin: '8px 0' } }, el('summary', { style: { cursor: 'pointer', fontWeight: 600 } }, '🤖 AI に【要記入】を埋めてもらう'), sub(`メモに書いた事実だけで埋めます。見出しや数字 (14 日・8 文字・10 回など) の決まりを変えた結果は使いません。${AIOS_B().os}の AI で処理し、外には出ません。`), notes, el('div', { class: 'row', style: { gap: '6px', marginTop: '6px' } }, el('button', { class: 'btn', onclick: async () => { if (!notes.value.trim()) return toast('メモを入れてください', 'err'); msg.innerHTML = ''; msg.append(el('div', { class: 'notice info' }, '⏳ AI が埋めています…')); try { const r = await POST('/mamoricho/policies/draft', { template_id: t.id, notes: notes.value, use_ai: true }); msg.innerHTML = ''; if (r.source === 'ai') { ta.value = r.body; source = 'ai'; upd(); } msg.append(el('div', { class: 'notice ' + (r.ai?.ok ? 'ok' : 'warn') }, r.ai?.note || '')); } catch (e) { msg.innerHTML = ''; msg.append(el('div', { class: 'notice err' }, e.message)); } } }, 'ひな形 + メモで埋める'), el('button', { class: 'btn', onclick: async () => { const ok = await confirmDialog({ title: 'ひな形から作り直しますか', body: 'いまの文章は消え、会社の情報を差し込んだひな形になります (保存するまで記録は変わりません)。', okLabel: '作り直す' }); if (!ok) return; try { ta.value = (await POST('/mamoricho/policies/draft', { template_id: t.id })).body; source = 'template'; upd(); } catch (e) { toast(e.message, 'err'); } } }, 'ひな形から作り直す'))));
  const notify = el('input', { type: 'checkbox', checked: true });
  const doSave = async () => { const r = await POST('/mamoricho/policies', { policy_id: pol?.id || null, template_id: t.id, title: t.title, body: ta.value, source }); pol = { id: r.policy_id }; return r; };
  c.append(msg, el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', alignItems: 'center', marginTop: '8px' } },
    isOp() ? el('button', { class: 'btn', onclick: async () => { try { const r = await doSave(); toast(`下書きを保存しました (第${r.version}版)`, 'ok'); } catch (e) { toast(e.message, 'err'); } } }, '下書きを保存') : '',
    isOp() ? el('button', { class: 'btn', onclick: async () => { try { const s = await doSave(); msg.innerHTML = ''; msg.append(el('div', { class: 'notice info' }, '⏳ レビューしています…')); const r = await POST('/mamoricho/policies/review', { template_id: t.id, policy_id: s.policy_id, version: s.version, level: 4 }); msg.innerHTML = ''; msg.append(reviewResult(r)); } catch (e) { msg.innerHTML = ''; msg.append(el('div', { class: 'notice err' }, e.message)); } } }, 'この下書きをレビュー') : '',
    isAdmin() ? el('label', { class: 'row', style: { gap: '4px', alignItems: 'center', fontSize: '13px' } }, notify, '採用したら全員に知らせる') : '',
    isAdmin() ? el('button', { class: 'btn primary', onclick: async () => { const s = await doSave().catch(e => { toast(e.message, 'err'); return null; }); if (!s) return; const n = left(); const ok = await confirmDialog({ title: `第${s.version}版を採用しますか`, body: `${n ? `<b>【要記入】が ${n} か所残っています。</b><br>` : ''}採用すると「いまの規程」になり、本文のハッシュが記録に残ります。${notify.checked ? '全員に知らせ、確認を集めます。' : ''}`, okLabel: '採用する' }); if (!ok) return; try { const r = await POST(`/mamoricho/policies/${s.policy_id}/adopt`, { version: s.version, notify: notify.checked }); closeModal(); toast(`採用しました (第${r.version}版)${r.nas?.id ? '・AI NAS に置きました' : ''}${r.notice ? '・全員に知らせました' : ''}`, 'ok'); win.navigate('rules', { template: t.id }); } catch (e) { toast(e.message, 'err'); } } }, '採用する') : '',
    el('button', { class: 'btn', style: { marginLeft: 'auto' }, onclick: () => { closeModal(); win.navigate('rules', { template: t.id }); } }, '閉じる')));
  if (d?.versions?.length) c.append(el('details', { style: { marginTop: '10px', fontSize: '13px' } }, el('summary', { style: { cursor: 'pointer' } }, `版の履歴 (${d.versions.length})`), ...d.versions.map(v => el('div', { class: 'row', style: { gap: '8px', padding: '4px 0', borderTop: '1px solid var(--line, #eee)', alignItems: 'center' } }, el('b', {}, `第${v.version}版`), tag(v.state === 'adopted' ? '採用' : v.state === 'draft' ? '下書き' : '旧版'), el('span', {}, `${fmtTime(v.created_at)} ${v.created_by_name}${v.adopted_at ? ` / 採用 ${fmtTime(v.adopted_at)} ${v.adopted_by_name}` : ''}`), el('button', { class: 'btn sm', onclick: () => download(`/mamoricho/policies/${pol.id}/export?format=docx&version=${v.version}`, `${t.title}-第${v.version}版.docx`) }, '⬇ Word'), el('button', { class: 'btn sm', onclick: () => { ta.value = v.body; source = 'edit'; upd(); } }, 'この版の文を使う')))));
  wide(c);
}

// ---------- 台帳 ----------
async function renderLedgers(c, p, win) {
  let d; try { d = await GET('/mamoricho/ledgers'); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  const kind = p?.kind || d.kinds[0].id;
  c.append(el('h1', {}, '台帳'), el('p', { class: 'sub' }, 'SCS 評価制度の「把握するための仕組みを整備すること」「記録を保管すること」のための一覧です。行の追加・変更・削除はすべて記録の鎖に残ります。年 1 回の見直しをしたら「見直した」を押します。'));
  const chips = el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', marginBottom: '12px' } }, ...d.kinds.map(k => el('button', { class: 'btn sm' + (k.id === kind ? ' primary' : ''), onclick: () => win.navigate('ledgers', { kind: k.id }) }, `${k.label} ${d.counts[k.id]?.n || 0}`))); c.append(chips);
  let l; try { l = await GET(`/mamoricho/ledgers/${kind}`); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  const k = l.kind; const box = el('div', { style: CARD }); c.append(box);
  box.append(el('div', { class: 'row', style: { gap: '8px', alignItems: 'center', flexWrap: 'wrap' } }, el('h2', { style: { margin: 0 } }, k.label), el('span', { class: 'sub', style: { margin: 0 } }, `評価基準 ${k.criteria.join(' ')}`), el('span', { style: { marginLeft: 'auto' } }, l.reviewed_at ? sub(`最後の見直し ${day(l.reviewed_at)}`) : sub('まだ見直しの記録なし'))), sub(k.note),
    el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', margin: '8px 0' } }, isOp() ? el('button', { class: 'btn sm primary', onclick: () => rowDialog(k, null, win) }, '＋ 行を足す') : '', isOp() && ['servers', 'netdevices', 'admins'].includes(k.id) ? el('button', { class: 'btn sm', onclick: () => suggestDialog(k, win) }, '💡 候補から足す (診断・箱の利用者)') : '', isOp() ? el('button', { class: 'btn sm', onclick: async () => { const ok = await confirmDialog({ title: `「${k.label}」を見直しましたか`, body: 'いまの中身を確かめたことを、日付つきで記録に残します (年 1 回の点検の材料)。', okLabel: '見直した' }); if (!ok) return; try { await POST(`/mamoricho/ledgers/${k.id}/reviewed`, {}); toast('記録しました', 'ok'); win.navigate('ledgers', { kind: k.id }); } catch (e) { toast(e.message, 'err'); } } }, '✔ 見直した') : '', el('button', { class: 'btn sm', onclick: () => download(`/mamoricho/ledgers/${k.id}/csv`, `${k.label}.csv`) }, '⬇ CSV')));
  if (!l.rows.length) { box.append(el('div', { class: 'notice info' }, 'まだ行がありません。')); return; }
  const t = el('table', { class: 'tbl' }, el('tr', {}, ...k.cols.map(cl => el('th', {}, cl[1])), el('th', {}, '')));
  for (const r of l.rows) t.append(el('tr', {}, ...k.cols.map(([key, , type]) => el('td', { style: { whiteSpace: type === 'long' ? 'pre-wrap' : undefined, fontSize: '13px' } }, type === 'bool' ? (r.data[key] ? '✓' : '') : String(r.data[key] ?? ''))), el('td', { style: { whiteSpace: 'nowrap' } }, isOp() ? el('button', { class: 'btn sm', onclick: () => rowDialog(k, r, win) }, '直す') : '', ' ', isOp() ? el('button', { class: 'btn sm danger', onclick: async () => { const ok = await confirmDialog({ title: 'この行を消しますか', body: '消した行も記録の鎖から追えます。', okLabel: '消す', danger: true }); if (!ok) return; try { await DEL(`/mamoricho/ledgers/${k.id}/${r.id}`); win.navigate('ledgers', { kind: k.id }); } catch (e) { toast(e.message, 'err'); } } }, '消す') : '')));
  box.append(el('div', { style: { overflow: 'auto' } }, t));
}
function rowDialog(k, r, win, preset = null) {
  const f = {}; const c = el('div', {}, el('h2', {}, `${k.label}: ${r ? '行を直す' : '行を足す'}`));
  const val = { ...(preset || {}), ...(r?.data || {}) };
  for (const [key, label, type, req] of k.cols) {
    let inp; if (type === 'bool') inp = el('input', { type: 'checkbox', checked: !!val[key] }); else if (type === 'long') inp = el('textarea', { class: 'inp', rows: 3, value: val[key] ?? '', style: { width: '100%' } }); else if (type.startsWith('select:')) inp = el('select', { class: 'inp' }, el('option', { value: '' }, '(選ぶ)'), ...type.slice(7).split('|').map(o => el('option', { value: o, selected: val[key] === o }, o))); else inp = el('input', { class: 'inp', type: type === 'date' ? 'date' : type === 'num' ? 'number' : 'text', value: val[key] ?? '', style: { width: type === 'date' || type === 'num' ? 'auto' : '100%' } });
    f[key] = inp; c.append(el('label', { class: 'lbl' }, label, req ? el('span', { style: { color: '#dc2626' } }, ' *') : ''), inp);
  }
  c.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px', marginTop: '12px' } }, el('button', { class: 'btn', onclick: closeModal }, 'やめる'), el('button', { class: 'btn primary', onclick: async () => { const data = Object.fromEntries(k.cols.map(([key, , type]) => [key, type === 'bool' ? f[key].checked : f[key].value])); try { await POST(`/mamoricho/ledgers/${k.id}`, { id: r?.id || null, data }); closeModal(); toast('記録しました', 'ok'); win.navigate('ledgers', { kind: k.id }); } catch (e) { toast(e.message, 'err'); } } }, '保存')));
  modal(c);
}
async function suggestDialog(k, win) {
  let s; try { s = await GET(`/mamoricho/ledgers/${k.id}/suggest`); } catch (e) { return toast(e.message, 'err'); }
  const c = el('div', {}, el('h2', {}, `${k.label}: 候補`), sub('まもり帳の対象の台帳・まとめて診断の結果・箱の利用者から。足すかどうかはあなたが決めます (足りない列は足すときに入れてください)。'));
  if (!s.suggestions.length) c.append(el('p', {}, '新しい候補はありません。'));
  for (const x of s.suggestions) c.append(el('div', { class: 'row', style: { gap: '8px', padding: '6px 0', borderTop: '1px solid var(--line, #eee)', alignItems: 'center' } }, el('span', { style: { flex: 1, fontSize: '13px' } }, Object.values(x).filter(v => v !== '' && v !== false).join(' / ')), el('button', { class: 'btn sm', onclick: () => { closeModal(); setTimeout(() => rowDialog(k, null, win, x), 50); } }, '足す')));
  modal(c);
}

// ---------- 全員に知らせる ----------
async function renderNotices(c, p, win) {
  c.append(el('h1', {}, '全員に知らせる'), el('p', { class: 'sub' }, `規程の制定・改定、ルールの周知、教育・訓練の受講の確認に使います。箱の通知で全員に届き、それぞれが開いて「確認しました」を押します。誰がいつ確認したかは記録に残ります (SCS 評価制度の「周知すること」「受講状況を記録すること」の材料)。まもり帳の許可が無い社員も、通知から確認できます。`));
  if (!isOp()) { c.append(el('div', { class: 'notice info' }, '知らせを出すのは Operator 以上です。自分あてのお知らせは「お知らせの確認」で見られます。'), el('button', { class: 'btn', onclick: () => win.navigate('inbox') }, 'お知らせの確認')); return; }
  const kind = el('select', { class: 'inp', style: { width: 'auto' } }, el('option', { value: 'notice' }, 'お知らせ (周知)'), el('option', { value: 'training' }, '教育・訓練の受講の確認'));
  const title = el('input', { class: 'inp', value: p?.title ? `${p.title} を制定・改定しました` : '', placeholder: '題名 (例: パスワードのルールを改定しました)', style: { width: '100%' } });
  const body = el('textarea', { class: 'inp', rows: 4, placeholder: '本文 (例: 8 文字以上・使い回し禁止。詳しくは規程「ID・パスワード・アクセス権の管理ルール」)', style: { width: '100%' } });
  const crit = el('input', { class: 'inp', value: p?.criteria || '', placeholder: '結びつける評価基準の番号 (任意。例: 4-1-5-5 4-1-6-3)', style: { width: '100%' } });
  let policies = []; try { policies = (await GET('/mamoricho/policies')).policies.filter(x => x.adopted_version); } catch { /* なし */ }
  const pol = el('select', { class: 'inp', style: { width: 'auto' } }, el('option', { value: '' }, '(規程を添えない)'), ...policies.map(x => el('option', { value: x.id, selected: x.id === p?.policy }, `${x.title} 第${x.adopted_version}版`)));
  c.append(el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, '新しく知らせる'), el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap' } }, kind, pol), el('label', { class: 'lbl' }, '題名'), title, el('label', { class: 'lbl' }, '本文'), body, el('label', { class: 'lbl' }, '評価基準'), crit,
    el('div', { style: { marginTop: '8px' } }, el('button', { class: 'btn primary', onclick: async () => { const pp = policies.find(x => x.id === pol.value); try { const r = await POST('/mamoricho/notices', { kind: kind.value, title: title.value, body: body.value, policy_id: pp?.id || null, policy_version: pp?.adopted_version || null, criteria: crit.value.split(/[\s,、]+/).filter(x => /^\d+-\d+-\d+-\d+$/.test(x)) }); toast('全員に知らせました', 'ok'); win.navigate('notices', { id: r.id }); } catch (e) { toast(e.message, 'err'); } } }, '全員に知らせる'))));
  let d; try { d = await GET('/mamoricho/notices'); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  const list = el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, `これまでの知らせ (対象 ${d.audience} 人)`));
  for (const n of d.notices) list.append(el('div', { class: 'row', style: { gap: '8px', padding: '6px 0', borderTop: '1px solid var(--line, #eee)', alignItems: 'center', cursor: 'pointer' }, onclick: () => win.navigate('notices', { id: n.id }) }, tag(n.kind === 'training' ? '受講' : '周知', n.kind === 'training' ? '#0d9488' : '#7c3aed'), el('b', {}, n.title), el('span', { class: 'sub', style: { margin: 0 } }, fmtTime(n.created_at)), el('span', { style: { marginLeft: 'auto', fontWeight: 700, color: n.acks >= n.audience ? '#16a34a' : '#d97706' } }, `確認 ${n.acks}/${n.audience}`), n.closed_at ? tag('締め切り') : ''));
  if (!d.notices.length) list.append(sub('まだ知らせはありません。'));
  c.append(list);
  if (p?.id) { let n; try { n = await GET(`/mamoricho/notices/${p.id}`); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
    c.append(el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, n.title), sub(`${fmtTime(n.created_at)} ${n.created_by_name}${n.criteria.length ? ` ・評価基準 ${n.criteria.join(' ')}` : ''}`), n.body ? el('p', { style: { whiteSpace: 'pre-wrap' } }, n.body) : '',
      el('div', { class: 'row', style: { gap: '6px', margin: '6px 0' } }, !n.closed_at ? el('button', { class: 'btn sm', onclick: async () => { try { const r = await POST(`/mamoricho/notices/${n.id}/remind`, {}); toast(`まだの ${r.reminded} 人にもう一度知らせました`, 'ok'); } catch (e) { toast(e.message, 'err'); } } }, 'まだの人にもう一度') : '', !n.closed_at ? el('button', { class: 'btn sm', onclick: async () => { const ok = await confirmDialog({ title: '締め切りますか', body: '確認できた人とまだの人の一覧を記録に残し、これ以上は確認を受け付けません。', okLabel: '締め切る' }); if (!ok) return; try { await POST(`/mamoricho/notices/${n.id}/close`, {}); win.navigate('notices', { id: n.id }); } catch (e) { toast(e.message, 'err'); } } }, '締め切る') : tag(`締め切り ${fmtTime(n.closed_at)}`)),
      el('div', { class: 'grid', style: { gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '10px' } }, el('div', {}, el('b', {}, `確認した (${n.acks.length})`), ...n.acks.map(a => sub(`${a.user_name}${a.department ? ` (${a.department})` : ''} ${fmtTime(a.at)}`, { fontSize: '13px' }))), el('div', {}, el('b', { style: { color: '#d97706' } }, `まだ (${n.pending.length})`), ...n.pending.map(u => sub(`${u.display_name}${u.department ? ` (${u.department})` : ''}`, { fontSize: '13px' }))))));
  }
}

// ---------- お知らせの確認 (だれでも) ----------
async function ackDialog(nid, onDone) {
  let v; try { v = await GET(`/mamoricho-ack/notice/${nid}`); } catch (e) { return toast(e.message, 'err'); }
  const c = el('div', {}, el('h2', {}, v.title), sub(`${fmtTime(v.created_at)} ${v.created_by_name}`), v.body ? el('p', { style: { whiteSpace: 'pre-wrap' } }, v.body) : '');
  if (v.policy) c.append(el('div', { style: { maxHeight: '50vh', overflow: 'auto', border: '1px solid var(--line, #e5e7eb)', borderRadius: '8px', padding: '8px 12px', margin: '8px 0' } }, el('div', { class: 'sub', style: { margin: 0 } }, `${v.policy.title} 第${v.policy.version}版`), md(v.policy.body)));
  c.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px', marginTop: '12px' } }, v.acked_at ? el('span', { class: 'sub', style: { margin: 0 } }, `確認済み ${fmtTime(v.acked_at)}`) : v.closed ? el('span', { class: 'sub' }, '締め切られています') : el('button', { class: 'btn primary', onclick: async () => { try { await POST(`/mamoricho-ack/notice/${nid}`, {}); closeModal(); toast('確認しました', 'ok'); onDone?.(); } catch (e) { toast(e.message, 'err'); } } }, '読んで、確認しました'), el('button', { class: 'btn', onclick: closeModal }, '閉じる')));
  wide(c, 820);
}
async function renderInbox(c, p, win) {
  c.append(el('h1', {}, 'お知らせの確認'), el('p', { class: 'sub' }, '会社からのお知らせ・規程の制定と改定・教育の受講の確認です。読んで「確認しました」を押してください。採用されている規程も、いつでもここで読めます。'));
  let d, pl; try { [d, pl] = await Promise.all([GET('/mamoricho-ack/pending'), GET('/mamoricho-ack/policies')]); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  const box = el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, `まだ確認していないもの (${d.notices.length})`));
  for (const n of d.notices) box.append(el('div', { class: 'row', style: { gap: '8px', padding: '6px 0', borderTop: '1px solid var(--line, #eee)', alignItems: 'center' } }, el('b', { style: { flex: 1 } }, n.title), el('span', { class: 'sub', style: { margin: 0 } }, fmtTime(n.created_at)), el('button', { class: 'btn sm primary', onclick: () => ackDialog(n.id, () => win.navigate('inbox')) }, '開く')));
  if (!d.notices.length) box.append(el('div', { class: 'notice ok' }, 'すべて確認しました。'));
  const pb = el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, 'いまの規程'));
  for (const x of pl.policies) pb.append(el('div', { class: 'row', style: { gap: '8px', padding: '6px 0', borderTop: '1px solid var(--line, #eee)', alignItems: 'center' } }, el('b', { style: { flex: 1 } }, x.title), el('span', { class: 'sub', style: { margin: 0 } }, `第${x.version}版 ${day(x.adopted_at)}`), el('button', { class: 'btn sm', onclick: async () => { try { const r = await GET(`/mamoricho-ack/policies/${x.id}`); wide(el('div', {}, el('h2', {}, `${r.title} 第${r.version}版`), md(r.body)), 820); } catch (e) { toast(e.message, 'err'); } } }, '読む')));
  if (!pl.policies.length) pb.append(sub('まだ採用された規程はありません。'));
  c.append(box, pb);
}

AIOS.mamorichoAck = { open: (nid) => ackDialog(nid), inbox: renderInbox };
AIOS.mamorichoExt = {
  // メニュー: 印の無いものは「点検」の後ろ、tail はメニューの最後、hidden はメニューに出さない (ほかの画面から入る)
  routes: {
    scs: { label: 'SCS 評価制度', icon: '★', render: renderScs },
    rules: { label: '規程', icon: '📘', render: renderRules },
    ledgers: { label: '台帳', icon: '🗂', render: renderLedgers },
    notices: { label: '全員に知らせる', icon: '📣', tail: true, sep: true, render: renderNotices },
    inbox: { label: 'お知らせの確認', icon: '📬', tail: true, render: renderInbox },
    scsplan: { label: '改善計画書', icon: '📝', hidden: true, render: renderPlan },
    scsreview: { label: '確認と宣誓', icon: '🖋', hidden: true, render: renderReview },
    scsprofile: { label: '会社の情報', icon: '🏢', hidden: true, render: renderProfile },
  },
};
})();
