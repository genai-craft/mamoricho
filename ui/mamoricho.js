// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳 — 基本の対策を対話で確かめて記録に残す (docs/MAMORICHO_DESIGN.md)。画面は 5 つ: ホーム / 点検 / 対象 / 記録 / もしものとき
(() => {
const { el, GET, POST, PUT, PATCH, DEL, toast, modal, confirmDialog, fmtTime, openWindow } = AIOS;
const api = (m, p, b, o) => (m === 'GET' ? GET(p) : m === 'POST' ? POST(p, b, o) : m === 'PUT' ? PUT(p, b) : m === 'PATCH' ? PATCH(p, b) : DEL(p));
const isOp = () => ['owner', 'admin', 'operator'].includes(AIOS.state.me?.role);
const isAdmin = () => ['owner', 'admin'].includes(AIOS.state.me?.role);
const ST = { ok: ['できている', '#16a34a'], partial: ['一部できている', '#d97706'], no: ['できていない', '#dc2626'], unknown: ['分からない', '#6b7280'], na: ['対象外', '#94a3b8'], unanswered: ['未回答', '#cbd5e1'] };
const dot = (s) => el('span', { style: { display: 'inline-block', width: '10px', height: '10px', borderRadius: '50%', background: (ST[s] || ST.unanswered)[1], marginRight: '6px', verticalAlign: '-1px' } });
const pill = (s) => el('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', padding: '2px 8px', borderRadius: '999px', background: 'rgba(15,23,42,.06)' } }, dot(s), (ST[s] || ST.unanswered)[0]);
const bar = (pct, color = '#16a34a') => el('div', { style: { height: '10px', borderRadius: '999px', background: 'rgba(15,23,42,.08)', overflow: 'hidden' } }, el('div', { style: { width: `${Math.max(0, Math.min(100, pct))}%`, height: '100%', background: color, transition: 'width .4s' } }));
const KIND = { ssh: 'サーバー・PC (SSH)', network: 'ネットワーク機器 (SSH)', web: '公開 HP (https)' };
const CARD = { padding: '14px 16px', border: '1px solid var(--line, #e5e7eb)', borderRadius: '12px', background: 'var(--card, #fff)', marginBottom: '12px' };
// ブランド (箱の名前など)。OS が /mamoricho/brand で差し出す (単体版では「この箱」)。表示の文言はこれを参照し、製品名を決め打ちしない
const B = { product: 'まもり帳', os: '言箱', os_en: 'Kotohako', ai: '箱の中の AI', store: '箱の中 (AI NAS の「まもり帳」フォルダ)' };

// ---------- ホーム ----------
// ダッシュボード: メニューが並んでも「何を・いつ・どうしたらいいか」で迷わないように、最優先の 1 つ・やることの順番・予定・対象ごとの最終確認を 1 か所に
const LV = { warn: ['#dc2626', '⚠ 疑い'], check: ['#d97706', '👀 確認'], todo: ['#2563eb', '▶ 次にやること'], ok: ['#16a34a', '✅ いまは落ち着いています'] };
const STEP = { done: ['✅', '#16a34a'], partial: ['◐', '#d97706'], todo: ['○', '#6b7280'], na: ['－', '#cbd5e1'] };
const goTo = (win, x) => { if (!x?.route || x.route === 'home') return; if (x.route === 'targets' && x.target_id) return win.navigate('targets', { focus: x.target_id }); win.navigate(x.route, x.params || null); };
function renderDashboard(c, d, win) {
  const pr = d.priority; const lv = LV[pr.level] || LV.todo;
  const top = el('div', { style: { ...CARD, borderColor: lv[0], borderWidth: '2px' } });
  top.append(el('div', { style: { fontSize: '12px', color: lv[0], fontWeight: 700 } }, `${lv[1]} — いちばん先にやること`), el('div', { style: { fontSize: '20px', fontWeight: 800, margin: '4px 0' } }, pr.title), el('div', { style: { fontSize: '13px' } }, pr.why),
    pr.route !== 'home' ? el('div', { style: { marginTop: '8px' } }, el('button', { class: 'btn primary', onclick: () => goTo(win, pr) }, 'ここから始める')) : '');
  c.append(top);
  const n = d.counts; const chip = (label, v, color, route, params) => el('button', { class: 'btn', style: { textAlign: 'left', padding: '8px 12px', borderColor: v ? color : undefined }, onclick: () => win.navigate(route, params || null) }, el('div', { style: { fontSize: '22px', fontWeight: 800, lineHeight: 1.1, color: v ? color : '#6b7280' } }, String(v)), el('div', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, label));
  c.append(el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', marginBottom: '12px', alignItems: 'stretch' } }, chip('管理者の操作に確認が必要', n.admin_needs_check, '#dc2626', 'admin'), chip('API の権限に確認が必要', n.authz_needs_check, '#dc2626', 'authz'), chip('機械・HP の兆候 (疑い)', n.sign_warn, '#dc2626', 'targets'), chip('まだ診断していない対象', n.unchecked_targets + n.pending_targets, '#d97706', 'targets'), chip('30 日以上診断していない', n.stale_targets, '#d97706', 'targets'),
    el('div', { class: 'sub', style: { margin: '0 0 0 auto', fontSize: '12px', alignSelf: 'center' } }, d.last_checked_at ? `最終確認 ${fmtTime(d.last_checked_at)}` : 'まだ何も確認していません')));
  const grid = el('div', { class: 'grid', style: { gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '12px', marginBottom: '12px' } });
  const steps = el('div', { style: { ...CARD, marginBottom: 0 } }, el('h2', { style: { marginTop: 0 } }, 'やることの順番'), el('div', { class: 'sub', style: { fontSize: '12px' } }, '上から順に。終わったものは ✅、途中は ◐。月 1 回の診断と四半期の見直しを続けるのが現実的な守りです。'));
  d.steps.forEach((x, i) => { const st = STEP[x.state] || STEP.todo; steps.append(el('div', { class: 'row', style: { alignItems: 'center', gap: '10px', padding: '6px 0', borderTop: '1px solid var(--line, #eee)', cursor: 'pointer' }, onclick: () => win.navigate(x.route, x.params || null) }, el('span', { style: { color: st[1], fontWeight: 800, width: '18px' } }, st[0]), el('div', { style: { flex: 1 } }, el('div', { style: { fontWeight: x.state === 'done' ? 400 : 700, opacity: x.state === 'na' ? .6 : 1 } }, `${i + 1}. ${x.label}`), el('div', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, x.detail)))); });
  const sch = el('div', { style: { ...CARD, marginBottom: 0 } }, el('h2', { style: { marginTop: 0 } }, 'いつ (予定)'));
  if (!d.schedule.length) sch.append(el('div', { class: 'sub' }, '対象を登録して診断すると、次の予定がここに出ます。'));
  for (const x of d.schedule) sch.append(el('div', { class: 'row', style: { gap: '8px', padding: '5px 0', borderTop: '1px solid var(--line, #eee)', fontSize: '13px', cursor: 'pointer' }, onclick: () => goTo(win, x) }, el('span', { style: { color: x.overdue ? '#dc2626' : '#6b7280', fontWeight: 700, minWidth: '96px' } }, new Date(x.at).toLocaleDateString('ja-JP') + (x.overdue ? ' 超過' : '')), el('span', {}, x.label)));
  grid.append(steps, sch); c.append(grid);
  if (d.targets.length) {
    const t = el('table', { class: 'tbl' }, el('thead', {}, el('tr', {}, el('th', {}, '対象'), el('th', {}, '最終診断'), el('th', {}, '兆候'), el('th', {}, '管理者'), el('th', {}, 'API の権限'), el('th', {}, ''))));
    const muted = (s) => el('span', { class: 'sub', style: { margin: 0 } }, s);
    for (const r of d.targets) {
      const sg = r.warn ? el('span', { style: { color: '#dc2626', fontWeight: 700 } }, `疑い ${r.warn}`) : r.check ? el('span', { style: { color: '#d97706' } }, `確認 ${r.check}`) : r.last_snapshot_at ? muted('なし') : '';
      const ad = !r.admin ? muted('－') : r.admin.not_yet ? muted('まとめて診断で') : r.admin.warn ? el('span', { style: { color: '#dc2626', fontWeight: 700 } }, `疑い ${r.admin.warn}`) : r.admin.check ? el('span', { style: { color: '#d97706' } }, `確認 ${r.admin.check}`) : muted(r.admin.unavailable ? `なし (確認できず ${r.admin.unavailable})` : 'なし');
      const az = !r.authz ? muted('－') : r.authz.suspects ? el('span', { style: { color: '#dc2626', fontWeight: 700 } }, `疑い ${r.authz.suspects}`) : r.authz.pending_plan ? el('span', { style: { color: '#d97706' } }, '承認待ち') : r.authz.last_run ? muted(`検査済み${r.authz.unclear ? '・判断できない ' + r.authz.unclear : ''}`) : r.authz.has_spec ? el('span', { style: { color: '#d97706' } }, `未確定 ${r.authz.unknown}`) : muted('未登録');
      t.append(el('tr', {}, el('td', {}, el('b', {}, r.name), ' ', el('span', { class: 'tag' }, KIND[r.kind] || r.kind), r.pending ? el('span', { style: { color: '#d97706', marginLeft: '6px', fontSize: '12px' } }, '登録待ち') : ''), el('td', { style: { color: r.stale ? '#dc2626' : undefined } }, r.last_snapshot_at ? `${new Date(r.last_snapshot_at).toLocaleDateString('ja-JP')} (${r.days_since} 日前)` : r.usable ? 'まだ' : '－'), el('td', {}, sg), el('td', {}, ad), el('td', {}, az),
        el('td', {}, el('button', { class: 'btn sm', onclick: () => win.navigate(r.kind === 'web' && r.authz?.suspects ? 'authz' : 'targets', r.kind === 'web' && r.authz?.suspects ? { target: r.id } : { focus: r.id }) }, '開く'))));
    }
    c.append(el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, '対象ごとの最終確認'), el('div', { style: { overflow: 'auto' } }, t), el('div', { class: 'sub', style: { fontSize: '12px', marginTop: '6px' } }, d.note)));
  }
}
async function renderHome(c, p, win) {
  c.append(el('h1', {}, 'まもり帳'), el('p', { class: 'sub' }, '「基本的なところからザル」と言われないために。できていることを確かめて、いつ・誰が・何で確かめたかを記録に残します。責任を肩代わりはできませんが、いつでも相談できます。'));
  let s, d; try { [s, d] = await Promise.all([GET('/mamoricho/summary'), GET('/probe/security-summary')]); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  renderDashboard(c, d, win);
  const color = s.score >= 80 ? '#16a34a' : s.score >= 50 ? '#d97706' : '#dc2626';
  const top = el('div', { style: CARD });
  top.append(el('div', { class: 'row', style: { alignItems: 'baseline', gap: '12px', flexWrap: 'wrap' } }, el('span', { style: { fontSize: '40px', fontWeight: 800, color } }, s.answered ? `${s.score}` : '—'), el('span', { class: 'sub', style: { margin: 0 } }, s.answered ? `点 (100 点満点。できている=1、一部=0.5)` : 'まだ点検していません'), el('span', { style: { marginLeft: 'auto' } }, `${s.answered} / ${s.total} 項目に回答`)),
    el('div', { style: { margin: '8px 0 12px' } }, bar(s.score, color)),
    el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap' } }, ...['ok', 'partial', 'no', 'unknown', 'na', 'unanswered'].map(k => el('span', {}, pill(k), ` ${s.counts[k]}`))),
    el('div', { class: 'row', style: { marginTop: '12px', gap: '8px', flexWrap: 'wrap' } },
      el('button', { class: 'btn primary', onclick: () => win.navigate('check') }, s.answered ? '点検を続ける' : '点検を始める (15 分)'),
      el('button', { class: 'btn', onclick: () => win.navigate('targets') }, '対象を調べる'),
      el('button', { class: 'btn', onclick: () => win.navigate('emergency') }, 'もしものとき')));
  c.append(top);
  // 次にやること
  const hw = el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, '次にやること'));
  if (!s.homework.length) hw.append(el('div', { class: 'notice ok' }, '宿題はありません。四半期ごとの見直しを続けてください。'));
  for (const h of s.homework) hw.append(el('div', { class: 'row', style: { alignItems: 'flex-start', gap: '10px', padding: '8px 0', borderTop: '1px solid var(--line, #eee)' } }, pill(h.status), el('div', { style: { flex: 1 } }, el('div', {}, h.q), el('div', { class: 'sub', style: { margin: '2px 0 0', fontSize: '12px' } }, `最低ライン: ${h.min}`)), el('button', { class: 'btn sm', onclick: () => win.navigate('check', { item: h.id }) }, '答える')));
  c.append(hw);
  // 箱 (OS)の自己点検 + 見直し + 記録
  const grid = el('div', { class: 'grid', style: { gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' } });
  const selfBox = el('div', { style: { ...CARD, marginBottom: 0 } }, el('h2', { style: { marginTop: 0 } }, `${B.os}の自己点検`), el('div', { class: 'notice ' + (s.self_failed.length ? 'warn' : 'ok') }, `${s.self.ok} / ${s.self.total} が達成`), s.self_failed.length ? el('ul', { style: { margin: '6px 0 0 18px', fontSize: '13px' } }, ...s.self_failed.map(f => el('li', {}, f))) : '',
    el('div', { class: 'row', style: { marginTop: '8px', gap: '8px' } }, el('button', { class: 'btn sm', onclick: () => selfDetail(win) }, '詳しく見る'), isOp() ? el('button', { class: 'btn sm', onclick: async () => { try { await GET('/mamoricho/selfcheck?save=1'); toast('自己点検を記録に残しました', 'ok'); win.navigate('home'); } catch (e) { toast(e.message, 'err'); } } }, '記録に残す') : ''));
  const revBox = el('div', { style: { ...CARD, marginBottom: 0 } }, el('h2', { style: { marginTop: 0 } }, '見直しの周期'), el('p', {}, s.last_review_at ? `前回の見直し: ${fmtTime(s.last_review_at)}` : 'まだ一度も見直しを終えていません'), el('p', {}, s.next_review_at ? `次の見直し: ${new Date(s.next_review_at).toLocaleDateString('ja-JP')} (四半期ごと)` : '全部の項目に答えると、見直しを終えられます'), el('p', { class: 'sub', style: { fontSize: '12px' } }, '見直しのときは、アクセス権の棚卸し (誰がどこに入れるか) も一緒に。'));
  const recBox = el('div', { style: { ...CARD, marginBottom: 0 } }, el('h2', { style: { marginTop: 0 } }, '記録'), el('div', { class: 'notice ' + (s.chain.ok ? 'ok' : 'err') }, s.chain.ok ? `${s.chain.count} 件。つながりと署名は正常` : `異常: ${s.chain.reason}`), el('p', { class: 'sub', style: { fontSize: '12px' } }, '1 件ごとに前の記録のハッシュを含めて箱の鍵で署名しています。後から書き換えると分かります。'), el('button', { class: 'btn sm', onclick: () => win.navigate('records') }, '記録を見る'));
  grid.append(selfBox, revBox, recBox); c.append(grid);
  // 相談
  const ta = el('textarea', { class: 'inp', rows: 3, placeholder: '例: 「このメール、本物か分かりません」「退職者のアカウントは何から止めればいい？」', style: { width: '100%' } }); const out = el('div');
  c.append(el('div', { style: { ...CARD, marginTop: '12px' } }, el('h2', { style: { marginTop: 0 } }, '相談する'), el('p', { class: 'sub', style: { fontSize: '12px' } }, `${B.ai}に聞きます (外には出ません)。社内の規程や手順書を入れていれば、それを根拠に答えます。`), ta,
    el('div', { class: 'row', style: { marginTop: '6px' } }, el('button', { class: 'btn primary', onclick: async () => { const q = ta.value.trim(); if (!q) return; out.innerHTML = ''; out.append(el('div', { class: 'sub' }, '考えています…')); try { const r = await POST('/mamoricho/consult', { question: q, workspace_id: AIOS.state.ws || null }); out.innerHTML = ''; out.append(el('div', { class: 'notice info', style: { whiteSpace: 'pre-wrap' } }, r.answer), r.sources?.length ? el('div', { class: 'sub', style: { fontSize: '12px' } }, '根拠にした文書: ' + r.sources.map(x => x.name).join('・')) : ''); } catch (e) { out.innerHTML = ''; out.append(el('div', { class: 'notice err' }, e.message)); } } }, '聞く')), out));
}
async function selfDetail(win) {
  let r; try { r = await GET('/mamoricho/selfcheck'); } catch (e) { return toast(e.message, 'err'); }
  const t = el('table', { class: 'tbl' }, el('thead', {}, el('tr', {}, el('th', {}, ''), el('th', {}, '項目'), el('th', {}, '状態'))));
  for (const x of r.checks) t.append(el('tr', {}, el('td', {}, x.level === 'info' ? 'ℹ' : x.ok ? '✅' : '⚠'), el('td', {}, x.label), el('td', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, x.detail)));
  const c = el('div', {}, el('h2', {}, `${B.os}の自己点検`), el('p', { class: 'sub' }, '箱の設定から機械的に確かめています。未達のものは System の設定で直せます。'), t);
  modal(c);
}

// ---------- 点検 ----------
async function renderCheck(c, p, win) {
  let d; try { d = await GET('/mamoricho/checklist'); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  c.append(el('h1', {}, '点検'), el('p', { class: 'sub' }, `基準: ${d.baseline.label}。質問に、いまの状態を選んで答えます。分からなければ「分からない」でかまいません (宿題になります)。文章で答えると、AI が状態を提案します (決めるのはあなたです)。`));
  // 機械で確かめる (聞き取りとは別に、箱 (OS)が読んだものから): 管理者アカウント・操作履歴・API の権限
  c.append(el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, '機械で確かめる'), el('div', { class: 'sub', style: { fontSize: '12px', marginBottom: '8px' } }, `下の質問 (聞き取り) とは別に、${B.os}が読んだもの (ログイン履歴・監査ログ・API の応答) から機械的に確かめます。見つかっても「要確認」まで、見つからなくても安全という意味ではありません。`),
    el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap' } }, el('button', { class: 'btn', onclick: () => win.navigate('admin', { target: 'self' }) }, '🔑 管理者アカウントの点検'), el('button', { class: 'btn', onclick: () => win.navigate('admin', { tab: 'events' }) }, '📜 管理者の操作履歴を確認'), el('button', { class: 'btn', onclick: () => win.navigate('authz') }, '🔐 API の権限を確かめる'))));
  const focusItem = p?.item ? d.items.find(i => i.id === p.item) : null;
  let cat = focusItem?.cat || p?.cat || d.categories[0].id;
  const chips = el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', marginBottom: '12px' } }); const list = el('div'); c.append(chips, list);
  const draw = () => {
    chips.innerHTML = '';
    for (const k of d.categories) { const items = d.items.filter(i => i.cat === k.id); const done = items.filter(i => i.answer).length; chips.append(el('button', { class: 'btn sm' + (k.id === cat ? ' primary' : ''), title: k.ref, onclick: () => { cat = k.id; draw(); } }, `${k.label} ${done}/${items.length}`)); }
    list.innerHTML = ''; const k = d.categories.find(x => x.id === cat);
    list.append(el('div', { class: 'sub', style: { marginBottom: '8px' } }, `${k.label} — ${k.sub}。委員会の基準: ${k.ref}`));
    for (const it of d.items.filter(i => i.cat === cat)) list.append(itemCard(it, d, win));
    const allDone = d.items.every(i => i.answer);
    list.append(el('div', { style: { marginTop: '16px' } }, isOp() ? el('button', { class: 'btn' + (allDone ? ' primary' : ''), disabled: !allDone, title: allDone ? '' : 'すべての項目に答えると終えられます', onclick: async () => { const ok = await confirmDialog({ title: 'この見直しを終えますか', body: 'いまの答えを「見直し済み」として記録し、次の見直しは 3 か月後になります。', okLabel: '終える' }); if (!ok) return; try { await POST('/mamoricho/review/close', {}); toast('見直しを終えました', 'ok'); win.navigate('home'); } catch (e) { toast(e.message, 'err'); } } }, 'この見直しを終える (記録に残す)') : ''));
    if (focusItem && focusItem.cat === cat) setTimeout(() => document.getElementById('mm-' + focusItem.id)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 50);
  };
  draw();
}
function itemCard(it, d, win) {
  const a = it.answer; const card = el('div', { id: 'mm-' + it.id, style: CARD });
  const head = el('div', { class: 'row', style: { alignItems: 'flex-start', gap: '10px' } }, el('div', { style: { flex: 1 } }, el('div', { style: { fontWeight: 700, fontSize: '15px' } }, it.q), el('div', { class: 'sub', style: { margin: '4px 0 0', fontSize: '12px' } }, `なぜ: ${it.why}`)), pill(a?.status || 'unanswered'));
  const base = el('div', { style: { fontSize: '13px', margin: '8px 0', padding: '8px 10px', background: 'rgba(15,23,42,.045)', borderRadius: '8px' } }, el('div', {}, el('b', {}, '最低ライン: '), it.min), el('div', { class: 'sub', style: { margin: '2px 0 0', fontSize: '12px' } }, `推奨: ${it.rec}`), el('div', { class: 'sub', style: { margin: '2px 0 0', fontSize: '12px' } }, `確かめ方: ${it.howto}`));
  const note = el('input', { class: 'inp', value: a?.note || '', placeholder: '記録に残す一言 (例: 2026-10 に全管理者が登録済み)', style: { width: '100%' } });
  const msg = el('div');
  const save = async (status, n) => { try { const r = await POST('/mamoricho/answer', { item_id: it.id, status, note: n ?? note.value }); it.answer = { ...(it.answer || {}), status: r.status, note: r.note, evidence: r.evidence, updated_at: r.updated_at, updated_by: AIOS.state.me.id }; toast('記録しました', 'ok'); const nc = itemCard(it, d, win); card.replaceWith(nc); } catch (e) { toast(e.message, 'err'); } };
  const btns = el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', margin: '6px 0' } }, ...['ok', 'partial', 'no', 'unknown', 'na'].map(s => el('button', { class: 'btn sm' + (a?.status === s ? ' primary' : ''), disabled: !isOp(), onclick: () => save(s) }, dot(s), ST[s][0])));
  // 文章で答える → AI が状態を提案 (決めるのは人)
  const ta = el('textarea', { class: 'inp', rows: 2, placeholder: 'ふだんの言葉で答えてください。例: 「バックアップは NAS に毎晩。外には出していない」', style: { width: '100%', marginTop: '4px' } });
  const history = []; const prop = el('div');
  const ask = async () => { const text = ta.value.trim(); if (!text) return; prop.innerHTML = ''; prop.append(el('div', { class: 'sub' }, 'AI が読んでいます…')); try { const r = await POST('/mamoricho/interview', { item_id: it.id, text, history }); prop.innerHTML = ''; if (!r.proposal) return prop.append(el('div', { class: 'notice warn' }, r.note)); history.push({ role: 'user', text }); const pr = r.proposal; history.push({ role: 'assistant', text: pr.follow_up || pr.note });
    prop.append(el('div', { class: 'notice info' }, el('div', {}, 'AI の提案: ', pill(pr.status), ` (確からしさ ${Math.round(pr.confidence * 100)}%)`), el('div', { style: { marginTop: '4px' } }, pr.note), pr.tip ? el('div', { class: 'sub', style: { margin: '4px 0 0', fontSize: '12px' } }, `ひとこと: ${pr.tip}`) : '', pr.follow_up ? el('div', { style: { marginTop: '6px' } }, el('b', {}, '確認: '), pr.follow_up) : '',
      el('div', { class: 'row', style: { marginTop: '8px', gap: '6px' } }, el('button', { class: 'btn sm primary', onclick: () => save(pr.status, pr.note) }, 'この提案で記録する'), el('button', { class: 'btn sm', onclick: () => { ta.value = ''; ta.focus(); } }, pr.follow_up ? '答えを続ける' : '違う (自分で選ぶ)')))); } catch (e) { prop.innerHTML = ''; prop.append(el('div', { class: 'notice err' }, e.message)); } };
  ta.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) ask(); });
  const ev = el('div', { class: 'sub', style: { fontSize: '12px', margin: '6px 0 0' } });
  if (a?.evidence?.length) ev.append('確かめた記録: ', ...a.evidence.map(e => el('span', { class: 'tag', style: { marginRight: '4px' } }, e.label || e.ref)));
  if (a?.updated_at) ev.append(el('div', {}, `最終更新 ${fmtTime(a.updated_at)}`));
  card.append(head, base, btns, note, isOp() ? el('div', {}, ta, el('div', { class: 'row', style: { gap: '6px', marginTop: '4px' } }, el('button', { class: 'btn sm', onclick: ask }, 'AI に相談して決める'), el('button', { class: 'btn sm', onclick: () => win.navigate('targets', { item: it.id }) }, '対象で確かめる')), prop) : '', ev, msg);
  note.addEventListener('change', () => { if (it.answer) save(it.answer.status); });
  return card;
}

// ---------- 安全の仕組みと、実行前の確認 ----------
let SAFETY = null; async function safety() { if (!SAFETY) { try { SAFETY = await GET('/mamoricho/safety'); } catch { SAFETY = { items: [], not_doing: [] }; } } return SAFETY; }
// 実行前の確認: これからやること・やらないこと・出力の行き先を示し、理解してもらってから動く
async function confirmRun({ title, what, steps = [], extra = null }) {
  const sf = await safety();
  const body = el('div', {},
    el('div', { style: { fontWeight: 700, marginBottom: '4px' } }, 'これからやること'), el('div', {}, what),
    steps.length ? el('details', { style: { margin: '6px 0' } }, el('summary', { style: { cursor: 'pointer', fontSize: '13px' } }, `実行するコマンド (${steps.length} 個。すべて「読むだけ」と判定ずみ)`), el('pre', { style: { fontSize: '11px', maxHeight: '140px', overflow: 'auto', background: 'rgba(15,23,42,.045)', padding: '6px', borderRadius: '6px' } }, steps.map(a => a.join(' ')).join('\n'))) : '',
    el('div', { style: { fontWeight: 700, margin: '8px 0 4px' } }, 'やらないこと'), el('ul', { style: { margin: '0 0 0 18px', fontSize: '13px' } }, ...(sf.not_doing || []).map(x => el('li', {}, x))),
    el('div', { style: { fontWeight: 700, margin: '8px 0 4px' } }, '出力の行き先'), el('div', { style: { fontSize: '13px' } }, `パスワードや鍵に見える行を伏せ字にしてから、${B.store}に保存します。箱の外には出ません。記録は署名つきで残ります。`),
    extra ? el('div', { class: 'notice warn', style: { marginTop: '8px' } }, extra) : '',
    el('div', { class: 'sub', style: { fontSize: '12px', marginTop: '8px' } }, '仕組みの詳しい説明は「安全の仕組み」のページにあります。'));
  return confirmDialog({ title, body, okLabel: '理解して実行する' });
}
async function renderSafety(c) {
  const sf = await safety();
  c.append(el('h1', {}, '安全の仕組み'), el('p', { class: 'sub' }, 'まもり帳の調査が、調べる相手の機械を壊さず、データを外に出さない理由です。調査のたびに、この要点を確認してから動きます。'));
  for (const it of sf.items) c.append(el('div', { style: CARD }, el('div', { class: 'row', style: { alignItems: 'center', gap: '8px' } }, el('span', { style: { fontSize: '18px' } }, it.ok ? '✅' : '⚠'), el('b', { style: { fontSize: '15px' } }, it.title)), el('p', { style: { margin: '6px 0 0' } }, it.body), it.detail ? el('div', { class: 'sub', style: { margin: '4px 0 0', fontSize: '12px' } }, it.detail) : ''));
  c.append(el('div', { style: CARD }, el('b', {}, 'やらないこと'), el('ul', { style: { margin: '6px 0 0 18px' } }, ...sf.not_doing.map(x => el('li', {}, x)))));
  c.append(el('div', { class: 'notice info' }, '正直に書いておく限界: 乗っ取られた機械の上で、その機械の道具 (ps・ss など) を使って調べるため、高度な攻撃 (ルートキット) には騙されることがあります。結果は「見つからなかった」までで、「無かった」とは言いません。重い事案は、早めに専門業者へ渡すための記録を作ることを目的にしています。'));
}
// ---------- 対象 ----------
async function renderTargets(c, p, win) {
  c.append(el('h1', {}, '対象'), el('p', { class: 'sub' }, '調べてよい機械の台帳です。ここに載せたものだけを、読むだけの決まった手順で調べます。つなぐ先 (住所・ポート・利用者) は台帳の値を使うので、ほかの機械へはつなげません。'));
  let d, tpl; try { [d, tpl] = await Promise.all([GET('/probe/targets'), GET('/mamoricho/templates')]); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  if (!isOp()) { c.append(el('div', { class: 'notice info' }, '対象の登録と調査は Operator 以上が行えます。')); }
  const tools = el('div', { class: 'row', style: { gap: '8px', marginBottom: '12px' } }, isAdmin() ? el('button', { class: 'btn primary', onclick: () => addTargetWizard(win) }, '＋ 対象を追加') : '', el('button', { class: 'btn', onclick: () => runsDialog() }, '調査の履歴'));
  c.append(tools);
  if (!d.targets.length) c.append(el('div', { style: CARD }, el('h2', { style: { marginTop: 0 } }, 'はじめての方へ'), el('p', {}, '難しい設定は要りません。「対象を追加」を押すと、3 つの聞き方で案内します。'),
    el('ol', { style: { margin: '6px 0 0 18px', lineHeight: 1.8 } }, el('li', {}, el('b', {}, 'サーバー・NAS・PC: '), `${B.os}が鍵を作ります。その機械で 1 行を実行する (または業者に渡す文面を送る) と、機械の側から${B.os}につながってきます。IP アドレスを調べる必要はありません。`), el('li', {}, el('b', {}, '会社のホームページ: '), 'アドレス (例: www.example.jp) を入れて、自社のものだと申告するだけです。'), el('li', {}, el('b', {}, 'ルーターなどの機器: '), '同じネットワークで見つかった機器から選べます。SSH で入れないものは、NetOps の台帳 (SNMP) で見ます。'))));
  // 公開 HP・API の対象は、API の権限検査の状態 (API 定義・テスト用の主体・承認) も台帳に出す
  const azs = Object.fromEntries(await Promise.all(d.targets.filter(t => t.kind === 'web').map(async t => [t.id, await GET('/probe/authz/status?target_id=' + encodeURIComponent(t.id)).catch(() => null)])));
  for (const t of d.targets) {
    const card = el('div', { id: 'mt-' + t.id, style: CARD });
    const state = t.revoked_at ? '権限を取り消し済み' : t.pending ? '1 行の実行を待っています' : t.excluded ? '除外中' : '調べられる';
    card.append(el('div', { class: 'row', style: { alignItems: 'baseline', gap: '10px', flexWrap: 'wrap' } }, el('b', { style: { fontSize: '15px' } }, t.name), el('span', { class: 'tag' }, KIND[t.kind] || t.kind), el('span', { class: 'sub', style: { margin: 0 } }, `${t.host}:${t.port}${t.username ? ' / ' + t.username : ''}`), el('span', { style: { marginLeft: 'auto', fontSize: '12px', color: t.pending ? '#d97706' : t.revoked_at || t.excluded ? '#6b7280' : '#16a34a' } }, state)),
      el('div', { class: 'sub', style: { fontSize: '12px', margin: '4px 0' } }, `資格: ${t.has_credential ? '登録済み' + (t.credential_expires_at ? ` (期限 ${new Date(t.credential_expires_at).toLocaleDateString('ja-JP')})` : '') : 'なし'} ・ 公開鍵 ${t.host_keys} 件${t.kind === 'ssh' ? (t.root_read ? ' ・ root の読み取り: 決まったコマンドだけ' : ' ・ root の読み取り: なし') : ''}${t.notes ? ' ・ ' + t.notes : ''}`));
    if (t.kind === 'ssh') card.append(el('div', { class: 'sub', style: { fontSize: '12px', margin: '0 0 4px' } }, `管理者の操作ログ: ${t.root_read ? '読める (root の認証ログ・鍵・sudo)' : '一部だけ (ログイン履歴。root の読み取り無し)'} ・ 管理者アカウントの点検は「まとめて診断」に含まれます`));
    if (t.kind === 'web') { const az = azs[t.id]; card.append(el('div', { class: 'sub', style: { fontSize: '12px', margin: '0 0 4px' } }, 'API の権限検査: ' + (az ? `API 定義 ${az.has_spec ? `あり (${az.operations} 操作)` : 'なし'} ・ テスト用アカウント ${az.actors.total} 件${az.actors.missing_credential ? ` (資格なし ${az.actors.missing_credential})` : ''} ・ 承認 ${az.pending_plan ? ({ pending: '待ち', approved: '済み (実行できます)' }[az.pending_plan.approval_state] || az.pending_plan.approval_state) : az.last_run ? `済み (最終 ${new Date(az.last_run.at).toLocaleDateString('ja-JP')}${az.suspects ? `・疑い ${az.suspects}` : ''})` : '未'}` : '読めません'))); }
    const row = el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap' } });
    const usable = !t.revoked_at && !t.excluded && !t.pending && isOp();
    if (t.pending && isAdmin()) row.append(el('button', { class: 'btn sm primary', onclick: async () => { try { const r = await POST(`/probe/targets/${t.id}/enroll/renew`, {}); enrollWaitDialog(win, { target_id: t.id, name: t.name, ...r }); } catch (e) { toast(e.message, 'err'); } } }, '1 行をもう一度表示'));
    if (!t.pending && !t.revoked_at && t.kind === 'ssh' && t.verify && isAdmin()) row.append(el('button', { class: 'btn sm', title: 'まもり帳の版が上がって root の読むだけの手順が増えたとき、同じ機械でもう一度 1 行を実行すると sudoers が今の版に更新されます (ユーザーと鍵はそのまま)', onclick: async () => { try { const r = await POST(`/probe/targets/${t.id}/enroll/renew`, {}); enrollWaitDialog(win, { target_id: t.id, name: t.name, ...r }); } catch (e) { toast(e.message, 'err'); } } }, '登録の 1 行をもう一度 (root の手順を更新)'));
    if (!t.pending && usable) row.append(el('button', { class: 'btn sm', onclick: async () => { const m = modal(el('div', {}, el('h2', {}, `${t.name} につながるか確かめています…`))); try { const r = await POST(`/probe/targets/${t.id}/test`, {}); m.close?.(); modal(el('div', {}, el('h2', {}, t.name), el('div', { class: 'notice ' + (r.ok ? 'ok' : 'err') }, r.message), r.output ? el('pre', { style: { fontSize: '11px', maxHeight: '160px', overflow: 'auto' } }, r.output) : '')); } catch (e) { m.close?.(); toast(e.message, 'err'); } } }, 'つながるか確かめる'));
    for (const x of tpl.templates.filter(x => x.kind.includes(t.kind) && !x.incident && !x.params)) row.append(el('button', { class: 'btn sm', disabled: !usable, onclick: () => runTemplate(t, x, p?.item || null) }, x.label));
    if (!t.pending) {
      // まとめて診断 (スナップショット) / 乗っ取りの兆候 (気休め程度、SSH だけ) / 履歴と比較。個別のボタンは畳む
      card.append(el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', margin: '6px 0 8px' } },
        el('button', { class: 'btn sm primary', disabled: !usable, onclick: () => runSetUI(t, 'full') }, t.kind === 'web' ? '🧾 まとめて診断 (改ざん・設定不備の兆候つき)' : t.kind === 'network' ? '🧾 まとめて診断 (設定の写しと変化)' : '🧾 まとめて診断 (スナップショット)'),
        t.kind === 'ssh' ? el('button', { class: 'btn sm', disabled: !usable, onclick: () => runSetUI(t, 'compromise') }, '🕵 乗っ取り・トロイの木馬・管理者の兆候 (気休め程度)') : '',
        t.kind === 'web' ? el('button', { class: 'btn sm', disabled: !usable, onclick: () => win.navigate('authz', { target: t.id }) }, '🔐 API の権限を確かめる') : '',
        el('button', { class: 'btn sm', onclick: () => snapshotsDialog(t) }, '📚 履歴と前回との比較')));
      const more = el('details', {}); more.append(el('summary', { style: { cursor: 'pointer', fontSize: '12px', color: '#6b7280' } }, '個別に調べる (1 つずつ)'), row); card.append(more);
    } else card.append(row);
    // 3 つの違い: 「しばらく調べない」= 台帳に残して調査だけ止める (戻せる) / 「預かった権限を返した」= 社外から借りた資格情報を先方が取り消したことを記録する (借りた権限がある対象だけ) / 「台帳から消す」= 行ごと消す (履歴は残る)
    if (isAdmin()) card.append(el('div', { class: 'row', style: { gap: '6px', marginTop: '8px', alignItems: 'center' } },
      el('button', { class: 'btn sm', title: t.excluded ? 'まとめて診断と個別の調査の対象に戻します' : '台帳には残したまま、まとめて診断と個別の調査の対象から外します (プリンタや工場の機器など触りたくないもの、しばらく止めたいとき)。いつでも戻せます', onclick: async () => { try { await PATCH(`/probe/targets/${t.id}`, { excluded: !t.excluded }); win.navigate('targets', p); } catch (e) { toast(e.message, 'err'); } } }, t.excluded ? '調査の対象に戻す' : 'しばらく調べない (除外)'),
      t.borrowed && !t.revoked_at ? el('button', { class: 'btn sm', title: '社外から預かった一時的な権限 (ホスティングやクラウドの読み取りアカウントなど) を、先方が取り消したことを記録します。金庫の資格情報を消し、取り消した日が記録に残ります。この対象はもう調べられなくなります', onclick: async () => { const ok = await confirmDialog({ title: '預かった権限を「返した」と記録しますか', body: `${t.name} の資格情報は社外から預かったものです。先方で権限が取り消されたことを確かめてから押してください。<br>・箱の金庫から資格情報を消します<br>・取り消した日を記録 (署名つき) に残します<br>・この対象はもう調べられなくなります (必要なら、改めて権限をもらって追加し直します)`, okLabel: '返したと記録する' }); if (!ok) return; try { await POST(`/probe/targets/${t.id}/revoke`, { revoked: true }); win.navigate('targets', p); } catch (e) { toast(e.message, 'err'); } } }, '預かった権限を返した') : '',
      el('button', { class: 'btn sm danger', title: '台帳から消します。調査の履歴と記録は残ります', onclick: async () => { const ok = await confirmDialog({ title: `${t.name} を台帳から消しますか`, body: '台帳からだけ消します。これまでの調査の履歴と記録は残ります。<br>しばらく止めたいだけなら「しばらく調べない (除外)」のほうが、戻せるので安全です。', okLabel: '台帳から消す', danger: true }); if (!ok) return; try { await DEL(`/probe/targets/${t.id}`); win.navigate('targets', p); } catch (e) { toast(e.message, 'err'); } } }, '台帳から消す'),
      t.revoked_at ? el('span', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, `預かった権限は ${new Date(t.revoked_at).toLocaleDateString('ja-JP')} に返しました`) : ''));
    c.append(card);
  }
  if (p?.focus) setTimeout(() => document.getElementById('mt-' + p.focus)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50);
  async function runTemplate(t, x, item) {
    const ok = await confirmRun({ title: `${t.name}: ${x.label}`, what: `${t.name} (${t.host}) で、下のコマンドを読むだけで実行します。何も変えません。`, steps: x.steps }); if (!ok) return;
    const m = modal(el('div', {}, el('h2', {}, `${t.name}: ${x.label}`), el('p', { class: 'sub' }, '読むだけの手順を、使い捨てのコンテナから実行しています…'), el('div', { class: 'sub', style: { fontSize: '12px' } }, x.steps.map(s => s.join(' ')).join(' / '))));
    try { const r = await POST('/mamoricho/probe/run', { target_id: t.id, template_id: x.id, item_id: item }); m.close?.(); showRun(r, item); } catch (e) { m.close?.(); document.getElementById('modal').classList.add('hidden'); toast(e.message, 'err'); }
  }
  function showRun(r, item) {
    const okN = r.results.filter(x => x.exit_code === 0).length;
    const c2 = el('div', {}, el('h2', {}, `${r.target.name}: ${r.template}`), el('div', { class: 'notice ok', style: { fontSize: '13px' } }, `この調査でやったこと: ${r.results.length} 個のコマンドを読むだけで実行 (読めたのは ${okN} 個)。設定やファイルは変えていません。出力は伏せ字にして箱の中に保存し、記録 ${r.record_id} に署名つきで残しました。`));
    for (const x of r.results) c2.append(el('div', { style: { margin: '8px 0' } }, el('div', { style: { fontFamily: 'monospace', fontSize: '12px', fontWeight: 700 } }, `$ ${x.argv.join(' ')}`, x.error ? el('span', { style: { color: '#dc2626', fontWeight: 400 } }, `  (${x.error})`) : el('span', { class: 'sub', style: { margin: 0, fontWeight: 400 } }, `  (終了 ${x.exit_code})`)), x.output !== undefined ? el('pre', { style: { maxHeight: '220px', overflow: 'auto', fontSize: '11px', background: 'rgba(15,23,42,.045)', padding: '8px', borderRadius: '6px' } }, x.output || '(出力なし)') : ''));
    c2.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px', marginTop: '8px' } }, item ? el('button', { class: 'btn', onclick: () => { document.getElementById('modal').classList.add('hidden'); win.navigate('check', { item }); } }, '点検の項目に戻る') : '', el('button', { class: 'btn primary', onclick: () => document.getElementById('modal').classList.add('hidden') }, '閉じる')));
    modal(c2);
  }
  async function runsDialog() {
    let r; try { r = await GET('/probe/runs?limit=100'); } catch (e) { return toast(e.message, 'err'); }
    const names = Object.fromEntries(d.targets.map(t => [t.id, t.name]));
    const t = el('table', { class: 'tbl' }, el('thead', {}, el('tr', {}, el('th', {}, '日時'), el('th', {}, '対象'), el('th', {}, 'コマンド'), el('th', {}, '判定'), el('th', {}, '結果'))));
    for (const x of r.runs) t.append(el('tr', {}, el('td', {}, fmtTime(x.created_at)), el('td', {}, names[x.target_id] || x.target_id), el('td', { style: { fontFamily: 'monospace', fontSize: '12px' } }, x.argv.join(' ').slice(0, 60)), el('td', {}, { read: '読むだけ', change: '要承認', forbidden: '不可' }[x.class] || x.class), el('td', {}, { done: `終了 ${x.exit_code}`, awaiting_approval: '承認待ち', running: '実行中', error: 'エラー' }[x.state] || x.state)));
    modal(el('div', {}, el('h2', {}, '調査の履歴'), el('p', { class: 'sub', style: { fontSize: '12px' } }, 'すべての実行は監査ログにも残ります。'), r.runs.length ? t : el('div', { class: 'notice info' }, 'まだありません')));
  }
}
// 追加のウィザード: 何を調べたいかを 3 つの絵柄から選ぶ → それぞれの最短の道
async function addTargetWizard(win) {
  const choice = (icon, title, body, fn) => el('button', { class: 'btn', style: { display: 'block', width: '100%', textAlign: 'left', padding: '12px 14px', margin: '6px 0', whiteSpace: 'normal', lineHeight: 1.5 }, onclick: fn }, el('div', { style: { fontSize: '15px', fontWeight: 700 } }, `${icon} ${title}`), el('div', { class: 'sub', style: { margin: '2px 0 0', fontSize: '12px' } }, body));
  const c = el('div', {}, el('h2', {}, '何を調べますか'), el('p', { class: 'sub' }, '当てはまるものを 1 つ選んでください。あとで増やせます。'));
  const m = modal(c); const close = () => { m.close?.(); document.getElementById('modal').classList.add('hidden'); };
  c.append(choice('🖥', 'サーバー・NAS・PC (Linux)', `${B.os}が鍵を作ります。その機械で 1 行を実行するだけ。IP アドレスを調べる必要はありません。`, () => { close(); enrollStep(win); }),
    choice('🌐', '会社のホームページ', 'アドレスを入れるだけ (例: www.example.jp)。外から見える状態を確かめます。', () => { close(); webStep(win); }),
    choice('📡', 'ルーター・ネットワーク機器', '同じネットワークで見つかった機器から選びます。', () => { close(); discoverStep(win, 'network'); }),
    choice('🤔', 'どれか分からない', '同じネットワークにある機械を探して、見つかったものから選びます。', () => { close(); discoverStep(win, null); }));
  c.append(el('div', { style: { marginTop: '10px', textAlign: 'right', fontSize: '12px' } }, el('a', { href: '#', onclick: (e) => { e.preventDefault(); close(); addTargetAdvanced(win); } }, '詳しい設定 (IP と鍵を自分で入れる)')));
}
async function enrollStep(win, preset = {}) {
  const name = el('input', { class: 'inp', value: preset.name || '', placeholder: '呼び名 (例: 経理サーバー)。空なら機械の名前が入ります', style: { width: '100%' } });
  const rootRead = el('input', { type: 'checkbox', checked: true });
  const c = el('div', {}, el('h2', {}, 'サーバー・NAS・PC をつなぐ'), el('p', { class: 'sub' }, `「準備する」を押すと、${B.os}が鍵を作って 1 行を表示します。その 1 行を、調べたい機械で root として実行してください (自分で実行できなければ、業者に渡す文面も出ます)。`), preset.host ? el('div', { class: 'notice info' }, `見つかった機械: ${preset.host}${preset.name ? ` (${preset.name})` : ''}。この機械で 1 行を実行してください。`) : '', el('label', { class: 'lbl' }, '呼び名'), name,
    el('label', { style: { display: 'flex', gap: '8px', alignItems: 'flex-start', marginTop: '10px', fontSize: '13px' } }, rootRead, el('span', {}, 'root でしか読めないもの (root の鍵・sudo の設定・認証ログ) も読めるようにする (推奨)', el('div', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, 'あらかじめ決めた読むだけのコマンドだけを sudoers に完全一致で書きます。任意のコマンドは動かせません。'))));
  const m = modal(c);
  c.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px', marginTop: '12px' } }, el('button', { class: 'btn', onclick: () => { m.close?.(); document.getElementById('modal').classList.add('hidden'); } }, 'やめる'), el('button', { class: 'btn primary', onclick: async () => {
    m.close?.(); document.getElementById('modal').classList.add('hidden');
    const ok = await confirmDialog({ title: '鍵を作って、つなぐ準備をします', body: '秘密鍵は箱の金庫に入り、画面には出ません。', okLabel: '準備する', reauth: true }); if (!ok) return;
    try { const r = await POST('/probe/enroll', { name: name.value.trim(), kind: 'ssh', root_read: rootRead.checked, notes: preset.host ? `見つかった機械 ${preset.host}` : '' }, { reauth: ok.reauth }); enrollWaitDialog(win, { target_id: r.target_id, name: name.value.trim() || '登録中の機械', ...r }); } catch (e) { toast(e.message, 'err'); }
  } }, '準備する')));
}
function enrollWaitDialog(win, r) {
  const copy = async (t, msg) => { try { await navigator.clipboard.writeText(t); toast(msg, 'ok'); } catch { toast('写せませんでした。選んで写してください', 'err'); } };
  const status = el('div', { class: 'notice info' }, '⏳ 1 行の実行を待っています… (この画面を閉じても待ち続けます。期限は 24 時間)');
  const c = el('div', {}, el('h2', {}, `${r.name}: この 1 行を、${r.reenroll ? 'もう一度その機械で' : 'その機械で'}実行してください`), r.reenroll ? el('div', { class: 'notice info', style: { fontSize: '12px' } }, '登録のやり直しです。ユーザー mamoricho と鍵はそのままで、root の読むだけの手順 (sudoers) が今の版に更新されます。別の機械で実行しても (SSH の公開鍵が違うので) 受け付けません。') : '', el('div', { style: { fontSize: '13px', margin: '4px 0 8px' } }, el('div', {}, el('b', {}, 'やること: '), `読み取り専用のユーザー mamoricho を作る (パスワード無し・鍵だけ・ポート転送なし・端末なし) / ${B.os}の公開鍵を置く / root の読み取りを許した場合は、決まった読むだけのコマンドだけを sudoers に完全一致で書く / ${B.os}に「つながった」と知らせる`), el('div', {}, el('b', {}, 'やらないこと: '), '設定の書き換え・ファイルの削除・サービスの停止・ソフトの導入'), el('div', {}, el('b', {}, '消し方: '), el('code', {}, 'userdel -r mamoricho; rm -f /etc/sudoers.d/mamoricho'))),
    el('pre', { style: { fontSize: '13px', padding: '10px', background: 'rgba(15,23,42,.06)', borderRadius: '8px', userSelect: 'all', whiteSpace: 'pre-wrap', wordBreak: 'break-all' } }, r.one_liner),
    el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap' } }, el('button', { class: 'btn primary', onclick: () => copy(r.one_liner, '1 行を写しました') }, '1 行を写す'), el('button', { class: 'btn', onclick: () => copy(r.vendor_message, '業者に渡す文面を写しました') }, '業者に渡す文面を写す'), el('a', { class: 'btn', href: r.script_url, target: '_blank' }, '中身を見る')),
    el('div', { style: { marginTop: '10px' } }, status));
  const m = modal(c); let timer = setInterval(async () => { try { const d = await GET('/probe/targets'); const t = d.targets.find(x => x.id === r.target_id); const done = r.reenroll ? (t && t.updated_at && t.updated_at !== r.wait_key) : (t && !t.pending); if (done) { clearInterval(timer); status.className = 'notice ok'; status.textContent = r.reenroll ? `✅ 更新されました: ${t.name} (${t.host})。root の手順が今の版になりました。` : `✅ つながりました: ${t.name} (${t.host})。「つながるか確かめる」で読み取りを試せます。`; win.navigate('targets'); } } catch { /* 次回 */ } }, 3000);
  const prevClose = m.close; m.close = () => { clearInterval(timer); prevClose?.(); };
  c.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', marginTop: '10px' } }, el('button', { class: 'btn', onclick: () => { clearInterval(timer); document.getElementById('modal').classList.add('hidden'); win.navigate('targets'); } }, '閉じる (待ち続けます)')));
}
async function webStep(win) {
  const host = el('input', { class: 'inp', placeholder: 'www.example.jp', style: { width: '100%' } }); const att = el('input', { type: 'checkbox' }); const name = el('input', { class: 'inp', placeholder: '呼び名 (例: 会社サイト)', style: { width: '100%' } });
  const c = el('div', {}, el('h2', {}, '会社のホームページを調べる'), el('p', { class: 'sub' }, '外から見える状態 (証明書・セキュリティのヘッダ・出てはいけないファイル) を、決まった場所に 1 回ずつ見に行くだけです。'), el('label', { class: 'lbl' }, 'アドレス'), host, el('label', { class: 'lbl' }, '呼び名'), name,
    el('label', { style: { display: 'flex', gap: '8px', alignItems: 'flex-start', marginTop: '10px', fontSize: '13px' } }, att, el('span', {}, 'このサイトは自社のもの (または調査を頼まれたもの) です。他人のサイトは調べません。', el('div', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, '誰が申告したかが記録に残ります。'))));
  const m = modal(c);
  c.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px', marginTop: '12px' } }, el('button', { class: 'btn', onclick: () => { m.close?.(); document.getElementById('modal').classList.add('hidden'); } }, 'やめる'), el('button', { class: 'btn primary', onclick: async () => {
    const h = host.value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, ''); if (!h) return toast('アドレスを入れてください', 'err'); if (!att.checked) return toast('自社のものだと申告してください', 'err');
    m.close?.(); document.getElementById('modal').classList.add('hidden');
    const ok = await confirmDialog({ title: `${h} を対象に追加します`, body: '追加のあと「つながるか確かめる」で応答を見ます。', okLabel: '追加する', reauth: true }); if (!ok) return;
    try { await POST('/probe/targets', { name: name.value.trim() || h, kind: 'web', host: h, port: 443, attested: true }, { reauth: ok.reauth }); toast('追加しました', 'ok'); win.navigate('targets'); } catch (e) { toast(e.message, 'err'); }
  } }, '追加する')));
}
async function discoverStep(win, kindFilter) {
  const list = el('div', {}, el('div', { class: 'sub' }, '同じネットワークの機械を探しています (10 秒ほど)…'));
  const c = el('div', {}, el('h2', {}, kindFilter === 'network' ? 'ルーター・ネットワーク機器' : '見つかった機械'), el('p', { class: 'sub', style: { fontSize: '12px' } }, `${B.os}と同じネットワークで応答のあった機械です。選ぶと、その機械のつなぎ方を案内します。`), list);
  const m = modal(c); const close = () => { m.close?.(); document.getElementById('modal').classList.add('hidden'); };
  try {
    const d = await GET('/probe/discover'); list.innerHTML = '';
    const rows = d.candidates.filter(x => !kindFilter || x.kind_hint === kindFilter || x.sources.includes('netops'));
    if (!rows.length) list.append(el('div', { class: 'notice info' }, `見つかりませんでした。機械の電源が入っていて、${B.os}と同じネットワークにあるか確かめてください。NetOps に機器を登録しておくと、ここに出ます。`));
    for (const x of rows) {
      const ports = [x.ports?.ssh ? 'SSH' : null, x.ports?.https ? 'https' : null, x.ports?.http ? 'http' : null].filter(Boolean).join('・') || '応答なし';
      list.append(el('div', { class: 'row', style: { alignItems: 'center', gap: '8px', padding: '6px 0', borderTop: '1px solid var(--line, #eee)' } }, el('div', { style: { flex: 1 } }, el('b', {}, x.name || x.host), el('div', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, `${x.host} ・ ${ports}${x.vendor ? ' ・ ' + x.vendor : ''}${x.sources.includes('netops') ? ' ・ NetOps の台帳' : ''}${x.registered ? ' ・ 登録済み' : ''}`)),
        x.registered ? el('span', { class: 'tag' }, '登録済み') : x.ports?.ssh ? el('button', { class: 'btn sm primary', onclick: () => { close(); enrollStep(win, { name: x.name || '', host: x.host }); } }, 'SSH で 1 行登録') : x.ports?.https || x.ports?.http ? el('button', { class: 'btn sm', onclick: () => { close(); webStep(win); } }, 'Web として') : el('button', { class: 'btn sm', onclick: () => { close(); addTargetAdvanced(win, { host: x.host, name: x.name || '' }); } }, '詳しい設定')));
    }
  } catch (e) { list.innerHTML = ''; list.append(el('div', { class: 'notice err' }, e.message)); }
  c.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', marginTop: '10px' } }, el('button', { class: 'btn', onclick: close }, '閉じる')));
}
function addTargetAdvanced(win, preset = {}) {
  const f = { name: el('input', { class: 'inp', value: preset.name || '', placeholder: '名前 (例: 経理サーバー)' }), kind: el('select', { class: 'inp' }, ...Object.entries(KIND).map(([v, l]) => el('option', { value: v }, l))), host: el('input', { class: 'inp', value: preset.host || '', placeholder: 'IP アドレスか名前 (例: 192.168.1.20 / www.example.jp)' }), port: el('input', { class: 'inp', placeholder: 'ポート (SSH 22 / https 443)', style: { width: '160px' } }), username: el('input', { class: 'inp', placeholder: '調査用のアカウント (読み取り専用)' }),
    secret_kind: el('select', { class: 'inp', style: { width: 'auto' } }, el('option', { value: 'key' }, '秘密鍵 (推奨)'), el('option', { value: 'password' }, 'パスワード')), secret: el('textarea', { class: 'inp', rows: 3, placeholder: '秘密鍵 (-----BEGIN … の全文) かパスワード。箱の金庫に暗号化して保存し、画面には出ません', style: { width: '100%', fontFamily: 'monospace', fontSize: '11px' } }),
    days: el('input', { class: 'inp', type: 'number', min: 1, max: 365, placeholder: '期限 (日)。社外からの一時的な権限は必ず', style: { width: '200px' } }), notes: el('input', { class: 'inp', placeholder: 'メモ (誰からもらった権限か、など)' }) };
  const hint = el('div', { class: 'notice info', style: { fontSize: '12px' } }, '先方には読み取り専用のアカウントを作ってもらってください (Linux: sudo を付けない一般ユーザー / 公開 HP: 持ち主であることを確かめてから)。');
  const c = el('div', {}, el('h2', {}, '対象を追加 (詳しい設定)'), hint, el('div', { class: 'grid', style: { gridTemplateColumns: '1fr 1fr', gap: '8px' } }, f.name, f.kind, f.host, f.port, f.username, f.secret_kind), f.secret, el('div', { class: 'row', style: { gap: '8px', marginTop: '6px' } }, f.days, f.notes));
  const m = modal(c);
  c.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px', marginTop: '12px' } }, el('button', { class: 'btn', onclick: () => { m.close?.(); document.getElementById('modal').classList.add('hidden'); } }, 'やめる'), el('button', { class: 'btn primary', onclick: async () => {
    const body = { name: f.name.value.trim(), kind: f.kind.value, host: f.host.value.trim(), port: f.port.value ? Number(f.port.value) : undefined, username: f.username.value.trim() || undefined, secret: f.secret.value.trim() || undefined, secret_kind: f.secret_kind.value, notes: f.notes.value.trim(), credential_expires_at: f.days.value ? new Date(Date.now() + Number(f.days.value) * 86400e3).toISOString() : null, attested: f.kind.value === 'web' };
    if (!body.host) return toast('住所を入れてください', 'err');
    m.close?.(); document.getElementById('modal').classList.add('hidden');
    const ok = await confirmDialog({ title: '対象を追加します', body: `${body.host} の公開鍵を記録し、資格情報を金庫に入れます。`, okLabel: '追加する', reauth: true }); if (!ok) return;
    try { await POST('/probe/targets', body, { reauth: ok.reauth }); toast('追加しました', 'ok'); win.navigate('targets'); } catch (e) { toast(e.message, 'err'); }
  } }, '追加する')));
}

// ---------- 記録 ----------
async function renderRecords(c, p, win) {
  c.append(el('h1', {}, '記録'), el('p', { class: 'sub' }, '点検の答え・自己点検・調査・見直し・もしものときの記録が、時間の順に 1 本の鎖になっています。1 件ごとに前の記録のハッシュを含めて箱の鍵で署名しているので、後から書き換えると分かります。'));
  let d; try { d = await GET('/mamoricho/records?limit=300'); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  c.append(el('div', { class: 'notice ' + (d.chain.ok ? 'ok' : 'err') }, d.chain.ok ? `${d.chain.count} 件。つながりと署名は正常です` : `異常: ${d.chain.reason} (${d.chain.broken_at} 件目)`));
  c.append(el('div', { class: 'row', style: { gap: '8px', marginBottom: '8px' } }, isAdmin() ? el('button', { class: 'btn sm', onclick: () => { const blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), chain: d.chain, records: d.records }, null, 2)], { type: 'application/json' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mamoricho-records-${new Date().toISOString().slice(0, 10)}.json`; a.click(); } }, 'JSON で書き出す (管理者)') : ''));
  const KINDS = { answer: '点検の答え', selfcheck: '自己点検', probe: '調査', review: '見直しを終えた', emergency_card: 'もしものときのカード', incident_note: '初動の記録', incident_probe: '初動の調査', snapshot: 'スナップショット', inquiry: '対話で調べた', admin_compromise_signs: `管理者の点検 (${B.os}自身)`, admin_event_analysis: '管理者の AI 説明', api_authz_spec: 'API の一覧', api_authz_policy_change: 'API の期待する権限', api_authz_scan: 'API の権限検査', api_authz_finding: 'API の権限の疑い' };
  const t = el('table', { class: 'tbl' }, el('thead', {}, el('tr', {}, el('th', {}, '#'), el('th', {}, '日時'), el('th', {}, '誰が'), el('th', {}, '種類'), el('th', {}, '内容'))));
  for (const r of d.records) {
    const pl = r.payload || {}; let body = '';
    if (r.kind === 'answer') body = el('span', {}, pill(pl.status), ' ', el('code', { style: { fontSize: '11px' } }, pl.item_id), pl.note ? ` — ${pl.note}` : '');
    else if (r.kind === 'selfcheck') body = `${pl.summary?.ok}/${pl.summary?.total} 達成`;
    else if (r.kind === 'probe') body = `${pl.target_name}: ${pl.template_id} (${(pl.runs || []).length} 手順)`;
    else if (r.kind === 'incident_note') body = pl.text;
    else if (r.kind === 'inquiry') body = `${pl.title || pl.url || (pl.text_excerpt || '').slice(0, 40)}: ${pl.conclusion?.conclusion?.slice(0, 80) || pl.summary?.slice(0, 80) || ''}`;
    else if (r.kind === 'snapshot') body = `${pl.target_name}: ${pl.set_label}${pl.totals ? ` ・ 兆候 ${pl.totals.warn || 0} 疑い / ${pl.totals.check || 0} 確認 ・ 前回比 +${pl.totals.added || 0} / -${pl.totals.removed || 0} 行` : ''}`;
    else if (r.kind === 'incident_probe') body = `${pl.target_name}: ${pl.baseline ? `前回と比べて +${(pl.sections || []).reduce((n, x) => n + x.added, 0)} / -${(pl.sections || []).reduce((n, x) => n + x.removed, 0)} 行` : '基準を作成'}`;
    else if (r.kind === 'review') body = pl.note || '全項目に回答';
    else if (r.kind === 'admin_compromise_signs') body = `${pl.target_name}: 疑い ${pl.warn || 0} / 確認 ${pl.check || 0}${pl.baseline ? ' (今回が基準)' : ''}${(pl.unavailable || []).length ? ` ・ 確認できず ${pl.unavailable.length}` : ''}`;
    else if (r.kind === 'admin_event_analysis') body = `${pl.target_name}: ${(pl.analysis?.summary || '').slice(0, 100)} → ${pl.analysis?.conclusion || '要確認'}`;
    else if (r.kind === 'api_authz_scan') body = `${pl.target_name}: ${pl.totals?.requests || 0} リクエスト ・ 疑い ${pl.totals?.suspect || 0} / 判断できない ${pl.totals?.unclear || 0} / 退行 ${pl.totals?.regressions || 0}`;
    else if (r.kind === 'api_authz_finding') body = `${pl.target_name}: ${pl.check} ${pl.check_label || ''} — ${pl.method} ${pl.url_path} (${pl.actor_label}) ${pl.reason || ''}`;
    else if (r.kind === 'api_authz_policy_change') body = `${pl.target_name}: 版 ${pl.version} (${(pl.changes || []).length} 件の変更)${pl.note ? ' — ' + pl.note : ''}`;
    else if (r.kind === 'api_authz_spec') body = `${pl.target_name}: ${pl.operations} 操作 (${pl.source === 'openapi' ? 'OpenAPI' : '手書き'})`;
    else body = JSON.stringify(pl).slice(0, 120);
    t.append(el('tr', {}, el('td', {}, r.seq), el('td', {}, fmtTime(r.at)), el('td', {}, r.by_name), el('td', {}, KINDS[r.kind] || r.kind), el('td', {}, body)));
  }
  c.append(d.records.length ? t : el('div', { class: 'notice info' }, 'まだ記録がありません。'));
}

// ---------- もしものとき ----------
// ---- セット (まとめて診断 / 兆候 / 初動) の結果とスナップショットの描画 (生の結果も、記録から読んだものも同じ形で) ----
const SET_HOWTO = {
  full: { what: (t, n) => t.kind === 'web' ? `${t.name} (https://${t.host}) に、決まった場所へ 1 回ずつ見に行くだけです (GET/HEAD、${n} の型)。書き込み・ログインの試行・総当たりはしません。検索エンジン名義 (Googlebot) でも 1 回だけトップページを見ます (乗っ取られた HP が検索エンジンにだけ別の内容を見せる「偽装」の確認。自社の HP だから できることです)。DNS は dig で読むだけ。終わるとスナップショットとして残り、前回と「構造の変化」(外部スクリプト・送り先・証明書・向き先) で比べます。` : t.kind === 'network' ? `${t.name} (${t.host}) に show 命令 (読むだけ) を順に流し、設定の写しをスナップショットとして残して前回と比べます。設定は変えません。機種により無い命令は「この機械には無い」で済みます。` : `${t.name} (${t.host}) で、ふつうの点検の型と乗っ取りの兆候のセット (合わせて ${n} の型、すべて読むだけ) を順に流します。何も変えません・止めません。終わるとスナップショットとして残り、前回の記録と比べます。`, extra: (t) => t.kind === 'web' ? '正直に: 外から見える範囲 (トップページ・決まった場所・DNS) だけの、気休め程度の確認です。見つからなくても「安全」とは言えません (中身の改ざんは巧妙に隠れますし、ログインの先は見ていません)。それでも、分かりやすい改ざんや設定の抜けはこれで引っかかるので、定期的に流して前回との変化を見るのが現実的な守りです。' : null, wait: (n) => `⏳ まとめて診断を流しています (${n} の型、1〜5 分)…` },
  compromise: { what: (t, n) => `${t.name} (${t.host}) で、乗っ取り・トロイの木馬のよくある手口の痕跡 (${n} の型、すべて読むだけ) を探します。何も変えません・止めません。`, extra: '正直に: これは気休め程度の確認です。見つからなくても「安全」とは言えません (巧妙なものは隠れますし、ここで分かるのは一部です)。それでも、分かりやすい手口はこれで引っかかるので、やらないよりはやったほうがよい、くらいの気持ちで使ってください。本当に疑わしいときは「もしものとき」の初動の調査と、専門業者への相談を。', wait: (n) => `⏳ 兆候を探しています (${n} の型、2〜3 分)…` },
  incident: { what: (t, n) => `消えやすいものから順に、${n} の型 (読むだけ) を流します。何も変えません・止めません。前回の記録があれば、増えたものを先に出します。`, extra: '調べる前に: 疑わしい機械の電源は切らない (手がかりが消えます)。切り離すのは人が判断してください。', wait: (n) => `⏳ 初動セットを流しています (${n} の型、1〜3 分)…` },
};
const stepsOfSec = (sec) => sec.results || sec.steps || [];
function renderSigns(out, signs) {
  if (!signs) return;
  const box = el('div', { style: { margin: '8px 0 10px', padding: '10px 12px', border: '1px solid ' + (signs.warn ? '#dc2626' : signs.check ? '#d97706' : '#16a34a'), borderRadius: '10px', background: signs.warn ? 'rgba(220,38,38,.05)' : signs.check ? 'rgba(217,119,6,.06)' : 'rgba(22,163,74,.05)' } });
  box.append(el('div', { style: { fontWeight: 700 } }, `🕵 ${signs.title || '乗っ取り・トロイの木馬の兆候'} (気休め程度の、機械的な目安)`));
  box.append(el('div', { class: 'sub', style: { fontSize: '12px', margin: '2px 0 8px' } }, signs.note));
  if (!signs.signs.length) box.append(el('div', {}, '✅ 分かりやすい兆候は見つかりませんでした。', el('span', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, ' (=「安全」ではありません。よくある手口は見当たらなかった、という意味です。定期的に流して、前回との差分を見るのが現実的な守りです)')));
  for (const x of signs.signs) {
    const d = el('details', { style: { margin: '4px 0' }, ...(x.level === 'warn' ? { open: true } : {}) });
    d.append(el('summary', { style: { cursor: 'pointer' } }, el('span', { style: { color: x.level === 'warn' ? '#dc2626' : '#d97706', fontWeight: 700 } }, x.level === 'warn' ? '⚠ 疑い: ' : '👀 確認: '), x.label, el('span', { class: 'sub', style: { margin: '0 0 0 6px', fontSize: '12px' } }, `${x.count} 件`)));
    d.append(el('div', { class: 'sub', style: { fontSize: '12px', margin: '2px 0 4px' } }, x.why), el('pre', { style: { fontSize: '11px', background: 'rgba(15,23,42,.045)', padding: '6px', borderRadius: '6px', maxHeight: '140px', overflow: 'auto', margin: 0 } }, x.lines.join('\n') + (x.count > x.lines.length ? `\n… ほか ${x.count - x.lines.length} 件` : '')));
    box.append(d);
  }
  out.append(box);
}
// 管理者の点検の補足 (スナップショットに admin があるとき): 基準かどうか・確認できなかった項目・操作履歴と AI の説明への入口
function renderAdminExtras(out, r) {
  const a = r.signs?.admin || r.admin; if (!a) return;
  const box = el('div', { style: { margin: '0 0 10px', padding: '8px 12px', border: '1px dashed var(--line, #ccc)', borderRadius: '10px', fontSize: '13px' } });
  box.append(el('div', { style: { fontWeight: 700 } }, `🔑 管理者アカウントの点検 ${a.baseline ? '(今回が基準。次回から「増えた」が分かります)' : `(前回 ${a.since ? fmtTime(a.since) : ''} からのイベント ${a.events_in_window || 0} 件)`}`));
  if (a.unavailable?.length) box.append(el('div', { class: 'sub', style: { fontSize: '12px', margin: '4px 0 0' } }, '確認できなかった項目 (= 問題なし ではありません): ', ...a.unavailable.map(u => el('div', { style: { marginLeft: '12px' } }, `${u.rule_id} ${u.label} — ${u.reason}`))));
  const tid = r.target_id || r.target?.id; if (tid) box.append(el('div', { style: { marginTop: '6px' } }, el('button', { class: 'btn sm', onclick: () => { document.getElementById('modal').classList.add('hidden'); openWindow('mamoricho', { route: 'admin', params: { target: tid } }); } }, '管理者の点検・操作履歴・AI の説明を開く')));
  out.append(box);
}
function renderSnapshot(out, r, { compare = false } = {}) {
  const secs = r.sections || []; const allN = secs.reduce((n, s) => n + stepsOfSec(s).length, 0), okN = secs.reduce((n, s) => n + stepsOfSec(s).filter(x => x.exit_code === 0).length, 0);
  out.append(el('div', { class: 'notice ' + (r.baseline ? 'warn' : 'info') }, r.note, r.record_id ? ` 記録 ${r.record_id}` : r.id ? ` 記録 ${r.id}` : ''));
  if (!compare) out.append(el('div', { class: 'notice ok', style: { fontSize: '13px' } }, `この調査でやったこと: ${allN} 個のコマンドを読むだけで実行 (読めたのは ${okN} 個)。設定やファイルは変えていません。出力は伏せ字にして箱の中に保存しました。`));
  renderSigns(out, r.signs);
  renderAdminExtras(out, r);
  if (r.common_added?.length) out.append(el('div', { class: 'notice err' }, el('b', {}, 'どのコマンドにも出る行 (機械全体の異常のサイン。仕込みや壊れた設定のおそれ): '), el('pre', { style: { margin: '4px 0 0', fontSize: '11px', whiteSpace: 'pre-wrap' } }, r.common_added.join('\n'))));
  if (r.common_removed?.length) out.append(el('div', { class: 'notice' }, el('b', {}, '前回はどのコマンドにも出ていたが、今回は消えた行 (直した・消えたなら問題なし): '), el('pre', { style: { margin: '4px 0 0', fontSize: '11px', whiteSpace: 'pre-wrap' } }, r.common_removed.join('\n'))));
  const summary = r.summary || secs.map(sec => ({ label: sec.label, added: stepsOfSec(sec).reduce((n, x) => n + (x.added_count ?? x.diff?.added_count ?? 0), 0), removed: stepsOfSec(sec).reduce((n, x) => n + (x.removed_count ?? x.diff?.removed_count ?? 0), 0) }));
  const hot = summary.filter(x => x.added > 0 || x.removed > 0);
  if (r.baseline) out.append(el('div', { style: { margin: '8px 0' } }, el('b', {}, hot.length ? '前回と変わったところ: ' : '前回と変わったところはありません (正規化して比べた範囲で)'), ...hot.map(x => el('span', { class: 'tag', style: { marginRight: '4px' } }, `${x.label} +${x.added}/-${x.removed}`))));
  if (r.digest_diff?.length) { const bx = el('div', { class: 'notice warn' }, el('b', {}, '構造の変化 (前回のスナップショットと比べて): ')); for (const d of r.digest_diff) bx.append(el('div', { style: { fontSize: '12px', margin: '2px 0' } }, `${d.label}: `, d.added || d.removed ? [d.added?.length ? el('span', { style: { color: '#dc2626' } }, `増えた ${d.added.join(', ')} `) : '', d.removed?.length ? el('span', { style: { color: '#6b7280' } }, `消えた ${d.removed.join(', ')}`) : ''] : `${d.from ?? '(なし)'} → ${d.to ?? '(なし)'}`)); out.append(bx); }
  else if (r.digest && r.baseline) out.append(el('div', { class: 'sub', style: { fontSize: '12px' } }, '構造 (外部スクリプト・送り先・証明書・向き先・タイトル) は前回から変わっていません'));
  const stale = secs.flatMap(stepsOfSec).filter(x => x.stale_sudoers).length;
  if (stale) out.append(el('div', { class: 'notice warn', style: { fontSize: '12px' } }, `root の手順のうち ${stale} 個は、この対象を登録したあとに増えたものです。対象の機械で登録の 1 行をもう一度実行すると (「1 行をもう一度表示」)、読めるようになります。`));
  for (const sec of secs) {
    const steps = stepsOfSec(sec).map(x => ({ ...x, diff: x.diff || (x.added_count != null ? { added: x.added || [], removed: x.removed || [], added_count: x.added_count, removed_count: x.removed_count, truncated: x.truncated } : null) }));
    const box = el('details', { style: { margin: '6px 0', border: '1px solid var(--line, #eee)', borderRadius: '8px', padding: '6px 10px' }, ...(steps.some(x => x.diff?.added_count) ? { open: true } : {}) });
    const add = steps.reduce((n, x) => n + (x.diff?.added_count || 0), 0), rem = steps.reduce((n, x) => n + (x.diff?.removed_count || 0), 0);
    const okS = steps.filter(x => x.exit_code === 0).length, rootN = steps.filter(x => x.needs_root || x.stale_sudoers).length;
    box.append(el('summary', { style: { cursor: 'pointer', fontWeight: 700 } }, sec.label, sec.error ? el('span', { style: { color: '#dc2626', fontWeight: 400 } }, ` (${sec.error})`) : '', add || rem ? el('span', { style: { color: add ? '#dc2626' : '#6b7280', fontWeight: 400, marginLeft: '8px' } }, `+${add} / -${rem}`) : '', el('span', { class: 'sub', style: { margin: '0 0 0 8px', fontWeight: 400, fontSize: '12px' } }, `読めた ${okS}/${steps.length}${rootN ? ` ・ root が要る ${rootN}` : ''}`)));
    for (const x of steps) {
      box.append(el('div', { style: { fontFamily: 'monospace', fontSize: '12px', margin: '6px 0 2px', opacity: x.needs_root || (x.exit_code && x.exit_code !== 0) ? .7 : 1 } }, `$ ${(x.argv || []).join(' ')}`, x.needs_root ? el('span', { style: { color: '#d97706' } }, '  (root の権限が要る)') : x.error ? el('span', { style: { color: '#dc2626' } }, `  (${x.error})`) : x.no_pair ? el('span', { style: { color: '#6b7280' } }, '  (古い側に同じ手順が無い)') : el('span', { class: 'sub', style: { margin: 0 } }, `  (終了 ${x.exit_code})${x.exit_code && x.exit_code !== 0 ? (x.partial ? ' 一部は読めなかった (読めた分は出ています)' : ' この機械には無いか、読めなかった') : ''}`)));
      if (x.diff?.truncated) box.append(el('div', { class: 'muted', style: { fontSize: '11px' } }, '出力が長いので、記録に残す先頭 200KB だけを前回と比べました'));
      if (x.diff?.added?.length) box.append(el('div', { style: { fontSize: '12px', fontWeight: 700, color: '#dc2626' } }, `増えた (${x.diff.added_count}):`), el('pre', { style: { fontSize: '11px', background: 'rgba(220,38,38,.06)', padding: '6px', borderRadius: '6px', maxHeight: '160px', overflow: 'auto' } }, x.diff.added.join('\n')));
      if (x.diff?.removed?.length) box.append(el('div', { style: { fontSize: '12px', fontWeight: 700, color: '#6b7280' } }, `消えた (${x.diff.removed_count}):`), el('pre', { style: { fontSize: '11px', background: 'rgba(15,23,42,.045)', padding: '6px', borderRadius: '6px', maxHeight: '120px', overflow: 'auto' } }, x.diff.removed.join('\n')));
      if (x.output !== undefined) box.append(el('details', {}, el('summary', { style: { fontSize: '12px', cursor: 'pointer' } }, '出力を見る'), el('pre', { style: { fontSize: '11px', maxHeight: '220px', overflow: 'auto', background: 'rgba(15,23,42,.045)', padding: '6px', borderRadius: '6px' } }, x.output || '(出力なし)')));
      else if (x.run_id) { const pre = el('pre', { style: { fontSize: '11px', maxHeight: '220px', overflow: 'auto', background: 'rgba(15,23,42,.045)', padding: '6px', borderRadius: '6px' } }); const dd = el('details', { ontoggle: async () => { if (!dd.open || pre.textContent) return; pre.textContent = '読んでいます…'; try { const o = await GET(`/probe/runs/${x.run_id}/output`); pre.textContent = o.output || '(出力なし)'; } catch (e) { pre.textContent = e.message; } } }, el('summary', { style: { fontSize: '12px', cursor: 'pointer' } }, '出力を見る (記録から)'), pre); box.append(dd); }
    }
    out.append(box);
  }
}
async function runSetUI(t, set) {
  let sets; try { sets = (await GET(`/mamoricho/sets?kind=${encodeURIComponent(t.kind)}`)).sets; } catch (e) { toast(e.message, 'err'); return; }
  const def = sets.find(x => x.id === set); const how = SET_HOWTO[set]; const n = def?.count || 0;
  const ok = await confirmRun({ title: `${t.name}: ${def?.label || set}`, what: how.what(t, n), extra: typeof how.extra === 'function' ? how.extra(t) : (how.extra || null) }); if (!ok) return;
  const m = modal(el('div', {}, el('h2', {}, `${t.name}: ${def?.label || set}`), el('p', { class: 'sub' }, how.wait(n)), el('p', { class: 'sub', style: { fontSize: '12px' } }, '読むだけの手順を、使い捨てのコンテナから順に実行しています。この画面は閉じても構いません (結果は記録に残ります)。')));
  try { const r = await POST('/mamoricho/set/run', { target_id: t.id, set }); m.close?.(); showSnapshot(r, `${t.name}: ${def?.label || set}`); }
  catch (e) { m.close?.(); document.getElementById('modal').classList.add('hidden'); toast(e.message, 'err'); }
}
function showSnapshot(r, title, opts = {}) {
  const c2 = el('div', {}, el('h2', {}, title)); renderSnapshot(c2, r, opts);
  c2.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px', marginTop: '8px' } }, el('button', { class: 'btn primary', onclick: () => document.getElementById('modal').classList.add('hidden') }, '閉じる')));
  modal(c2);
}
async function snapshotsDialog(t) {
  let rows; try { rows = (await GET(`/mamoricho/snapshots?target_id=${encodeURIComponent(t.id)}&limit=100`)).snapshots; } catch (e) { toast(e.message, 'err'); return; }
  const c2 = el('div', {}, el('h2', {}, `${t.name}: スナップショットの履歴`), el('p', { class: 'sub', style: { fontSize: '12px' } }, 'まとめて診断・兆候・初動セットの実行はスナップショットとして残ります。1 つを開くと、そのときの前回との差分と出力が見られます。2 つを選ぶと、その間に何が変わったかを出力どうしで比べます。'));
  if (!rows.length) { c2.append(el('div', { class: 'notice info' }, 'まだありません。「まとめて診断」を流すと、それが最初の基準になります。')); }
  else {
    const cmp = rows.filter(x => x.comparable);
    if (cmp.length >= 2 && isOp()) {
      const selA = el('select', { class: 'inp' }), selB = el('select', { class: 'inp' });
      for (const x of cmp) { const lab = `${new Date(x.at).toLocaleString('ja-JP')} ${x.set_label}`; selA.append(el('option', { value: x.id }, lab)); selB.append(el('option', { value: x.id }, lab)); }
      selA.value = cmp[1].id; selB.value = cmp[0].id;
      const res = el('div');
      c2.append(el('div', { style: { padding: '8px 10px', border: '1px solid var(--line, #eee)', borderRadius: '8px', margin: '6px 0 10px' } }, el('div', { style: { fontWeight: 700, marginBottom: '4px' } }, '2 つを比べる'), el('div', { class: 'row', style: { gap: '6px', alignItems: 'center', flexWrap: 'wrap' } }, el('span', { class: 'sub', style: { margin: 0 } }, '古い:'), selA, el('span', { class: 'sub', style: { margin: 0 } }, '→ 新しい:'), selB, el('button', { class: 'btn sm primary', onclick: async () => { res.innerHTML = ''; res.append(el('div', { class: 'sub' }, '比べています…')); try { const r = await GET(`/mamoricho/snapshots/compare?a=${encodeURIComponent(selA.value)}&b=${encodeURIComponent(selB.value)}`); res.innerHTML = ''; renderSnapshot(res, r, { compare: true }); } catch (e) { res.innerHTML = ''; res.append(el('div', { class: 'notice err' }, e.message)); } } }, '比べる')), res));
    }
    const tbl = el('table', { class: 'tbl' }); tbl.append(el('tr', {}, el('th', {}, '日時'), el('th', {}, '種類'), el('th', {}, '読めた'), el('th', {}, '前回比'), el('th', {}, '兆候'), el('th', {}, '')));
    for (const x of rows) tbl.append(el('tr', {}, el('td', {}, new Date(x.at).toLocaleString('ja-JP')), el('td', {}, x.set_label), el('td', {}, `${x.totals?.ok ?? '-'}/${x.totals?.steps ?? '-'}`), el('td', {}, x.baseline ? `+${x.totals?.added || 0} / -${x.totals?.removed || 0}` : '基準'), el('td', {}, x.totals?.warn ? el('span', { style: { color: '#dc2626', fontWeight: 700 } }, `疑い ${x.totals.warn}`) : '', x.totals?.check ? el('span', { style: { color: '#d97706', marginLeft: '4px' } }, `確認 ${x.totals.check}`) : '', !x.totals?.warn && !x.totals?.check && x.set !== 'incident' ? el('span', { class: 'sub', style: { margin: 0 } }, 'なし') : ''), el('td', {}, x.comparable ? el('button', { class: 'btn sm', onclick: async () => { try { const r = await GET(`/mamoricho/snapshots/${encodeURIComponent(x.id)}`); showSnapshot(r, `${t.name}: ${x.set_label} (${new Date(x.at).toLocaleString('ja-JP')})`); } catch (e) { toast(e.message, 'err'); } } }, '開く') : '')));
    c2.append(tbl);
  }
  c2.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', marginTop: '8px' } }, el('button', { class: 'btn', onclick: () => document.getElementById('modal').classList.add('hidden') }, '閉じる')));
  modal(c2);
}

// ---- 対話で調べる: ニュースの URL や新しい情報 → 箱の AI が下読み → 台帳の対象に関係するか → 読むだけの型を提案 → 承認して実行 → 見立て ----
const VERDICT = { '該当のおそれ': '#dc2626', '該当しない': '#16a34a', '分からない': '#d97706' };
function renderInquiryView(box, it, { win, templates, targets, onChange }) {
  box.innerHTML = '';
  const art = el('div', { style: CARD });
  art.append(el('div', { style: { fontWeight: 700 } }, '📰 持ってきた情報'), el('div', { class: 'sub', style: { fontSize: '12px', margin: '2px 0' } }, it.title ? `${it.title}` : '', it.final_url ? el('div', {}, el('a', { href: it.final_url, target: '_blank', rel: 'noopener' }, it.final_url)) : ''), it.text_excerpt ? el('pre', { style: { fontSize: '11px', whiteSpace: 'pre-wrap', maxHeight: '120px', overflow: 'auto', background: 'rgba(15,23,42,.045)', padding: '6px', borderRadius: '6px', margin: '4px 0 0' } }, it.text_excerpt + (it.article_chars > it.text_excerpt.length ? `\n… (全 ${it.article_chars} 文字。AI には全文を渡しました)` : '')) : '');
  box.append(art);
  if (it.note) box.append(el('div', { class: 'notice warn' }, it.note));
  if (it.plan) {
    const pl = it.plan; const sev = { high: ['#dc2626', '高'], medium: ['#d97706', '中'], low: ['#16a34a', '低'], unknown: ['#6b7280', '不明'] }[pl.severity] || ['#6b7280', '不明'];
    const rel = { yes: ['#dc2626', '関係ありそう'], maybe: ['#d97706', '関係するかもしれない'], no: ['#16a34a', '関係なさそう'] }[pl.relevance] || ['#6b7280', '判断できない'];
    const pb = el('div', { style: CARD });
    pb.append(el('div', { style: { fontWeight: 700 } }, '🤖 箱の AI の下読み ', el('span', { class: 'sub', style: { margin: 0, fontWeight: 400, fontSize: '12px' } }, '(目安です。記事の読み違いや、台帳に無い機械の見落としがあります)')),
      el('div', { style: { margin: '6px 0' } }, pl.summary || ''),
      el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', margin: '4px 0' } }, el('span', { class: 'tag', style: { borderColor: sev[0], color: sev[0] } }, `深刻さ: ${sev[1]}`), el('span', { class: 'tag', style: { borderColor: rel[0], color: rel[0] } }, `台帳との関係: ${rel[1]}`), ...(pl.products || []).map(x => el('span', { class: 'tag' }, x))),
      pl.reason ? el('div', { class: 'sub', style: { fontSize: '12px' } }, pl.reason) : '');
    if (pl.advice?.length) pb.append(el('div', { style: { marginTop: '6px', fontSize: '13px' } }, el('b', {}, '調べなくても言えること: '), el('ul', { style: { margin: '2px 0 0 18px' } }, ...pl.advice.map(a => el('li', {}, a)))));
    box.append(pb);
    const pending = (pl.checks || []).filter(c => !c.done);
    const cb = el('div', { style: CARD });
    cb.append(el('div', { style: { fontWeight: 700 } }, `🔍 確かめる手順 (${(pl.checks || []).length} 個、すべて読むだけの決まった型)`), el('div', { class: 'sub', style: { fontSize: '12px' } }, 'AI は一覧にある型と対象からしか選べず、コマンドは作れません。実行の前にもう一度、やること・やらないことを確認します。'));
    if (!(pl.checks || []).length) cb.append(el('div', { class: 'notice info' }, '流せる手順はありません (台帳の対象に関係しない、または型が無い)。「調べなくても言えること」を参考にしてください。'));
    for (const c of pl.checks || []) cb.append(el('div', { style: { padding: '6px 0', borderTop: '1px solid var(--line, #eee)', fontSize: '13px' } }, el('div', {}, c.done ? '✅ ' : '▫ ', el('b', {}, c.target_name), ' に ', el('span', { class: 'tag' }, c.template_label), c.params && Object.keys(c.params).length ? el('span', { class: 'sub', style: { margin: '0 0 0 6px', fontSize: '12px' } }, Object.entries(c.params).map(([k, v]) => `${k}=${v}`).join(' ')) : ''), el('div', { class: 'sub', style: { fontSize: '12px', margin: '2px 0 0 18px' } }, c.why || ''), c.dropped ? el('div', { style: { color: '#dc2626', fontSize: '12px', marginLeft: '18px' } }, `(外しました: ${c.dropped})`) : ''));
    if (pending.length && isOp()) cb.append(el('div', { style: { marginTop: '8px' } }, el('button', { class: 'btn primary', onclick: async () => {
      const steps = pending.flatMap(c => (c.steps || []));
      const ok = await confirmRun({ title: `対話で調べる: ${pending.length} 個の手順`, what: `${[...new Set(pending.map(c => c.target_name))].join('・')} で、下のコマンドを読むだけで実行します。何も変えません。結果は箱の AI が記事と突き合わせて見立てを書きます (目安)。`, steps }); if (!ok) return;
      const m = modal(el('div', {}, el('h2', {}, '調べています…'), el('p', { class: 'sub' }, `${pending.length} 個の手順を順に流し、AI が見立てを書きます (1〜3 分)`)));
      try { const r = await POST(`/mamoricho/inquiry/${encodeURIComponent(it.id)}/run`, {}); m.close?.(); document.getElementById('modal').classList.add('hidden'); onChange(r); } catch (e) { m.close?.(); document.getElementById('modal').classList.add('hidden'); toast(e.message, 'err'); }
    } }, `この手順で調べる (${pending.length} 個)`)));
    box.append(cb);
  }
  if (it.results?.length) {
    const rb = el('div', { style: CARD }); rb.append(el('div', { style: { fontWeight: 700 } }, '📋 調べた結果'));
    for (const r of it.results) { const d = el('details', { style: { margin: '4px 0' } }); d.append(el('summary', { style: { cursor: 'pointer', fontSize: '13px' } }, `${r.target_name}: ${r.template_label}`, el('span', { class: 'sub', style: { margin: '0 0 0 6px', fontSize: '12px' } }, `読めた ${r.ok}/${r.steps.length}`, r.record_id ? ` ・ 記録 ${r.record_id}` : ''))); for (const x of r.steps) d.append(el('div', { style: { fontFamily: 'monospace', fontSize: '12px', margin: '4px 0 0' } }, `$ ${x.argv.join(' ')}`, el('span', { class: 'sub', style: { margin: 0 } }, x.error ? ` (${x.error})` : ` (終了 ${x.exit_code})`)), el('pre', { style: { fontSize: '11px', maxHeight: '160px', overflow: 'auto', background: 'rgba(15,23,42,.045)', padding: '6px', borderRadius: '6px', margin: '2px 0' } }, x.output || '(出力なし)')); rb.append(d); }
    box.append(rb);
  }
  if (it.conclusion) {
    const c = it.conclusion; const kb = el('div', { style: { ...CARD, borderColor: '#2563eb' } });
    kb.append(el('div', { style: { fontWeight: 700 } }, '🧭 見立て ', el('span', { class: 'sub', style: { margin: 0, fontWeight: 400, fontSize: '12px' } }, '(箱の AI が記事と結果を突き合わせた目安。版の読み方は配布元で違う (Debian は古い版番号のまま直されることがある) ので、最後は配布元の案内で確かめてください)')), el('div', { style: { margin: '6px 0' } }, c.conclusion || ''));
    if (c.affected?.length) { const tb = el('table', { class: 'tbl' }); tb.append(el('tr', {}, el('th', {}, '対象'), el('th', {}, '見立て'), el('th', {}, '根拠'))); for (const a of c.affected) tb.append(el('tr', {}, el('td', {}, a.target_name), el('td', { style: { color: VERDICT[a.verdict] || '#6b7280', fontWeight: 700 } }, a.verdict), el('td', { style: { fontSize: '12px' } }, a.evidence || ''))); kb.append(tb); }
    if (c.next_steps?.length) kb.append(el('div', { style: { marginTop: '6px', fontSize: '13px' } }, el('b', {}, '次にすること: '), el('ul', { style: { margin: '2px 0 0 18px' } }, ...c.next_steps.map(a => el('li', {}, a)))));
    box.append(kb);
  }
  if (it.messages?.length) { const mb = el('div', { style: CARD }); mb.append(el('div', { style: { fontWeight: 700 } }, '💬 やりとり')); for (const m of it.messages) mb.append(el('div', { style: { margin: '4px 0', fontSize: '13px', padding: '6px 8px', borderRadius: '8px', background: m.role === 'user' ? 'rgba(37,99,235,.08)' : 'rgba(15,23,42,.045)' } }, el('b', {}, m.role === 'user' ? 'あなた: ' : 'AI: '), m.text)); box.append(mb); }
  if (it.plan && isOp()) {
    const ta = el('textarea', { class: 'inp', rows: 2, placeholder: '続けて聞く (例: a16 も同じ? / この版なら大丈夫? / ほかに確かめるべき機械は?)', style: { width: '100%' } });
    box.append(el('div', { style: CARD }, ta, el('div', { style: { marginTop: '6px' } }, el('button', { class: 'btn', onclick: async () => { const text = ta.value.trim(); if (!text) return; ta.disabled = true; try { const r = await POST(`/mamoricho/inquiry/${encodeURIComponent(it.id)}/ask`, { text }); onChange(r); } catch (e) { toast(e.message, 'err'); ta.disabled = false; } } }, '聞く'))));
  }
}
async function renderInquiry(c, p, win) {
  c.append(el('h1', {}, '対話で調べる'), el('p', { class: 'sub' }, 'ニュースの URL や、聞いた話を入れると、箱の AI が読んで、台帳の機械に関係するかを考え、確かめるための「読むだけの型」を提案します。実行はあなたが承認してから。結果と記事を突き合わせた見立ても AI が書きます (目安)。'));
  if (!isOp()) { c.append(el('div', { class: 'notice info' }, 'Operator 以上が使えます。')); return; }
  const url = el('input', { class: 'inp', placeholder: 'https://… (ニュース・注意喚起・配布元の案内のアドレス)', style: { width: '100%' } });
  const text = el('textarea', { class: 'inp', rows: 3, placeholder: '文章でも構いません (例: 取引先から「○○ の脆弱性で情報漏えい」と聞いた。うちの機械は関係ある?)', style: { width: '100%' } });
  const out = el('div'); const list = el('div');
  const go = async () => {
    const u = url.value.trim(), t = text.value.trim(); if (!u && !t) { toast('アドレスか文章を入れてください', 'err'); return; }
    if (u) { const ok = await confirmDialog({ title: `このアドレスを${B.os}から読みに行きます`, body: `${u}\n\n・${B.os}の使い捨てコンテナから 1 回だけ読みます (書き込みやログインはしません)\n・社内の住所 (192.168.x.x など) は読みません\n・読んだ文章は箱の中の AI が下読みします。外のサービスには送りません\n・台帳の機械にはまだ何もしません (提案を見てから、あなたが承認します)`, okLabel: '読みに行く' }); if (!ok) return; }
    out.innerHTML = ''; out.append(el('div', { class: 'notice info' }, '⏳ 読んで考えています… (記事の取得と AI の下読みで 20〜60 秒)'));
    try { const r = await POST('/mamoricho/inquiry', { url: u || null, text: t || null }); show(r); url.value = ''; text.value = ''; loadList(); } catch (e) { out.innerHTML = ''; out.append(el('div', { class: 'notice err' }, e.message)); }
  };
  const show = (it) => renderInquiryView(out, it, { win, onChange: show });
  c.append(el('div', { style: CARD }, el('label', { class: 'lbl' }, 'アドレス'), url, el('label', { class: 'lbl' }, '文章 (アドレスと一緒でも、文章だけでも)'), text, el('div', { style: { marginTop: '8px' } }, el('button', { class: 'btn primary', onclick: go }, '読んで考える'))), out, el('h2', {}, 'これまでに調べたもの'), list);
  const loadList = async () => { try { const r = await GET('/mamoricho/inquiries'); list.innerHTML = ''; if (!r.inquiries.length) { list.append(el('div', { class: 'sub' }, 'まだありません')); return; } const tb = el('table', { class: 'tbl' }); tb.append(el('tr', {}, el('th', {}, '日時'), el('th', {}, '情報'), el('th', {}, '状態'), el('th', {}, ''))); for (const x of r.inquiries) tb.append(el('tr', {}, el('td', {}, new Date(x.at).toLocaleString('ja-JP')), el('td', {}, x.title || x.url || x.text_excerpt?.slice(0, 40) || ''), el('td', {}, x.has_conclusion || x.state === 'done' ? (x.pending ? '見立てあり・追加の提案あり' : '見立てあり') : x.pending ? `提案あり (${x.pending} 個、未実行)` : '提案なし'), el('td', {}, x.live ? el('button', { class: 'btn sm', onclick: async () => { try { show(await GET(`/mamoricho/inquiry/${encodeURIComponent(x.id)}`)); window.scrollTo(0, 0); } catch (e) { toast(e.message, 'err'); } } }, '開く') : el('span', { class: 'sub', style: { margin: 0 } }, '記録に残っています')))); list.append(tb); } catch (e) { list.innerHTML = ''; list.append(el('div', { class: 'notice err' }, e.message)); } };
  loadList();
}

async function renderEmergency(c, p, win) {
  c.append(el('h1', {}, 'もしものとき'), el('p', { class: 'sub' }, 'やられたと分かったときに開くページです。印刷して見える所にも置いてください。'));
  let d; try { d = await GET('/mamoricho/emergency'); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  const steps = [['落ち着く。電源は切らない', '電源を切ると、何が起きたかの手がかり (メモリの中身) が消えます。再起動・削除・駆除ソフトの実行もまだしない。'], ['ネットワークから切り離す', '疑わしい機械の LAN ケーブルを抜く・Wi-Fi を切る。社内全体なら、インターネットとの境目 (ルーター・VPN) を止める。'], ['アカウントを止める', '疑わしいアカウントのパスワードを変える・無効にする。管理者のパスワードも。'], ['連絡する', '下の連絡先の順に。専門業者 (フォレンジック) と、保険に入っていれば保険会社。'], ['記録する', 'いつ・誰が・何に気づき・何をしたかを、このページの「初動の記録」に残す (時刻つき)。'], ['報告の期限を確かめる', '個人データが漏れたおそれがあれば、個人情報保護委員会へ速報 (おおむね 3〜5 日) と確報 (30 日・不正アクセスは 60 日)、本人への通知。']];
  const ol = el('div', { style: CARD }); steps.forEach(([h, b], i) => ol.append(el('div', { style: { display: 'flex', gap: '12px', padding: '8px 0', borderTop: i ? '1px solid var(--line, #eee)' : 'none' } }, el('div', { style: { width: '32px', height: '32px', borderRadius: '50%', background: '#dc2626', color: '#fff', display: 'grid', placeItems: 'center', fontWeight: 800, flexShrink: 0 } }, i + 1), el('div', {}, el('div', { style: { fontWeight: 700, fontSize: '15px' } }, h), el('div', { class: 'sub', style: { margin: '2px 0 0' } }, b)))));
  c.append(el('h2', {}, '最初の 6 つ'), ol);
  // 初動で確かめること (管理者監視と API 検査から)。あくまで読むだけ。止める・消す・遮断するのは人が判断する
  c.append(el('div', { style: CARD }, el('b', {}, '初動で確かめること (読むだけ。勝手に止めない・消さない・遮断しない)'), el('ul', { style: { margin: '6px 0 0 18px', fontSize: '13px', lineHeight: 1.7 } }, el('li', {}, '多要素認証の手段が勝手に増えていないか (管理者の点検 ADMIN-04)'), el('li', {}, '新しい管理者・API キー・鍵が作られていないか (ADMIN-01 / 02 / 08)'), el('li', {}, '権限のない API アクセスが成功していないか (API の権限検査)'), el('li', {}, '大量のデータ取得の履歴がないか (この版では取れる対象が限られます。取れないものは「確認できなかった」)')),
    el('div', { class: 'row', style: { gap: '6px', marginTop: '8px', flexWrap: 'wrap' } }, el('button', { class: 'btn sm', onclick: () => win.navigate('admin', { target: 'self' }) }, '🔑 管理者の点検を開く'), el('button', { class: 'btn sm', onclick: () => win.navigate('authz') }, '🔐 API の権限を開く'))));
  // 連絡先
  const ct = d.settings.contacts || {}; const F = [['lead', '責任者 (経営層)'], ['it', '実務の担当者'], ['vendor', 'システム保守の会社'], ['forensics', '専門業者 (フォレンジック)'], ['insurance', 'サイバー保険'], ['police', '警察 (都道府県警のサイバー犯罪相談窓口)'], ['ppc', '個人情報保護委員会 (漏えい等報告フォーム)']];
  const inputs = {}; const box = el('div', { style: CARD });
  for (const [k, l] of F) { inputs[k] = el('input', { class: 'inp', value: ct[k] || '', placeholder: '名前・電話・メール', disabled: !isAdmin(), style: { width: '100%' } }); box.append(el('label', { class: 'lbl' }, l), inputs[k]); }
  const notes = el('textarea', { class: 'inp', rows: 2, value: d.settings.notes || '', placeholder: '補足 (例: 夜間は○○へ、鍵の置き場所)', disabled: !isAdmin(), style: { width: '100%' } }); box.append(el('label', { class: 'lbl' }, '補足'), notes);
  if (isAdmin()) box.append(el('div', { style: { marginTop: '8px' } }, el('button', { class: 'btn primary', onclick: async () => { const contacts = Object.fromEntries(F.map(([k]) => [k, inputs[k].value.trim()])); try { await PUT('/mamoricho/emergency', { contacts, notes: notes.value.trim() }); toast('連絡先を保存しました (記録にも残ります)', 'ok'); } catch (e) { toast(e.message, 'err'); } } }, '保存')));
  c.append(el('h2', {}, '連絡先'), box);
  // 期限
  const date = el('input', { class: 'inp', type: 'date', value: new Date().toISOString().slice(0, 10), style: { width: 'auto' } }); const dl = el('div');
  const calc = async () => { try { const r = await GET(`/mamoricho/deadlines?discovered_at=${date.value}`); dl.innerHTML = ''; dl.append(el('dl', { class: 'kv' }, el('dt', {}, r.prompt_report.label), el('dd', {}, `${r.prompt_report.from} 〜 ${r.prompt_report.to}`), el('dt', {}, r.final_report.label), el('dd', {}, r.final_report.to), el('dt', {}, r.final_report_malicious.label), el('dd', {}, r.final_report_malicious.to), el('dt', {}, '本人への通知'), el('dd', {}, r.notify_subjects))); } catch (e) { toast(e.message, 'err'); } };
  date.addEventListener('change', calc); calc();
  c.append(el('h2', {}, '報告の期限'), el('div', { style: CARD }, el('div', { class: 'row', style: { gap: '8px', alignItems: 'center' } }, '発覚した日: ', date), dl, el('p', { class: 'sub', style: { fontSize: '12px' } }, '個人情報保護法 26 条の漏えい等報告。期限は目安なので、迷ったら早めに。')));
  // 初動の記録
  const ta = el('textarea', { class: 'inp', rows: 2, placeholder: '例: 10:05 経理 PC で身代金の表示に気づく。LAN ケーブルを抜いた (田中)', style: { width: '100%' } }); const list = el('div');
  const drawNotes = () => { list.innerHTML = ''; for (const n of d.notes) list.append(el('div', { style: { padding: '6px 0', borderTop: '1px solid var(--line, #eee)', fontSize: '13px' } }, el('span', { class: 'sub', style: { margin: 0 } }, `${fmtTime(n.at)} ${n.by_name}: `), n.payload?.text)); if (!d.notes.length) list.append(el('div', { class: 'sub' }, 'まだ記録はありません。')); };
  drawNotes();
  // 初動の調査: 対象を選んで初動セットを流し、前回の記録との差分を見る
  const incBox = el('div', { style: CARD }); c.append(el('h2', {}, '初動の調査 (仕込まれていないか・何が増えたか)'), incBox);
  (async () => {
    let tg = []; try { tg = (await GET('/probe/targets')).targets.filter(t => t.kind === 'ssh' && !t.pending && !t.excluded && !t.revoked_at); } catch { /* 下で案内 */ }
    if (!isOp()) { incBox.append(el('div', { class: 'notice info' }, '初動の調査は Operator 以上が行えます。')); return; }
    if (!tg.length) { incBox.append(el('div', { class: 'notice info' }, '調べられるサーバー・PC がまだありません。「対象」で追加してください (平時に一度流しておくと、有事に「何が増えたか」が分かります)。')); return; }
    const sel = el('select', { class: 'inp', style: { width: 'auto' } }, ...tg.map(t => el('option', { value: t.id }, `${t.name} (${t.host})`))); const out = el('div');
    incBox.append(el('p', { class: 'sub', style: { fontSize: '12px' } }, '消えやすいものから順に読みます (動いているプロセス → 通信の相手 → ログイン → 管理者権限・鍵・sudo・自動起動・仕込みに使われる場所 → 特権プログラム → 改ざん確認 → 最近変わったもの → ログ)。読むだけで、何も変えません。前回の記録があれば「増えたもの」を先に出します。'),
      el('div', { class: 'row', style: { gap: '8px', alignItems: 'center', flexWrap: 'wrap' } }, sel, el('button', { class: 'btn primary', onclick: async () => { const tsel = tg.find(x => x.id === sel.value); const ok = await confirmRun({ title: `${tsel?.name || ''}: 初動セット`, what: '消えやすいものから順に、17 の型 (読むだけ) を流します。何も変えません・止めません。前回の記録があれば、増えたものを先に出します。', extra: '調べる前に: 疑わしい機械の電源は切らない (手がかりが消えます)。切り離すのは人が判断してください。' }); if (!ok) return; out.innerHTML = ''; out.append(el('div', { class: 'notice info' }, '⏳ 初動セットを流しています (17 の型、1〜3 分)…')); try { const r = await POST('/mamoricho/set/run', { target_id: sel.value, set: 'incident' }); showIncident(r); } catch (e) { out.innerHTML = ''; out.append(el('div', { class: 'notice err' }, e.message)); } } }, '初動セットを流す'), el('span', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, '平時にも流しておくと、それが基準になります')), out);
    function showIncident(r) { out.innerHTML = ''; renderSnapshot(out, r); }
  })();
  // 速報の下書き
  const sumIn = el('textarea', { class: 'inp', rows: 2, placeholder: '分かっていることを一言 (例: 経理 PC で身代金の表示。共有フォルダの一部が開けない)', style: { width: '100%' } }); const rep = el('div');
  c.append(el('h2', {}, '速報の下書き (委員会への報告)'), el('div', { style: CARD }, el('p', { class: 'sub', style: { fontSize: '12px' } }, '上の「発覚した日」「連絡先」「初動の記録」「初動の調査」を材料に、1〜9 の項目の下書きを作ります。分からないことは「調査中」のままにします。送る前に必ず読み直してください。'), sumIn,
    el('div', { class: 'row', style: { margin: '6px 0 10px', gap: '6px' } }, isOp() ? el('button', { class: 'btn primary', onclick: async () => { rep.innerHTML = ''; rep.append(el('div', { class: 'sub' }, '下書きを作っています…')); try { const r = await POST('/mamoricho/incident/report', { discovered_at: date.value, summary: sumIn.value.trim() }); rep.innerHTML = ''; rep.append(el('pre', { style: { whiteSpace: 'pre-wrap', fontSize: '13px', background: 'rgba(15,23,42,.045)', padding: '10px', borderRadius: '8px', userSelect: 'all' } }, r.draft), r.note ? el('div', { class: 'notice warn' }, r.note) : '', el('button', { class: 'btn sm', onclick: async () => { try { await navigator.clipboard.writeText(r.draft); toast('写しました', 'ok'); } catch { toast('写せませんでした', 'err'); } } }, '写す')); } catch (e) { rep.innerHTML = ''; rep.append(el('div', { class: 'notice err' }, e.message)); } } }, '下書きを作る') : ''), rep));
  c.append(el('h2', {}, '初動の記録 (時系列)'), el('div', { style: CARD }, isOp() ? el('div', {}, ta, el('div', { style: { margin: '6px 0 10px' } }, el('button', { class: 'btn primary', onclick: async () => { const text = ta.value.trim(); if (!text) return; try { const r = await POST('/mamoricho/incident/note', { text }); d.notes.unshift({ at: r.at, by_name: AIOS.state.me.display_name, payload: { text } }); ta.value = ''; drawNotes(); } catch (e) { toast(e.message, 'err'); } } }, '記録する'))) : '', list));
}

// ---------- 管理者アカウントの点検: 箱 (OS)自身 + サーバー (まとめて診断の結果) の兆候・操作履歴 (時系列)・AI の説明 ----------
async function renderAdmin(c, p, win) {
  c.append(el('h1', {}, '管理者アカウントの点検'), el('p', { class: 'sub' }, `管理者が増えていないか、鍵や入口が足されていないか、多要素認証を変えた直後に重要な操作がないか。${B.os}が読んだもの (ログイン履歴・認証ログ・監査ログ) を時刻順のイベントに直し、決まった規則で確かめます。見つかっても侵害の確定ではなく「要確認」、見つからなくても安全という意味ではありません。`));
  let d; try { d = await GET('/probe/admin/findings'); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  const selfBtn = isOp() ? el('button', { class: 'btn primary', onclick: async () => { const m = modal(el('div', {}, el('h2', {}, `${B.os}自身の管理者の点検`), el('p', { class: 'sub' }, '監査ログ・利用者・API キーを読んでいます (数秒)…'))); try { await POST('/probe/admin/self', { save: true }); m.close?.(); document.getElementById('modal').classList.add('hidden'); toast('記録に残しました', 'ok'); win.navigate('admin', { target: 'self' }); } catch (e) { m.close?.(); document.getElementById('modal').classList.add('hidden'); toast(e.message, 'err'); } } }, `🔑 ${B.os}自身を点検する (記録に残す)`) : '';
  c.append(el('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', marginBottom: '12px' } }, selfBtn, el('button', { class: 'btn', onclick: () => win.navigate('targets') }, 'サーバーは「まとめて診断」に含まれます →'), el('button', { class: 'btn', onclick: () => eventsDialog(null) }, '📜 操作履歴 (全対象)')));
  c.append(el('details', { style: { ...CARD, fontSize: '13px' } }, el('summary', { style: { cursor: 'pointer', fontWeight: 700 } }, '確かめている規則 (10 個)'), el('div', { class: 'sub', style: { fontSize: '12px', margin: '4px 0' } }, d.note), el('table', { class: 'tbl' }, ...d.rules.map(r => el('tr', {}, el('td', { style: { fontFamily: 'monospace', fontSize: '12px' } }, r.id), el('td', {}, el('span', { style: { color: r.level === 'warn' ? '#dc2626' : '#d97706', fontWeight: 700 } }, r.level === 'warn' ? '疑い' : '確認')), el('td', {}, r.label, el('div', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, r.why)))))));
  if (!d.findings.length) c.append(el('div', { class: 'notice info' }, `まだありません。「${B.os}自身を点検する」か、サーバーの「まとめて診断」を流してください。`));
  for (const f of d.findings) {
    const card = el('div', { id: 'ma-' + f.target_id, style: { ...CARD, borderColor: f.warn ? '#dc2626' : f.check ? '#d97706' : undefined } });
    card.append(el('div', { class: 'row', style: { alignItems: 'baseline', gap: '10px', flexWrap: 'wrap' } }, el('b', { style: { fontSize: '15px' } }, f.target_name), el('span', { class: 'sub', style: { margin: 0 } }, `${fmtTime(f.at)} ・ 記録 ${f.record_id}${f.baseline ? ' ・ 今回が基準' : f.since ? ` ・ 前回 ${fmtTime(f.since)} からイベント ${f.events_in_window} 件` : ''}`), el('span', { style: { marginLeft: 'auto' } }, f.warn ? el('span', { style: { color: '#dc2626', fontWeight: 700 } }, `疑い ${f.warn} `) : '', f.check ? el('span', { style: { color: '#d97706' } }, `確認 ${f.check}`) : '', !f.warn && !f.check ? el('span', { class: 'sub', style: { margin: 0 } }, '兆候なし') : '')));
    renderSigns(card, { title: '管理者アカウントの乗っ取りの兆候', signs: f.signs, note: d.note, warn: f.warn, check: f.check });
    if (f.unavailable?.length) card.append(el('div', { class: 'sub', style: { fontSize: '12px' } }, '確認できなかった項目 (= 問題なし ではありません): ', ...f.unavailable.map(u => el('div', { style: { marginLeft: '12px' } }, `${u.rule_id} ${u.label} — ${u.reason}`))));
    const ana = el('div');
    card.append(el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', marginTop: '8px' } }, el('button', { class: 'btn sm', onclick: () => eventsDialog(f.target_id, f.target_name) }, '📜 操作履歴 (時系列)'), isOp() ? el('button', { class: 'btn sm', onclick: async () => { ana.innerHTML = ''; ana.append(el('div', { class: 'sub' }, '箱の AI が証拠を読んでいます (20〜60 秒)…')); try { const r = await POST('/probe/admin/analyze', { target_id: f.target_id, record_id: f.record_id }); ana.innerHTML = ''; renderAnalysis(ana, r); } catch (e) { ana.innerHTML = ''; ana.append(el('div', { class: 'notice err' }, e.message)); } } }, '🤖 AI に説明してもらう (目安)') : ''), ana);
    c.append(card);
  }
  if (p?.target) setTimeout(() => document.getElementById('ma-' + p.target)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50);
  if (p?.tab === 'events') eventsDialog(null);
  async function eventsDialog(target_id, name) {
    let r; try { r = await GET('/probe/admin/events?limit=300' + (target_id ? '&target_id=' + encodeURIComponent(target_id) : '')); } catch (e) { return toast(e.message, 'err'); }
    const t = el('table', { class: 'tbl', style: { fontSize: '12px' } }, el('thead', {}, el('tr', {}, el('th', {}, '時刻'), el('th', {}, '誰が'), el('th', {}, 'どこから'), el('th', {}, '何を'), el('th', {}, '対象・補足'), el('th', {}, '証拠'))));
    for (const e of r.events) t.append(el('tr', {}, el('td', {}, fmtTime(e.timestamp)), el('td', {}, e.actor?.id || '?', e.actor?.role === 'administrator' ? el('span', { class: 'tag', style: { marginLeft: '4px' } }, '管理者') : ''), el('td', {}, e.actor?.ip || ''), el('td', { style: { color: e.result === 'failure' ? '#6b7280' : undefined } }, e.action_ja), el('td', {}, [e.details?.subject, e.details?.note].filter(Boolean).join(' / ')), el('td', { style: { fontSize: '11px', fontFamily: 'monospace' } }, e.id, e.evidence?.probe_run_id ? ` (${e.evidence.probe_run_id})` : e.evidence?.source_ref ? ` (${e.evidence.source_ref})` : '')));
    modal(el('div', {}, el('h2', {}, `${name || '全対象'}: 管理者の操作履歴`), el('p', { class: 'sub', style: { fontSize: '12px' } }, '原本 (調査の出力・監査ログ) を正規化したものです。証拠 id で、兆候や AI の説明からたどれます。資格情報や鍵の中身は持っていません。'), r.events.length ? el('div', { style: { maxHeight: '60vh', overflow: 'auto' } }, t) : el('div', { class: 'notice info' }, 'まだありません')));
  }
}
function renderAnalysis(box, r) {
  if (!r.analysis) return box.append(el('div', { class: 'notice warn' }, r.note || 'AI の説明はありません'));
  const a = r.analysis; const kb = el('div', { style: { ...CARD, borderColor: '#2563eb', marginTop: '8px' } });
  kb.append(el('div', { style: { fontWeight: 700 } }, '🤖 箱の AI の説明 ', el('span', { class: 'sub', style: { margin: 0, fontWeight: 400, fontSize: '12px' } }, `(目安。結論は常に「${a.conclusion}」。証拠 id は実在を確かめ、一覧に無い証拠 ${a.dropped?.evidence_ids?.length || 0} 件・型 ${a.dropped?.template_ids?.length || 0} 件は外しました)`)), el('div', { style: { margin: '6px 0' } }, a.summary));
  for (const s of a.suspicions || []) kb.append(el('div', { style: { padding: '6px 8px', margin: '4px 0', background: 'rgba(15,23,42,.045)', borderRadius: '8px', fontSize: '13px' } }, el('div', {}, el('b', {}, '不審な点: '), s.description, s.unverified ? el('span', { style: { color: '#dc2626' } }, ' (実在する証拠 id が無い → 根拠不明)') : ''), el('div', { class: 'sub', style: { margin: '2px 0 0', fontSize: '12px' } }, `正当な理由の可能性: ${s.possible_legitimate_reason || '—'}`), s.evidence_ids?.length ? el('div', { style: { fontSize: '11px', fontFamily: 'monospace', color: '#6b7280' } }, '証拠: ' + s.evidence_ids.join(', ')) : ''));
  if (a.missing_evidence?.length) kb.append(el('div', { style: { fontSize: '13px', marginTop: '6px' } }, el('b', {}, '足りない証拠: '), a.missing_evidence.join(' / ')));
  if (a.recommended_templates?.length) kb.append(el('div', { style: { fontSize: '13px', marginTop: '6px' } }, el('b', {}, '追加で読むとよい型: '), ...a.recommended_templates.map(t => el('span', { class: 'tag', style: { marginRight: '4px' } }, t.label))));
  if (a.human_checks?.length) kb.append(el('div', { style: { fontSize: '13px', marginTop: '6px' } }, el('b', {}, '人が確かめること: '), el('ul', { style: { margin: '2px 0 0 18px' } }, ...a.human_checks.map(x => el('li', {}, x)))));
  kb.append(el('div', { class: 'sub', style: { fontSize: '12px', marginTop: '6px' } }, `結論: ${a.conclusion}${r.record_id ? ' ・ 記録 ' + r.record_id : ''}`));
  box.append(kb);
}

// ---------- API の権限を確かめる (公開 HP・API の対象): ① 一覧 → ② 主体 → ③ 期待する権限 → ④ 承認して実行 → ⑤ 結果 ----------
const RES_COLOR = { '想定どおり': '#16a34a', '認可不備の疑い': '#dc2626', '判断できない': '#d97706', '未検査': '#6b7280' };
async function renderAuthz(c, p, win) {
  c.append(el('h1', {}, 'API の権限を確かめる'), el('p', { class: 'sub' }, '自社の Web / API を、テスト用のアカウント (未ログイン・一般・管理者) で「想定外の操作ができないか」を確かめます。やることは「誰が・どこを・見てよいか」の表を人が決めて、その表どおりかを読むだけ (GET/HEAD) で確かめる、です。本番ではなくステージング環境で。'));
  let targets; try { targets = (await GET('/probe/targets')).targets.filter(t => t.kind === 'web' && !t.pending && !t.excluded && !t.revoked_at); } catch (e) { c.append(el('div', { class: 'notice err' }, e.message)); return; }
  if (!targets.length) { c.append(el('div', { class: 'notice info' }, '公開 HP・API の対象がまだありません。「対象」で会社のホームページ (または API のステージング) を追加してください。 ', el('button', { class: 'btn sm', onclick: () => win.navigate('targets') }, '対象へ'))); return; }
  const sel = el('select', { class: 'inp', style: { width: 'auto' } }, ...targets.map(t => el('option', { value: t.id }, `${t.name} (${t.host})`))); if (p?.target && targets.some(t => t.id === p.target)) sel.value = p.target;
  const body = el('div'); c.append(el('div', { class: 'row', style: { gap: '8px', alignItems: 'center', marginBottom: '10px' } }, '対象: ', sel), body);
  sel.addEventListener('change', () => draw()); draw();
  async function draw() {
    const t = targets.find(x => x.id === sel.value); body.innerHTML = ''; body.append(el('div', { class: 'sub' }, '読んでいます…'));
    let d, st; try { [d, st] = await Promise.all([GET('/probe/authz/operations?target_id=' + t.id), GET('/probe/authz/status?target_id=' + t.id)]); } catch (e) { body.innerHTML = ''; body.append(el('div', { class: 'notice err' }, e.message)); return; }
    body.innerHTML = '';
    const bar = el('div', { class: 'row', style: { gap: '6px', flexWrap: 'wrap', marginBottom: '10px' } });
    for (const [l, ok] of [['① API の一覧', st.has_spec], ['② テスト用の主体', st.actors.total > 0 && !st.actors.missing_credential], ['③ 期待する権限', !!st.policy_version], ['④ 承認して実行', !!st.last_run]]) bar.append(el('span', { class: 'tag', style: { borderColor: ok ? '#16a34a' : '#d97706', color: ok ? '#16a34a' : '#d97706' } }, (ok ? '✅ ' : '○ ') + l));
    body.append(bar);
    // ① 一覧
    const s1 = el('details', { open: !st.has_spec, style: CARD }); s1.append(el('summary', { style: { cursor: 'pointer', fontWeight: 700 } }, `① API の一覧 ${st.has_spec ? `(${st.operations} 操作、${d.spec.source === 'openapi' ? 'OpenAPI' : '手書き'}、${fmtTime(d.spec.at)})` : '(未登録)'}`));
    const oa = el('textarea', { class: 'inp', rows: 4, placeholder: 'OpenAPI の JSON をここに貼る ({"openapi":"3.0.0","paths":{...}})。YAML はこの版では読めません', style: { width: '100%', fontFamily: 'monospace', fontSize: '11px' } });
    const ml = el('textarea', { class: 'inp', rows: 4, placeholder: 'または、1 行に 1 つ: GET /api/users/{id} 利用者の情報\nGET /api/admin/users 全利用者 (管理)', style: { width: '100%', fontFamily: 'monospace', fontSize: '11px', marginTop: '6px' } });
    s1.append(el('p', { class: 'sub', style: { fontSize: '12px' } }, 'OpenAPI 定義があればそれを。無ければ、確かめたい API を数行だけ書けば十分です。JavaScript を解析して探す・総当たりで探す、はしません。'), oa, ml, isOp() ? el('div', { style: { marginTop: '6px' } }, el('button', { class: 'btn primary', onclick: async () => { try { const r = await POST('/probe/authz/import', { target_id: t.id, openapi: oa.value.trim() || null, list: ml.value.trim() || null }); toast(`${r.operations.length} 操作を登録しました`, 'ok'); draw(); } catch (e) { toast(e.message, 'err'); } } }, '登録する')) : '');
    if (st.has_spec) { const tb = el('table', { class: 'tbl' }); for (const o of d.operations.slice(0, 80)) tb.append(el('tr', {}, el('td', { style: { fontFamily: 'monospace', fontSize: '12px' } }, `${o.method} ${o.path}`), el('td', { style: { fontSize: '12px' } }, o.summary || ''), el('td', { style: { fontSize: '11px', color: '#6b7280' } }, ['GET', 'HEAD'].includes(o.method) ? '' : '書き込み (この版では検査しない)'))); s1.append(el('details', { style: { marginTop: '6px' } }, el('summary', { style: { fontSize: '12px', cursor: 'pointer' } }, '登録済みの操作を見る'), tb)); }
    body.append(s1);
    // ② 主体
    const s2 = el('details', { open: st.has_spec && (st.actors.total === 0 || st.actors.missing_credential > 0), style: CARD }); s2.append(el('summary', { style: { cursor: 'pointer', fontWeight: 700 } }, `② テスト用の主体 (${st.actors.total} 件${st.actors.missing_credential ? `・資格情報なし ${st.actors.missing_credential}` : ''})`));
    s2.append(el('p', { class: 'sub', style: { fontSize: '12px' } }, '未ログイン / 一般ユーザー A・B / 管理者 A のように登録します。資格情報 (トークンやセッション) は箱の金庫に入り、画面には出ません。「テスト用データ」は、その主体のものとして path の {id} などに入れる値です (他の主体のデータを見られないか、の確認に使います)。'));
    const at = el('table', { class: 'tbl' }, el('thead', {}, el('tr', {}, el('th', {}, '呼び名'), el('th', {}, '役割'), el('th', {}, 'テナント'), el('th', {}, 'テスト用データ'), el('th', {}, '資格'), el('th', {}, ''))));
    for (const a of d.actors) at.append(el('tr', {}, el('td', {}, a.label), el('td', {}, d.roles[a.role] || a.role), el('td', {}, a.tenant || '—'), el('td', { style: { fontSize: '12px', fontFamily: 'monospace' } }, Object.entries(a.params || {}).map(([k, v]) => `${k}=${v}`).join(' ') || '—'), el('td', {}, a.role === 'anon' ? '不要' : a.has_credential ? '登録済み' : el('span', { style: { color: '#dc2626' } }, 'なし')), el('td', {}, isAdmin() ? el('div', { class: 'row', style: { gap: '4px' } }, el('button', { class: 'btn sm', onclick: () => actorForm(t, a) }, '編集'), el('button', { class: 'btn sm danger', onclick: async () => { if (!await confirmDialog({ title: `${a.label} を消しますか`, body: '金庫の資格情報も消えます。', okLabel: '消す', danger: true })) return; try { await DEL(`/probe/authz/actors/${a.id}?target_id=${t.id}`); draw(); } catch (e) { toast(e.message, 'err'); } } }, '消す')) : '')));
    s2.append(at, isAdmin() ? el('div', { style: { marginTop: '6px' } }, el('button', { class: 'btn', onclick: () => actorForm(t, null) }, '＋ 主体を追加')) : el('div', { class: 'sub', style: { fontSize: '12px' } }, '主体の登録は Admin 以上が行えます。'));
    body.append(s2);
    // ③ 期待する権限 (決めるのは人。AI は候補だけ)
    const s3 = el('details', { open: st.has_spec && st.actors.total > 0 && !st.actors.missing_credential, style: CARD }); s3.append(el('summary', { style: { cursor: 'pointer', fontWeight: 700 } }, `③ 期待する権限 ${st.policy_version ? `(版 ${st.policy_version}${st.unknown ? `・未確定 ${st.unknown}` : ''})` : '(未設定)'}`));
    if (st.has_spec && d.actors.length) {
      s3.append(el('p', { class: 'sub', style: { fontSize: '12px' } }, '操作ごとに、各主体が「使ってよい (allow)」か「使えないはず (deny)」かを決めます。決めるのは人です。AI は候補を出すだけで、表に入れて保存するまで検査の対象にはなりません。未確定のものは検査しません。保存すると版が上がり、変更は記録に残ります。'));
      const m = JSON.parse(JSON.stringify(d.policy?.matrix || {})); const readOps = d.operations.filter(o => ['GET', 'HEAD'].includes(o.method)); const cells = {};
      const tb = el('table', { class: 'tbl', style: { fontSize: '12px' } }); tb.append(el('tr', {}, el('th', {}, '操作'), ...d.actors.map(a => el('th', {}, a.label, el('div', { class: 'sub', style: { margin: 0, fontSize: '11px', fontWeight: 400 } }, d.roles[a.role])))));
      const cell = (o, a) => { const s = el('select', { class: 'inp', style: { width: 'auto', padding: '2px 4px', fontSize: '12px' }, disabled: !isAdmin() }, el('option', { value: 'unknown' }, '未確定'), el('option', { value: 'allow' }, 'allow 使える'), el('option', { value: 'deny' }, 'deny 拒否')); s.value = m[o.operation_id]?.[a.id] || (a.role === 'anon' && o.secured ? 'deny' : 'unknown'); if (!m[o.operation_id]?.[a.id] && a.role === 'anon' && o.secured) s.title = '認証ありと宣言された操作: 未ログインは deny が既定'; s.addEventListener('change', () => { m[o.operation_id] ||= {}; m[o.operation_id][a.id] = s.value; s.style.background = ''; }); cells[`${o.operation_id}|${a.id}`] = s; return s; };
      for (const o of readOps) tb.append(el('tr', {}, el('td', { style: { fontFamily: 'monospace' } }, `${o.method} ${o.path}`, o.summary ? el('div', { class: 'sub', style: { margin: 0, fontSize: '11px', fontFamily: 'inherit' } }, o.summary) : ''), ...d.actors.map(a => el('td', {}, cell(o, a)))));
      const note = el('input', { class: 'inp', placeholder: '変更のメモ (例: 管理 API は管理者だけ)', style: { width: '100%', marginTop: '6px' } }); const sug = el('div');
      s3.append(el('div', { style: { overflow: 'auto' } }, tb), note, el('div', { class: 'row', style: { gap: '6px', marginTop: '6px', flexWrap: 'wrap' } }, isAdmin() ? el('button', { class: 'btn primary', onclick: async () => { try { const r = await POST('/probe/authz/policies', { target_id: t.id, matrix: m, note: note.value.trim() }); toast(r.unchanged ? '変わっていません' : `版 ${r.version} として保存しました (${r.changes.length} 件の変更)`, 'ok'); draw(); } catch (e) { toast(e.message, 'err'); } } }, '保存する (承認)') : '', isOp() ? el('button', { class: 'btn', onclick: async () => { sug.innerHTML = ''; sug.append(el('div', { class: 'sub' }, '箱の AI が候補を考えています (20〜60 秒)…')); try { const r = await POST('/probe/authz/suggest', { target_id: t.id }); sug.innerHTML = ''; let n = 0; for (const cnd of r.candidates) { const s = cells[`${cnd.operation_id}|${cnd.actor_id}`]; if (s && s.value === 'unknown' && cnd.expected !== 'unknown') { s.value = cnd.expected; s.style.background = 'rgba(37,99,235,.14)'; s.title = `AI の候補: ${cnd.reason}`; m[cnd.operation_id] ||= {}; m[cnd.operation_id][cnd.actor_id] = cnd.expected; n++; } } sug.append(el('div', { class: 'notice info', style: { fontSize: '12px' } }, `${n} 件の候補を表に入れました (青い枠)。${r.candidates.filter(x => x.expected === 'unknown').length} 件は AI も分からず「未確定」のまま、外した候補 ${r.dropped.length} 件。内容を確かめて「保存する」を押すまで、検査には使われません。${r.note ? ' ' + r.note : ''}`)); } catch (e) { sug.innerHTML = ''; sug.append(el('div', { class: 'notice err' }, e.message)); } } }, '🤖 AI に候補を出してもらう') : ''), sug);
    } else s3.append(el('div', { class: 'sub' }, '① と ② を済ませると、ここに表が出ます。'));
    body.append(s3);
    // ④ 計画と承認、実行
    const s4 = el('details', { open: !!st.policy_version, style: CARD }); s4.append(el('summary', { style: { cursor: 'pointer', fontWeight: 700 } }, `④ 承認して実行 ${st.pending_plan ? `(計画が承認${({ pending: '待ち', approved: '済み・実行できます' })[st.pending_plan.approval_state] || st.pending_plan.approval_state})` : st.last_run ? `(最終 ${fmtTime(st.last_run.at)})` : ''}`));
    const planBox = el('div');
    s4.append(el('p', { class: 'sub', style: { fontSize: '12px' } }, `やること: 登録した操作 × 主体 (× 誰のデータか) を 1 回ずつ GET/HEAD で読み、表どおりかを確かめます。つなぐ先 (${t.host}:${t.port}) は計画の時点で住所を固定し、転送は追わず、毎秒 1 回・1 回 ${d.limits.max_requests} リクエストまで。GET/HEAD 以外は実行しません。やらないこと: 書き込み・総当たり・本番への自動実行。計画は Owner / Admin が内容を見て承認してから実行します。`), planBox);
    const showPlan = async (pid) => { planBox.innerHTML = ''; let pl; try { pl = await GET('/probe/authz/plans/' + pid); } catch (e) { planBox.append(el('div', { class: 'notice err' }, e.message)); return; }
      const ap = pl.approval; const bx = el('div', { style: { padding: '8px 10px', border: '1px solid var(--line, #eee)', borderRadius: '8px', margin: '6px 0' } });
      bx.append(el('div', {}, el('b', {}, `計画: ${pl.cases.length} リクエスト`), el('span', { class: 'sub', style: { margin: '0 0 0 8px' } }, `${pl.pinned.host}:${pl.pinned.port} → ${pl.pinned.ip} に固定 ・ 未検査 ${pl.skipped.length} ・ ${Object.entries(pl.checks).map(([k, v]) => `${k} ${v}`).join(' / ') || '—'}`)));
      bx.append(el('div', { style: { fontSize: '12px', margin: '4px 0' } }, `承認: ${ap ? ({ pending: '待ち (Owner / Admin が承認してください)', approved: `済み (${ap.approver_id})`, rejected: '却下', expired: '期限切れ' }[ap.state] || ap.state) : '不要'}`, pl.state === 'done' ? ' ・ 実行済み' : ''));
      if (pl.skipped.length) bx.append(el('details', {}, el('summary', { style: { fontSize: '12px', cursor: 'pointer' } }, `未検査の理由 (${pl.skipped.length})`), el('ul', { style: { fontSize: '12px', margin: '2px 0 0 18px', maxHeight: '140px', overflow: 'auto' } }, ...pl.skipped.slice(0, 60).map(s => el('li', {}, `${s.method} ${s.path} × ${s.actor_label}: ${s.reason}`)))));
      const row = el('div', { class: 'row', style: { gap: '6px', marginTop: '6px', flexWrap: 'wrap' } });
      if (ap?.state === 'pending' && isAdmin()) row.append(el('button', { class: 'btn primary', onclick: async () => { const ok = await confirmDialog({ title: 'この計画を承認しますか', body: `${t.name} (${pl.pinned.host} → ${pl.pinned.ip}) に ${pl.cases.length} リクエスト (GET/HEAD、毎秒 1 回)。テスト用の主体とデータだけを使います。ステージング環境であることを確かめてください。`, okLabel: '承認する' }); if (!ok) return; try { await POST(`/approvals/${ap.id}/decide`, { decision: 'approve' }); toast('承認しました', 'ok'); showPlan(pid); } catch (e) { toast(e.message, 'err'); } } }, '承認する (Owner / Admin)'));
      if (ap?.state === 'approved' && pl.state !== 'done' && isOp()) row.append(el('button', { class: 'btn primary', onclick: async () => { const ok = await confirmRun({ title: `${t.name}: API の権限を確かめる`, what: `${pl.pinned.host}:${pl.pinned.port} (${pl.pinned.ip} に固定) へ、${pl.cases.length} 個の GET/HEAD を毎秒 1 回ずつ送り、応答が「期待する権限」の表どおりかを確かめます。書き込みはしません。`, extra: '本番ではなくステージングで。資格情報は環境変数でコンテナに渡し、記録には残りません。' }); if (!ok) return; const mm = modal(el('div', {}, el('h2', {}, '検査しています…'), el('p', { class: 'sub' }, `${pl.cases.length} リクエスト (毎秒 1 回なので ${Math.max(1, Math.ceil(pl.cases.length / 60))} 分ほど)`))); try { const r = await POST('/probe/authz/runs', { plan_id: pid }); mm.close?.(); document.getElementById('modal').classList.add('hidden'); toast('終わりました', 'ok'); draw(); showRun(r); } catch (e) { mm.close?.(); document.getElementById('modal').classList.add('hidden'); toast(e.message, 'err'); } } }, '▶ 実行する'));
      bx.append(row); planBox.append(bx); };
    if (st.pending_plan) showPlan(st.pending_plan.id);
    if (isOp() && st.has_spec) s4.append(el('div', { style: { marginTop: '6px' } }, el('button', { class: 'btn' + (st.pending_plan ? '' : ' primary'), onclick: async () => { try { const pl = await POST('/probe/authz/plans', { target_id: t.id }); toast(pl.cases.length ? '計画を作りました。承認を待っています' : '実行できる検査がありません (未検査の理由を見てください)', pl.cases.length ? 'ok' : 'err'); draw(); } catch (e) { toast(e.message, 'err'); } } }, '計画を作る (承認を求める)')));
    body.append(s4);
    // ⑤ 結果
    const s5 = el('details', { open: !!st.last_run, style: CARD }); s5.append(el('summary', { style: { cursor: 'pointer', fontWeight: 700 } }, `⑤ 結果 ${st.last_run ? `(疑い ${st.suspects}・判断できない ${st.unclear}・前回からの退行 ${st.regressions})` : '(まだ)'}`));
    try { const rr = await GET('/probe/authz/runs?target_id=' + t.id + '&limit=20'); if (!rr.runs.length) s5.append(el('div', { class: 'sub' }, 'まだありません')); else { const tb = el('table', { class: 'tbl' }, el('thead', {}, el('tr', {}, el('th', {}, '日時'), el('th', {}, 'リクエスト'), el('th', {}, '想定どおり'), el('th', {}, '疑い'), el('th', {}, '判断できない'), el('th', {}, '退行'), el('th', {}, '')))); for (const r of rr.runs) tb.append(el('tr', {}, el('td', {}, fmtTime(r.started_at)), el('td', {}, r.totals?.requests ?? '-'), el('td', {}, r.totals?.ok ?? '-'), el('td', { style: { color: r.totals?.suspect ? '#dc2626' : undefined, fontWeight: r.totals?.suspect ? 700 : 400 } }, r.totals?.suspect ?? '-'), el('td', {}, r.totals?.unclear ?? '-'), el('td', { style: { color: r.totals?.regressions ? '#dc2626' : undefined } }, r.totals?.regressions ?? '-'), el('td', {}, el('button', { class: 'btn sm', onclick: async () => { try { showRun(await GET('/probe/authz/runs/' + r.id)); } catch (e) { toast(e.message, 'err'); } } }, '開く')))); s5.append(tb); } } catch (e) { s5.append(el('div', { class: 'notice err' }, e.message)); }
    body.append(s5);
  }
  function showRun(r) {
    const c2 = el('div', {}, el('h2', {}, `検査の結果 (${fmtTime(r.started_at)})`)); const tt = r.totals || {};
    c2.append(el('div', { class: 'notice ' + (tt.suspect || tt.regressions ? 'err' : tt.unclear ? 'warn' : 'ok') }, `${tt.requests} リクエスト: 想定どおり ${tt.ok} ・ 疑い ${tt.suspect} ・ 判断できない ${tt.unclear} ・ 未検査 ${tt.skipped} ・ 前回からの退行 ${tt.regressions}${tt.fixed ? ` ・ 直った ${tt.fixed}` : ''}${tt.stopped ? ' ・ ' + tt.stopped : ''}`), el('div', { class: 'sub', style: { fontSize: '12px' } }, `承認 ${r.approved_by || '-'} ・ 記録 ${r.record_id || '-'}。見つからなくても認可が正しいとは限りません (登録した操作・主体・データの範囲だけ)。`));
    const order = Object.keys(RES_COLOR); const tb = el('table', { class: 'tbl', style: { fontSize: '12px' } }, el('thead', {}, el('tr', {}, el('th', {}, '検査'), el('th', {}, '操作'), el('th', {}, '主体'), el('th', {}, '誰のデータ'), el('th', {}, '期待'), el('th', {}, '応答'), el('th', {}, '結果'))));
    for (const x of [...(r.results || [])].sort((a, b) => order.indexOf(a.result === '認可不備の疑い' ? '' : a.result) - order.indexOf(b.result === '認可不備の疑い' ? '' : b.result))) tb.append(el('tr', {}, el('td', {}, x.check || ''), el('td', { style: { fontFamily: 'monospace' } }, `${x.method} ${x.url_path}`), el('td', {}, x.actor_label), el('td', {}, x.owner_id === x.actor_id ? '自分' : x.owner_label), el('td', {}, x.expected), el('td', {}, x.status || '-'), el('td', { style: { color: RES_COLOR[x.result] || undefined, fontWeight: x.result === '認可不備の疑い' ? 700 : 400 } }, x.result, el('div', { class: 'sub', style: { margin: 0, fontSize: '11px' } }, x.reason))));
    c2.append(el('div', { style: { overflow: 'auto', maxHeight: '60vh' } }, tb), el('div', { class: 'row', style: { justifyContent: 'flex-end', marginTop: '8px' } }, el('button', { class: 'btn primary', onclick: () => document.getElementById('modal').classList.add('hidden') }, '閉じる')));
    modal(c2);
  }
  function actorForm(t, a) {
    const f = { label: el('input', { class: 'inp', value: a?.label || '', placeholder: '呼び名 (例: 一般ユーザー A)' }), role: el('select', { class: 'inp' }, el('option', { value: 'anon' }, '未ログイン'), el('option', { value: 'user' }, '一般ユーザー'), el('option', { value: 'admin' }, '管理者')), tenant: el('input', { class: 'inp', value: a?.tenant || '', placeholder: 'テナント (任意。例: 会社 A)' }), params: el('textarea', { class: 'inp', rows: 3, value: Object.entries(a?.params || {}).map(([k, v]) => `${k}=${v}`).join('\n'), placeholder: 'テスト用データ: 1 行に 1 つ name=value (例: id=42)。path の {id} に入ります', style: { width: '100%', fontFamily: 'monospace', fontSize: '12px' } }), auth_kind: el('select', { class: 'inp', style: { width: 'auto' } }, el('option', { value: 'bearer' }, 'Bearer トークン'), el('option', { value: 'cookie' }, 'Cookie'), el('option', { value: 'basic' }, 'Basic (user:pass)'), el('option', { value: 'header' }, 'ヘッダ (名前を指定)')), header_name: el('input', { class: 'inp', value: a?.header_name || 'Authorization', placeholder: 'ヘッダ名', style: { width: '160px' } }), secret: el('textarea', { class: 'inp', rows: 2, placeholder: a?.has_credential ? '変えないなら空のまま' : 'トークン / Cookie の値 / user:pass。箱の金庫に入り、画面には出ません', style: { width: '100%', fontFamily: 'monospace', fontSize: '11px' } }), days: el('input', { class: 'inp', type: 'number', min: 1, max: 365, placeholder: '期限 (日)', style: { width: '120px' } }) };
    if (a) { f.role.value = a.role; f.auth_kind.value = a.auth_kind || 'bearer'; }
    const c3 = el('div', {}, el('h2', {}, a ? '主体を編集' : '主体を追加'), el('div', { class: 'grid', style: { gridTemplateColumns: '1fr 1fr', gap: '8px' } }, f.label, f.role, f.tenant, el('div', { class: 'row', style: { gap: '6px' } }, f.auth_kind, f.header_name)), el('label', { class: 'lbl' }, 'テスト用データ'), f.params, el('label', { class: 'lbl' }, '資格情報 (未ログインは不要)'), f.secret, el('div', { class: 'row', style: { gap: '8px', marginTop: '4px', alignItems: 'center' } }, f.days, el('span', { class: 'sub', style: { margin: 0, fontSize: '12px' } }, 'テスト用のアカウントだけを。本番の利用者の資格情報は入れないでください')));
    const m = modal(c3);
    c3.append(el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px', marginTop: '12px' } }, el('button', { class: 'btn', onclick: () => { m.close?.(); document.getElementById('modal').classList.add('hidden'); } }, 'やめる'), el('button', { class: 'btn primary', onclick: async () => {
      const params = {}; for (const l of f.params.value.split('\n')) { const mm = l.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/); if (mm) params[mm[1]] = mm[2]; }
      m.close?.(); document.getElementById('modal').classList.add('hidden');
      const ok = await confirmDialog({ title: a ? '主体を更新します' : '主体を追加します', body: '資格情報は箱の金庫に入ります。', okLabel: a ? '更新する' : '追加する', reauth: true }); if (!ok) return;
      try { await POST('/probe/authz/actors', { target_id: t.id, id: a?.id || null, label: f.label.value.trim(), role: f.role.value, tenant: f.tenant.value.trim(), params, secret: f.secret.value.trim() || null, auth_kind: f.auth_kind.value, header_name: f.header_name.value.trim() || 'Authorization', expires_days: f.days.value ? Number(f.days.value) : null }, { reauth: ok.reauth }); toast('保存しました', 'ok'); draw(); } catch (e) { toast(e.message, 'err'); }
    } }, a ? '更新する' : '追加する')));
  }
}

AIOS.apps.mamoricho = {
  async mount(win, opts) {
    try { Object.assign(B, (await GET('/mamoricho/brand')).brand || {}); } catch { /* 既定のまま */ }
    const W = (fn) => (c, p) => fn(c, p, win);
    // route と params の両方があるときは、既定の描画 (params なし) をせずに下で 1 回だけ描く (2 回描くと、非同期の中身が二重に足される)
    const app = routedApp(win, { title: 'まもり帳', defaultRoute: opts.route && opts.params ? null : (opts.route || 'home'), routes: {
      home: { label: 'ホーム', icon: '🏠', render: W(renderHome) },
      check: { label: '点検', icon: '☑', render: W(renderCheck) },
      targets: { label: '対象', icon: '🖥', render: W(renderTargets) },
      records: { label: '記録', icon: '📜', render: W(renderRecords) },
      emergency: { label: 'もしものとき', icon: '🚨', sep: true, render: W(renderEmergency) },
      inquiry: { label: '対話で調べる', icon: '💬', render: W(renderInquiry) },
      safety: { label: '安全の仕組み', icon: '🛡', render: W(renderSafety) },
      // メニューには出さない (ホーム・点検・対象・もしものとき から入る)。メニューが並ぶと何をいつやるか迷うため
      admin: { label: '管理者アカウントの点検', icon: '🔑', hidden: true, render: W(renderAdmin) },
      authz: { label: 'API の権限を確かめる', icon: '🔐', hidden: true, render: W(renderAuthz) },
    } });
    if (opts.route && opts.params) app.render(opts.route, opts.params);
  },
};
})();
