// まもり帳 — 対話で調べる (docs/MAMORICHO_DESIGN.md「対話で調べる」)。
//   利用者が持ってきたニュースの URL や文章 → 箱の AI が下読み → 台帳の対象に関係するかを考え、「読むだけの型 × 対象」の確認を提案
//   → 利用者が承認して実行 → AI が記事と結果を突き合わせた見立て (目安) → 続けて聞ける。
//   AI は選ぶだけで作らない: 提案できるのは一覧にある型と対象だけ。コマンドは作れない。引数つきの型は決まった形の引数だけ。
import { HttpError, id as newId, nowIso } from '../util.js';
import { audit } from '../audit.js';
import { requireRole } from '../auth.js';
import { TEMPLATES, validateParams, fillSteps } from './mamoricho.js';

const MAX_TEXT = 12000; // AI に渡す記事の長さ
const KEEP = 50; // 箱の中に持っておく対話の数 (再起動で消える。要点は記録に残る)
const VERDICTS = ['該当のおそれ', '該当しない', '分からない'];
const jsonOf = (s) => { const m = String(s || '').match(/```(?:json)?\s*([\s\S]*?)```/i); const raw = m ? m[1] : String(s || ''); const i = raw.indexOf('{'), j = raw.lastIndexOf('}'); if (i < 0 || j <= i) throw new Error('AI の答えに JSON がありません'); return JSON.parse(raw.slice(i, j + 1)); };
const str = (v, n = 2000) => (typeof v === 'string' ? v : v == null ? '' : JSON.stringify(v)).slice(0, n);
const arr = (v, n = 10) => (Array.isArray(v) ? v.filter(x => typeof x === 'string' && x.trim()).map(x => x.trim().slice(0, 300)).slice(0, n) : []);

export class Inquiry {
  constructor(mm, { probe, llm }) { this.mm = mm; this.probe = probe; this.llm = llm; this.items = new Map(); }
  _get(id) { const it = this.items.get(id); if (!it) throw new HttpError(404, 'not_found', 'この対話は見つかりません (言箱の再起動で消えたかもしれません。要点は「記録」に残っています)'); return it; }
  // 台帳の対象と、直近に読んだ事実 (OS・待ち受け・更新・HP の構造)。AI が「関係するか」を考える材料
  _targets(actor) {
    const list = this.probe.listTargets(actor);
    const latest = (tid, template_id) => { const tpl = TEMPLATES.find(t => t.id === template_id); if (!tpl) return []; return tpl.steps.map(a => { const p = this.probe.previousOutput(tid, template_id, a); return p ? `$ ${a.join(' ')}\n${String(p.output).split('\n--- エラー出力 ---')[0].slice(0, 700)}` : null; }).filter(Boolean); };
    return list.map(t => {
      const usable = !t.pending && !t.excluded && !t.revoked_at; let facts = [];
      try {
        if (t.kind === 'ssh') facts = [...latest(t.id, 'linux.basic'), ...latest(t.id, 'linux.ports').slice(0, 1), ...latest(t.id, 'linux.updates').slice(0, 1)];
        else if (t.kind === 'network') facts = latest(t.id, 'network.show').slice(0, 1);
        else if (t.kind === 'web') { const sn = this.mm.snapshots(actor, { target_id: t.id, limit: 1 })[0]; const d = sn?.comparable ? this.mm.snapshot(actor, sn.id).digest : null; if (d) facts = [`タイトル: ${d.title || ''} / サーバーの名乗り: ${d.server || '(無し)'} / ${d.powered || ''} / 外部スクリプト: ${(d.scripts_ext || []).join(', ') || '無し'} / 証明書: ${d.cert?.issuer || ''}`]; }
      } catch { /* 材料が無くても続ける */ }
      return { id: t.id, name: t.name, kind: t.kind, host: t.host, hostname: t.enrolled_hostname || null, notes: t.notes || '', usable, facts };
    });
  }
  _catalog() { return TEMPLATES.map(t => ({ id: t.id, kind: t.kind, label: t.label, steps: t.steps.map(a => a.join(' ')), params: t.params ? Object.fromEntries(Object.entries(t.params).map(([k, v]) => [k, v.desc])) : null })); }
  _sys() { return 'あなたは、中小企業の情報セキュリティ担当者を手伝う「言箱 (ことはこ)」のまもり帳の AI です。利用者が持ってきた記事や情報を読み、台帳にある機械 (対象) に関係があるかを考え、関係を確かめるために流せる「読むだけの調査の型」を選びます。守ること: (1) 選べるのは一覧にある型と対象だけ。コマンドは作らない。引数つきの型は、説明された形の引数だけ。(2) 推測は推測と書く。「安全」とは言い切らない。(3) 版の読み方は配布元で違う (Debian/Ubuntu はバックポートで古い版番号のまま直されることがある) ことを踏まえる。(4) 出力は JSON だけ。日本語で、やさしい言葉で。'; }
  _ctx(actor, it) {
    const targets = this._targets(actor);
    const tl = targets.map(t => `- id=${t.id} 名前=「${t.name}」 種類=${t.kind} 住所=${t.host}${t.hostname ? ' 機械名=' + t.hostname : ''}${t.notes ? ' 備考=' + t.notes.slice(0, 120) : ''} 調べられる=${t.usable ? 'はい' : 'いいえ'}${t.facts.length ? '\n  直近に読んだ事実:\n' + t.facts.map(f => '  ' + f.replace(/\n/g, '\n  ')).join('\n') : ''}`).join('\n');
    const cl = this._catalog().map(c => `- id=${c.id} 種類=${c.kind.join('/')} 「${c.label}」 手順: ${c.steps.join(' / ')}${c.params ? ' 引数: ' + Object.entries(c.params).map(([k, d]) => `${k} (${d})`).join(', ') : ''}`).join('\n');
    return { targets, text: `# 持ってきた情報\n題: ${it.title || '(無し)'}\nアドレス: ${it.final_url || it.url || '(無し)'}\n本文:\n${it.text.slice(0, MAX_TEXT)}\n\n# 台帳の対象\n${tl || '(無し)'}\n\n# 読むだけの調査の型 (この中からだけ選ぶ)\n${cl}` };
  }
  async _json(sys, user, max_tokens) { const r = await this.llm.chat([{ role: 'system', content: sys }, { role: 'user', content: user }], { temperature: 0.1, max_tokens, json: true }); return jsonOf(r?.content); }
  // AI が出した確認の候補を、台帳と一覧で確かめる。外したものは理由つきで残す (利用者に見せる)
  _normalizeChecks(raw, targets) {
    const out = []; let okN = 0;
    for (const c of Array.isArray(raw) ? raw.slice(0, 20) : []) {
      const row = { target_id: str(c?.target_id, 60), template_id: str(c?.template_id, 60), params: c?.params && typeof c.params === 'object' ? c.params : null, why: str(c?.why, 300), done: false };
      const t = targets.find(x => x.id === row.target_id) || targets.find(x => x.name === row.target_id); const tpl = TEMPLATES.find(x => x.id === row.template_id);
      row.target_name = t?.name || row.target_id; row.template_label = tpl?.label || row.template_id;
      if (!t) row.dropped = '台帳に無い対象'; else if (!t.usable) row.dropped = '今は調べられない対象 (登録中・除外・取り消し)'; else if (!tpl) row.dropped = '一覧に無い型'; else if (!tpl.kind.includes(t.kind)) row.dropped = `対象の種類 (${t.kind}) に合わない型`;
      else { try { const prm = tpl.params ? validateParams(tpl, row.params || {}) : {}; row.params = prm; row.target_id = t.id; row.steps = fillSteps(tpl, prm); } catch (e) { row.dropped = `引数が決まった形でない (${e.message})`; } }
      if (!row.dropped) { if (okN >= 12) { row.dropped = '一度に流せるのは 12 個まで'; } else okN++; }
      out.push(row);
    }
    return out;
  }
  async start(actor, { url = null, text = null } = {}) {
    requireRole(actor, 'operator');
    url = url ? String(url).trim() : null; text = text ? String(text).trim() : null;
    if (!url && !text) throw new HttpError(400, 'bad_request', 'アドレスか文章を入れてください');
    const article = url ? await this.probe.fetchPublic(actor, url) : null;
    const body = [article?.text, text].filter(Boolean).join('\n\n');
    if (!body.trim()) throw new HttpError(422, 'empty', '読める文章がありませんでした');
    const it = { id: newId('minq'), at: nowIso(), by: actor.id, by_name: actor.display_name || actor.name || actor.id, url, final_url: article?.final_url || null, title: article?.title || null, text: body.slice(0, MAX_TEXT), messages: [], plan: null, results: [], conclusion: null, record_id: null, state: 'planned', note: null };
    if (!this.llm) it.note = 'この箱には AI が無いので、下読みと提案はできません。文章を読んで、「対象」の画面から型を選んでください。';
    else {
      try {
        const { targets, text: ctx } = this._ctx(actor, it);
        const raw = await this._json(this._sys(), `${ctx}\n\n# 出力の形: plan\n{"summary": "記事の要点を 2〜3 文で (何が・どの製品/版が・どう危ないか)", "products": ["関係する製品やソフトの名前"], "severity": "high|medium|low|unknown", "relevance": "yes|maybe|no|unknown (台帳の対象に関係するか)", "reason": "そう考えた理由 (台帳のどの対象の、どの事実から)", "checks": [{"target_id": "対象の id", "template_id": "型の id", "params": {"引数名": "値"}, "why": "この型で何を確かめるか"}], "advice": ["調べなくても言えること・すぐできる対策 (0〜5 個)"]}\nchecks は、関係を確かめるのに意味がある組み合わせだけ (無ければ空)。対象の種類と型の種類を合わせること。`, 1500);
        it.plan = { summary: str(raw.summary, 1500), products: arr(raw.products, 10), severity: ['high', 'medium', 'low', 'unknown'].includes(raw.severity) ? raw.severity : 'unknown', relevance: ['yes', 'maybe', 'no', 'unknown'].includes(raw.relevance) ? raw.relevance : 'unknown', reason: str(raw.reason, 800), checks: this._normalizeChecks(raw.checks, targets), advice: arr(raw.advice, 8) };
      } catch (e) { it.note = `AI の下読みができませんでした: ${String(e.message || e).slice(0, 160)}`; }
    }
    this.items.set(it.id, it); while (this.items.size > KEEP) this.items.delete(this.items.keys().next().value);
    audit({ actor, action: 'mamoricho.inquiry_start', target: it.id, detail: { url: url ? url.slice(0, 200) : null, text_chars: (text || '').length, checks: it.plan?.checks?.filter(c => !c.dropped).length || 0 } });
    return this.view(it);
  }
  // 提案された確認を実行する (ふつうの型と同じ道: classify・コンテナ・記録)。終わったら AI が見立てを書く
  async run(actor, { id } = {}) {
    requireRole(actor, 'operator'); const it = this._get(id);
    if (!it.plan) throw new HttpError(400, 'no_plan', '提案がありません');
    const todo = it.plan.checks.filter(c => !c.dropped && !c.done); if (!todo.length) throw new HttpError(400, 'nothing', '実行する手順がありません');
    for (const c of todo) {
      try {
        const r = await this.mm.runTemplate(actor, { target_id: c.target_id, template_id: c.template_id, params: c.params, record: true });
        c.done = true; it.results.push({ target_id: c.target_id, target_name: c.target_name, template_id: c.template_id, template_label: c.template_label, record_id: r.record_id, ok: r.results.filter(x => x.exit_code === 0).length, steps: r.results.map(x => ({ argv: x.argv, exit_code: x.exit_code ?? null, error: x.error || null, output: String(x.output || '').slice(0, 2500) })) });
      } catch (e) { c.done = true; c.error = String(e.message || e); it.results.push({ target_id: c.target_id, target_name: c.target_name, template_id: c.template_id, template_label: c.template_label, record_id: null, ok: 0, error: c.error, steps: [] }); }
    }
    if (this.llm) {
      try {
        const { targets } = this._ctx(actor, it);
        const res = it.results.map(r => `## ${r.target_name} (id=${r.target_id}): ${r.template_label}${r.error ? ' (失敗: ' + r.error + ')' : ''}\n${r.steps.map(x => `$ ${x.argv.join(' ')} (終了 ${x.exit_code ?? '-'})\n${x.output.slice(0, 1500)}`).join('\n')}`).join('\n\n');
        const raw = await this._json(this._sys(), `# 持ってきた情報の要点\n${it.plan.summary}\n製品: ${it.plan.products.join(', ')}\n\n# 調べた結果\n${res}\n\n# 対象の一覧\n${targets.map(t => `- id=${t.id} 「${t.name}」 ${t.kind}`).join('\n')}\n\n# 出力の形: conclusion\n{"conclusion": "結果を記事と突き合わせた見立てを 2〜4 文で。版の読み方の注意 (バックポート) も必要なら", "affected": [{"target_id": "対象の id", "verdict": "該当のおそれ|該当しない|分からない", "evidence": "そう見た根拠 (結果のどの行)"}], "next_steps": ["次にすること (更新・設定・配布元の案内で確かめる など、0〜5 個)"]}`, 1200);
        it.conclusion = { conclusion: str(raw.conclusion, 2000), affected: (Array.isArray(raw.affected) ? raw.affected.slice(0, 20) : []).map(a => { const t = targets.find(x => x.id === a?.target_id) || targets.find(x => x.name === a?.target_id); return { target_id: t?.id || str(a?.target_id, 60), target_name: t?.name || str(a?.target_id, 60), verdict: VERDICTS.includes(a?.verdict) ? a.verdict : '分からない', evidence: str(a?.evidence, 500) }; }), next_steps: arr(raw.next_steps, 8) };
      } catch (e) { it.conclusion = { conclusion: `AI の見立てが作れませんでした (${String(e.message || e).slice(0, 120)})。結果をそのまま読んでください`, affected: [], next_steps: [] }; }
    } else it.conclusion = { conclusion: 'この箱には AI が無いので見立てはありません。結果を記事と見比べてください', affected: [], next_steps: [] };
    it.state = 'done';
    // 記録には記事の全文は持たない (URL・題・要点・提案・結果の要約・見立てだけ)
    const rec = this.mm.record(actor, 'inquiry', { inquiry_id: it.id, url: it.url, final_url: it.final_url, title: it.title, text_excerpt: it.text.slice(0, 300), summary: it.plan.summary, severity: it.plan.severity, relevance: it.plan.relevance, checks: it.plan.checks.map(c => ({ target_name: c.target_name, template_id: c.template_id, params: c.params || null, why: c.why, done: !!c.done, dropped: c.dropped || null })), results: it.results.map(r => ({ target_name: r.target_name, template_label: r.template_label, record_id: r.record_id, ok: r.ok, steps: r.steps.length, error: r.error || null })), conclusion: it.conclusion });
    it.record_id = rec.id;
    audit({ actor, action: 'mamoricho.inquiry_run', target: it.id, detail: { record: rec.id, checks: todo.length, affected: it.conclusion.affected.filter(a => a.verdict === '該当のおそれ').length } });
    return this.view(it);
  }
  // 続けて聞く。AI は答えと、必要なら追加の確認 (提案に足す) を返す
  async ask(actor, { id, text } = {}) {
    requireRole(actor, 'operator'); const it = this._get(id); text = String(text || '').trim(); if (!text) throw new HttpError(400, 'bad_request', '聞きたいことを入れてください');
    it.messages.push({ role: 'user', text: text.slice(0, 2000), at: nowIso() });
    if (!this.llm) { it.messages.push({ role: 'assistant', text: 'この箱には AI が無いので答えられません。', at: nowIso() }); return this.view(it); }
    try {
      const { targets, text: ctx } = this._ctx(actor, it);
      const res = it.results.map(r => `## ${r.target_name}: ${r.template_label}\n${r.steps.map(x => `$ ${x.argv.join(' ')}\n${x.output.slice(0, 800)}`).join('\n')}`).join('\n\n');
      const hist = it.messages.slice(-8).map(m => `${m.role === 'user' ? '利用者' : 'AI'}: ${m.text}`).join('\n');
      const raw = await this._json(this._sys(), `${ctx}\n\n# これまでの下読み\n${it.plan ? JSON.stringify({ summary: it.plan.summary, relevance: it.plan.relevance, reason: it.plan.reason }) : '(無し)'}\n\n# 調べた結果\n${res || '(まだ無し)'}\n\n# 見立て\n${it.conclusion?.conclusion || '(まだ無し)'}\n\n# やりとり\n${hist}\n\n# 出力の形: answer\n{"answer": "最後の質問への答え (2〜5 文)", "checks": [{"target_id": "対象の id", "template_id": "型の id", "params": {"引数名": "値"}, "why": "何を確かめるか"}]}\nchecks は、答えるために追加で確かめたいことがあるときだけ (無ければ空)。`, 1200);
      it.messages.push({ role: 'assistant', text: str(raw.answer, 2000) || '(答えがありませんでした)', at: nowIso() });
      const more = this._normalizeChecks(raw.checks, targets).filter(c => !c.dropped && !it.plan?.checks.some(x => x.target_id === c.target_id && x.template_id === c.template_id && JSON.stringify(x.params || {}) === JSON.stringify(c.params || {})));
      if (more.length) { if (!it.plan) it.plan = { summary: '', products: [], severity: 'unknown', relevance: 'unknown', reason: '', checks: [], advice: [] }; it.plan.checks.push(...more); if (it.state === 'done') it.state = 'planned'; }
    } catch (e) { it.messages.push({ role: 'assistant', text: `AI に聞けませんでした: ${String(e.message || e).slice(0, 160)}`, at: nowIso() }); }
    return this.view(it);
  }
  get(actor, id) { requireRole(actor, 'viewer'); return this.view(this._get(id)); }
  view(it) { const { text, ...rest } = it; return { ...rest, text_excerpt: text.slice(0, 600), article_chars: text.length, live: true }; }
  list(actor) {
    requireRole(actor, 'viewer');
    const live = [...this.items.values()].map(it => ({ id: it.id, at: it.at, by_name: it.by_name, url: it.url, title: it.title, text_excerpt: it.text.slice(0, 120), state: it.state, live: true, record_id: it.record_id }));
    const liveIds = new Set(live.map(x => x.record_id).filter(Boolean));
    const recs = this.mm.records(actor, { kind: 'inquiry', limit: 100 }).filter(r => !liveIds.has(r.id)).map(r => ({ id: r.id, at: r.at, by_name: r.by_name, url: r.payload.url, title: r.payload.title, text_excerpt: r.payload.text_excerpt, state: 'done', live: false, record_id: r.id }));
    return { inquiries: [...live, ...recs].sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 50) };
  }
}
