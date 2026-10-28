#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// 経済産業省「★3・★4要求事項及び評価基準」(Excel) から core/scs-criteria.js を作る (原文はそのまま。読みがなだけ落とす)。
//   使い方: node tools/scs-import.mjs <scs_3.xlsx> [取得した日 YYYY-MM-DD] > core/scs-criteria.js
//   新しい版が出たら、Excel を取り直してこれを流し、core/scs-guide.js (ふつうの言葉の質問など) の過不足をテストで確かめる
import fs from 'node:fs';
import { unzip, xmlText } from '../core/zip.js';

const [file, fetched = new Date().toISOString().slice(0, 10)] = process.argv.slice(2);
if (!file) { console.error('使い方: node tools/scs-import.mjs <scs_3.xlsx> [取得した日]'); process.exit(2); }
const z = unzip(fs.readFileSync(file));
const strings = [...z.text('xl/sharedStrings.xml').replace(/<rPh[\s\S]*?<\/rPh>/g, '').matchAll(/<si>([\s\S]*?)<\/si>/g)].map(m => xmlText([...m[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map(t => t[1]).join('')));
const cellText = (attrs, inner) => { const v = /<v>([\s\S]*?)<\/v>/.exec(inner || '')?.[1]; if (/t="s"/.test(attrs) && v != null) return strings[Number(v)]; if (/t="inlineStr"/.test(attrs)) return xmlText([...(inner || '').matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map(t => t[1]).join('')); return v != null ? xmlText(v) : ''; };
const rows = [...z.text('xl/worksheets/sheet1.xml').matchAll(/<row [^>]*>([\s\S]*?)<\/row>/g)].map(r => Object.fromEntries([...r[1].matchAll(/<c r="([A-Z]+)\d+"([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)].map(c => [c[1], cellText(c[2], c[3]).replace(/\r\n?/g, '\n').trim()])));
const clean = (s) => String(s || '').replace(/^・/, '').replace(/[ \t]+\n/g, '\n').trim();
const out = [];
for (const r of rows.slice(1)) {
  if (!r.L || !/^\d+-\d+-\d+-\d+$/.test(r.L)) continue;
  out.push({ id: r.L, level: r.K === '★3' ? 3 : 4, req: r.F, req_name: r.I, req_text: clean(r.J), req_in3: r.G === '○', cat_no: Number(r.B), cat: r.C, sub_no: r.D, sub: r.E, text: clean(r.M), csf: r.N || '' });
}
const n3 = out.filter(x => x.level === 3).length; const reqs = new Set(out.map(x => x.req)); const reqs3 = new Set(out.filter(x => x.req_in3).map(x => x.req));
if (!out.length) { console.error('評価基準が読めませんでした'); process.exit(1); }
console.error(`評価基準 ${out.length} (★3 ${n3} / ★4 で追加 ${out.length - n3})・要求事項 ${reqs.size} (★3 ${reqs3.size})`);
process.stdout.write(`// SPDX-License-Identifier: Apache-2.0 AND LicenseRef-PDL-1.0
// 出典: 「★3・★4要求事項及び評価基準」(経済産業省) https://www.meti.go.jp/policy/netsecurity/docs/scs/scs_3.xlsx (${fetched}に利用)。
//   公共データ利用規約 (第1.0版) に従って利用しています。要求事項・評価基準の文言は原文のまま (読みがなを落とし、行頭の「・」を外しただけ)。
//   このファイルは tools/scs-import.mjs が作ります。手で直さないでください。ふつうの言葉の質問などは core/scs-guide.js (生成AI工房が作成。国の公式の文言ではありません)
export const SCS_SOURCE = ${JSON.stringify({ title: '★3・★4要求事項及び評価基準', publisher: '経済産業省', url: 'https://www.meti.go.jp/policy/netsecurity/docs/scs/scs_3.xlsx', page: 'https://www.meti.go.jp/policy/netsecurity/scs.html', used_at: fetched, license: '公共データ利用規約 (第1.0版)', note: '要求事項・評価基準は原文のまま。ふつうの言葉の質問・手がかり・規程のひな形は生成AI工房が作成したもので、国の公式の文言ではありません。★の取得は、制度の手続き (★3 はセキュリティ専門家の確認を経た自己評価、★4 は評価機関の評価) によります' })};
export const SCS_CRITERIA = [
${out.map(x => '  ' + JSON.stringify(x)).join(',\n')},
];
`);
