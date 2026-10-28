// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// Word (.docx) の最小の読み書き。読む: 本文の段落と表のセルを文字にする (レビュー用)。書く: 規程の Markdown (見出し・段落・箇条書き・表・太字) を .docx にする
import { unzip, zip, xmlText, xmlEsc } from './zip.js';

// .docx → 段落の文字 (表のセルも 1 つずつ段落として。改行は段落の区切り)
export function docxText(buf) {
  const z = unzip(buf); const xml = z.text('word/document.xml'); if (!xml) throw new Error('Word の本文 (word/document.xml) がありません');
  const body = xml.replace(/<w:del\b[\s\S]*?<\/w:del>/g, ''); // 変更履歴で消した文字は読まない
  const paras = [];
  for (const m of body.matchAll(/<w:p[ >][\s\S]*?<\/w:p>|<w:p\/>/g)) {
    const p = m[0].replace(/<w:tab\/>/g, '<w:t>\t</w:t>').replace(/<w:br[^>]*\/>/g, '<w:t>\n</w:t>');
    const t = [...p.matchAll(/<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>/g)].map(x => xmlText(x[1])).join('');
    const style = /<w:pStyle w:val="([^"]+)"/.exec(p)?.[1] || ''; const hn = /^Heading(\d)$/i.exec(style)?.[1]; const lvl = /^Title$/i.test(style) ? 1 : hn ? Math.min(6, Number(hn) + 1) : 0; // 書き出しと同じ対応 (# = 表題、## = 見出し 1)
    if (t.trim()) paras.push(lvl ? `${'#'.repeat(lvl)} ${t.trim()}` : t);
  }
  return paras.join('\n');
}

const run = (text, bold = false) => `<w:r>${bold ? '<w:rPr><w:b/></w:rPr>' : ''}<w:t xml:space="preserve">${xmlEsc(text)}</w:t></w:r>`;
// **太字** だけ解釈する
const runs = (s) => String(s).split(/(\*\*[^*]+\*\*)/).filter(Boolean).map(x => (x.startsWith('**') && x.endsWith('**') ? run(x.slice(2, -2), true) : run(x))).join('');
const para = (s, style = null, extra = '') => `<w:p>${style || extra ? `<w:pPr>${style ? `<w:pStyle w:val="${style}"/>` : ''}${extra}</w:pPr>` : ''}${runs(s)}</w:p>`;
const table = (rows) => {
  const cells = (r, head) => r.map(c => `<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/>${head ? '<w:shd w:val="clear" w:color="auto" w:fill="EEF2F7"/>' : ''}</w:tcPr>${para(head ? `**${c}**` : c)}</w:tc>`).join('');
  return `<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>${['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map(b => `<w:${b} w:val="single" w:sz="4" w:space="0" w:color="A0A8B8"/>`).join('')}</w:tblBorders></w:tblPr>${rows.map((r, i) => `<w:tr>${cells(r, i === 0)}</w:tr>`).join('')}</w:tbl>${para('')}`;
};
export function mdToDocxXml(md) {
  const out = []; const lines = String(md).replace(/\r\n?/g, '\n').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/^\s*\|/.test(l)) { const rows = []; while (i < lines.length && /^\s*\|/.test(lines[i])) { const r = lines[i].trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim()); if (!r.every(c => /^:?-{2,}:?$/.test(c))) rows.push(r); i++; } i--; out.push(table(rows)); continue; }
    const h = /^(#{1,3})\s+(.*)$/.exec(l); if (h) { out.push(para(h[2], h[1].length === 1 ? 'Title' : `Heading${h[1].length - 1}`)); continue; }
    const li = /^\s*(-|\d+\.)\s+(.*)$/.exec(l); if (li) { out.push(para(`${li[1] === '-' ? '・' : li[1] + ' '}${li[2]}`, null, '<w:ind w:left="420" w:hanging="210"/>')); continue; }
    if (!l.trim()) continue;
    out.push(para(l));
  }
  return out.join('');
}
const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Yu Gothic" w:hAnsi="Yu Gothic" w:eastAsia="游ゴシック"/><w:sz w:val="21"/><w:lang w:val="en-US" w:eastAsia="ja-JP"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="80" w:line="300" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:jc w:val="center"/><w:spacing w:after="240"/></w:pPr><w:rPr><w:b/><w:sz w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="60"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>`;
export function mdToDocx(md, { title = '規程', author = '' } = {}) {
  const doc = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>${mdToDocxXml(md)}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1418" w:right="1304" w:bottom="1418" w:left="1304" w:header="709" w:footer="709" w:gutter="0"/></w:sectPr></w:body></w:document>`;
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  return zip([
    { name: '[Content_Types].xml', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>' },
    { name: '_rels/.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>' },
    { name: 'word/_rels/document.xml.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>' },
    { name: 'word/document.xml', data: doc },
    { name: 'word/styles.xml', data: STYLES },
    { name: 'docProps/core.xml', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>${xmlEsc(title)}</dc:title><dc:creator>${xmlEsc(author)}</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">${now}</dcterms:created></cp:coreProperties>` },
  ]);
}
