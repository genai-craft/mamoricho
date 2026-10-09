// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// このパッケージは、node の標準モジュールとパッケージの中しか import しない。組み込み先 (言箱 OS など) が差し出すものは全部 ports.js の口を通る。
//   これが守られている限り、組み込み先で足した機能はそのまま単体版 (公開版) に出せる
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const PKG = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? (['node_modules', 'data', '.git'].includes(e.name) ? [] : walk(path.join(d, e.name))) : /\.m?js$/.test(e.name) ? [path.join(d, e.name)] : []);
const SELF = fileURLToPath(import.meta.url); const OUTSIDE = ["getDb(", "process.env.AIOS_", "from '../../"]; // 目印の文字列を含むこのファイル自身は見ない
test('import は node: とパッケージの中だけ (組み込み先の db / auth / vault / audit を直接見ない)', () => {
  const bad = [];
  for (const f of walk(PKG)) {
    if (f === SELF) continue;
    const src = fs.readFileSync(f, 'utf8');
    for (const m of src.matchAll(/^\s*(?:import|export)\s[^'"\n]*?from\s+['"]([^'"]+)['"]/gm)) {
      const spec = m[1]; if (spec.startsWith('node:')) continue;
      if (!spec.startsWith('.')) { bad.push(`${path.relative(PKG, f)}: ${spec} (外部パッケージ)`); continue; }
      const target = path.resolve(path.dirname(f), spec); if (!target.startsWith(PKG + path.sep)) bad.push(`${path.relative(PKG, f)}: ${spec} → ${target}`);
    }
    for (const w of OUTSIDE) if (src.includes(w) && !f.endsWith('ports.js')) bad.push(`${path.relative(PKG, f)}: ${w.trim()} を使っている`);
  }
  assert.deepEqual(bad, [], '境界を越えている import:\n' + bad.join('\n'));
  assert.ok(walk(PKG).length >= 14, 'パッケージのファイルが少なすぎる (移動に失敗?)');
});
