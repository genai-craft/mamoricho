#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// 単体版の入口: mamoricho init --user owner --password ... / mamoricho serve [--port 7700] [--data ./data] / mamoricho passwd --user owner --password ...
import fs from 'node:fs';
import path from 'node:path';
import { createServer } from './server.mjs';
import { createStandalone } from './ports.mjs';

const args = process.argv.slice(2); const cmd = args[0] || 'help';
const opt = (k, fb = null) => { const i = args.indexOf('--' + k); return i >= 0 ? (args[i + 1] ?? true) : fb; };
const dataDir = path.resolve(opt('data', process.env.MAMORICHO_DATA || 'data'));
const configPath = path.join(dataDir, 'config.json');
const loadConfig = () => { let c = {}; try { c = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch { /* 無ければ既定 */ } if (process.env.MAMORICHO_LLM_PROVIDER || process.env.MAMORICHO_LLM_BASE_URL || process.env.MAMORICHO_LLM_MODEL) c.llm = { ...(c.llm || {}), ...(process.env.MAMORICHO_LLM_PROVIDER ? { provider: process.env.MAMORICHO_LLM_PROVIDER } : {}), ...(process.env.MAMORICHO_LLM_BASE_URL ? { base_url: process.env.MAMORICHO_LLM_BASE_URL } : {}), ...(process.env.MAMORICHO_LLM_MODEL ? { model: process.env.MAMORICHO_LLM_MODEL } : {}) }; return c; };
const HELP = `まもり帳 (Mamoricho) 単体版

  mamoricho init --user <名前> --password <パスワード> [--data ./data]   管理者 (owner) と鍵・設定を作る
  mamoricho serve [--port 7700] [--host 0.0.0.0] [--data ./data]          画面と API を出す
  mamoricho passwd --user <名前> --password <新しいパスワード>            パスワードを変える
  mamoricho config --llm-provider ollama --llm-base-url http://127.0.0.1:11434/v1 --llm-model qwen3:8b [--llm-api-key ...]

環境変数: MAMORICHO_DATA, MAMORICHO_PORT, MAMORICHO_ADMIN_PASSWORD (init の --password の代わり), MAMORICHO_LLM_PROVIDER / _BASE_URL / _MODEL / _API_KEY
`;
if (cmd === 'init') {
  const user = opt('user', 'owner'); const password = opt('password', process.env.MAMORICHO_ADMIN_PASSWORD || null);
  if (!password || password === true) { console.error('--password (または MAMORICHO_ADMIN_PASSWORD) が要ります'); process.exit(2); }
  const sa = createStandalone(dataDir, loadConfig());
  if (sa.auth.users().length) { console.error(`${dataDir} にはもう利用者がいます (passwd で変えてください)`); process.exit(2); }
  sa.auth.createUser(null, { username: user, password, role: 'owner', display_name: user });
  if (!fs.existsSync(configPath)) fs.writeFileSync(configPath, JSON.stringify({ port: 7700, host: '0.0.0.0', llm: { provider: 'ollama', base_url: 'http://127.0.0.1:11434/v1', model: 'qwen3:8b' } }, null, 2));
  console.log(`できました: owner=${user}、データ=${dataDir}、設定=${configPath}\n次: mamoricho serve --data ${dataDir}`);
} else if (cmd === 'passwd') {
  const sa = createStandalone(dataDir, loadConfig()); sa.auth.setPassword(opt('user', 'owner'), opt('password')); console.log('パスワードを変えました');
} else if (cmd === 'config') {
  const c = loadConfig(); c.llm = { ...(c.llm || {}) }; for (const k of ['provider', 'base_url', 'model', 'api_key']) { const v = opt('llm-' + k.replace('_', '-')); if (v && v !== true) c.llm[k] = v; }
  fs.mkdirSync(dataDir, { recursive: true }); fs.writeFileSync(configPath, JSON.stringify(c, null, 2)); console.log('設定を書きました', configPath, JSON.stringify({ ...c, llm: { ...c.llm, api_key: c.llm.api_key ? '***' : undefined } }));
} else if (cmd === 'serve') {
  const c = loadConfig(); const port = Number(opt('port', process.env.MAMORICHO_PORT || c.port || 7700)); const host = opt('host', c.host || '0.0.0.0');
  const app = createServer({ dataDir, config: c }); if (!app.auth.users().length) console.warn('利用者がいません。先に mamoricho init を実行してください');
  app.server.listen(port, host, () => { console.log(`まもり帳 ${c.tls?.cert ? 'https' : 'http'}://${host}:${port}/  (data: ${dataDir}, llm: ${app.ports.llm ? app.ports.llm.provider + ' ' + app.ports.llm.model : 'なし'})`); app.start(); });
  const stop = () => { app.stop(); process.exit(0); }; process.on('SIGINT', stop); process.on('SIGTERM', stop);
} else { console.log(HELP); process.exit(cmd === 'help' ? 0 : 2); }
