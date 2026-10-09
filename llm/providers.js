// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳の LLM の口。provider を選べる (BuildLearn と同じ考え方)。標準は Ollama。
//   ollama / openai-compatible (llama.cpp・vLLM・LM Studio・OpenAI・Groq など /v1/chat/completions を持つもの) / anthropic。
//   返すのは ports.llm の形: { chat(messages, { temperature, max_tokens, json }) → { content, model }, model, provider, local, health() }。
//   local = 接続先が自分の箱か社内 (loopback / プライベートアドレス / .local) か。外のサービスなら「データが外に出る」と画面に出す。
import net from 'node:net';
const isPrivateHost = (host) => { const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, ''); if (!h || h === 'localhost' || /\.(local|lan|home|internal|corp|intranet)$/.test(h)) return true; const m = h.match(/^(\d+)\.(\d+)\./); if (m) { const a = +m[1], b = +m[2]; return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127); } return h === '::1' || /^f[cd]/.test(h) || !net.isIP(h) && !h.includes('.'); };
export const PROVIDERS = {
  ollama: { label: 'Ollama (標準)', base_url: 'http://127.0.0.1:11434/v1', model: 'qwen3:8b', key: false, note: 'ollama pull <model> で入れたモデル。OpenAI 互換の口 (/v1) を使う' },
  'openai-compatible': { label: 'OpenAI 互換 (llama.cpp / vLLM / LM Studio / OpenAI / Groq …)', base_url: 'http://127.0.0.1:8080/v1', model: '', key: true, note: 'base_url は /v1 まで' },
  anthropic: { label: 'Anthropic', base_url: 'https://api.anthropic.com', model: 'claude-sonnet-5-5', key: true, note: 'データは箱の外に出る' },
};
// cfg: { provider, base_url, model, api_key, timeout_ms, disable_thinking }
export function createLlm(cfg = {}) {
  const provider = PROVIDERS[cfg.provider] ? cfg.provider : 'ollama'; const def = PROVIDERS[provider];
  const base = String(cfg.base_url || def.base_url).replace(/\/$/, ''); const model = cfg.model || def.model; const key = cfg.api_key || process.env.MAMORICHO_LLM_API_KEY || '';
  const timeout = Number(cfg.timeout_ms) || 120000; let host = ''; try { host = new URL(base).hostname; } catch { host = ''; }
  const local = provider !== 'anthropic' && isPrivateHost(host);
  const fetchJson = async (url, body, headers) => {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeout) });
    if (!r.ok) { const e = new Error(`LLM ${provider} ${r.status}: ${(await r.text()).slice(0, 200)}`); e.status = r.status; throw e; }
    return r.json();
  };
  if (provider === 'anthropic') {
    return { provider, model, local, base_url: base,
      async chat(messages, { temperature = 0.2, max_tokens = 2048, json = false } = {}) {
        const sys = messages.filter(m => m.role === 'system').map(m => m.content).join('\n'); const rest = messages.filter(m => m.role !== 'system').map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content) }));
        const d = await fetchJson(base + '/v1/messages', { model, max_tokens, temperature, ...(sys ? { system: sys + (json ? '\nJSON だけを返す。' : '') } : {}), messages: rest }, { 'x-api-key': key, 'anthropic-version': '2023-06-01' });
        return { content: (d.content || []).filter(c => c.type === 'text').map(c => c.text).join(''), model: d.model || model, usage: d.usage || null };
      },
      async health() { try { const r = await fetch(base + '/v1/models', { headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' }, signal: AbortSignal.timeout(5000) }); return { ok: r.ok, status: r.status }; } catch (e) { return { ok: false, error: e.message }; } } };
  }
  const H = key ? { authorization: `Bearer ${key}` } : {};
  return { provider, model, local, base_url: base,
    async chat(messages, { temperature = 0.2, max_tokens = 2048, json = false } = {}) {
      const body = { model, messages, temperature, max_tokens }; if (cfg.disable_thinking) body.chat_template_kwargs = { enable_thinking: false };
      let d; try { d = await fetchJson(base + '/chat/completions', json ? { ...body, response_format: { type: 'json_object' } } : body, H); }
      catch (e) { if (!json || e.status !== 400) throw e; d = await fetchJson(base + '/chat/completions', body, H); } // response_format を知らないサーバーでは外して頼む (JSON は呼ぶ側が取り出す)
      const m = d.choices?.[0]?.message || {}; return { content: m.content || '', reasoning: m.reasoning_content || null, model: d.model || model, usage: d.usage || null };
    },
    async health() { try { const r = await fetch(base + '/models', { headers: H, signal: AbortSignal.timeout(5000) }); return { ok: r.ok, status: r.status }; } catch (e) { return { ok: false, error: e.message }; } } };
}
