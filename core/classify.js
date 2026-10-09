// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// 調査のコマンドの判定 (まもり帳の段階 1、docs/MAMORICHO_DESIGN.md 5.1)。
//   コマンドはシェルを通さず、[プログラム, 引数...] の並びで扱う。パイプ・リダイレクト・つなぎ (; && $( ` > <) は使わせない。
//   判定は 3 つ: read (読むだけ) / change (状態を変えるおそれ。Owner の許可と理由が要る) / forbidden (使えない)。
//   ルールで決まらないものは change にする (分からないものを「読むだけ」にしない)。AI の見立て (llmJudge) は承認者への参考で、判定を軽くはしない。

const META = /[|;&`<>]|\$\(|\n/;

// 使えないもの: 消す・壊す・止める・権限や利用者を変える・任意のプログラムを動かす・別の機械へつなぐ
const FORBIDDEN = new Set(['rm', 'rmdir', 'shred', 'wipefs', 'dd', 'mkfs', 'fdisk', 'parted', 'sfdisk', 'shutdown', 'reboot', 'poweroff', 'halt', 'init', 'telinit',
  'kill', 'pkill', 'killall', 'chmod', 'chown', 'chgrp', 'chattr', 'setfacl', 'useradd', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod', 'passwd', 'chpasswd', 'visudo',
  'sudo', 'su', 'doas', 'pkexec', 'bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'python', 'python3', 'perl', 'ruby', 'node', 'php', 'lua', 'pwsh', 'powershell', 'cmd', 'eval', 'exec', 'xargs', 'env',
  'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ssh', 'scp', 'sftp', 'rsync', 'ftp', 'tftp', 'modprobe', 'insmod', 'rmmod', 'swapoff', 'swapon', 'umount', 'crontab_e', 'at', 'batch', 'nohup', 'setsid', 'screen', 'tmux']);
// 状態を変えるおそれがあるもの (書く・入れる・設定する)
const CHANGE = new Set(['mv', 'cp', 'ln', 'touch', 'mkdir', 'tee', 'truncate', 'install', 'patch', 'tar', 'unzip', 'gzip', 'gunzip', 'zip', 'pip', 'pip3', 'npm', 'npx', 'gem', 'cargo', 'go', 'make',
  'apt-get', 'yum', 'dnf', 'zypper', 'snap', 'flatpak', 'sysctl', 'hostnamectl', 'timedatectl', 'nmcli', 'ifup', 'ifdown', 'wget', 'git', 'service', 'update-rc.d', 'chkconfig', 'logrotate']);
// 読むだけ (引数の条件は下の SUB で絞る)
const READ = new Set(['cat', 'head', 'tail', 'ls', 'stat', 'file', 'wc', 'grep', 'egrep', 'fgrep', 'du', 'df', 'free', 'uptime', 'uname', 'hostname', 'id', 'whoami', 'who', 'w', 'last', 'lastb', 'lastlog',
  'ps', 'ss', 'netstat', 'lsof', 'lsblk', 'blkid', 'getent', 'sha256sum', 'sha1sum', 'md5sum', 'date', 'locale', 'lscpu', 'lspci', 'lsusb', 'dmidecode', 'arch', 'nproc', 'printenv', 'groups',
  'readlink', 'realpath', 'basename', 'lsattr', 'lsmod', 'dirname', 'sort', 'uniq', 'cut', 'tr', 'nl', 'od', 'strings', 'diff', 'cmp', 'find', 'ip', 'ifconfig', 'route', 'arp', 'dig', 'nslookup', 'host', 'openssl',
  'systemctl', 'journalctl', 'dpkg', 'dpkg-query', 'rpm', 'apt', 'apt-cache', 'docker', 'crontab', 'mount', 'iptables', 'ip6tables', 'nft', 'ufw', 'curl', 'sed', 'awk', 'show', 'display', 'get']);
// サブコマンド・オプションで読むだけか決まるもの。返り値: 'read' | 'change' | 'forbidden' | null (READ のまま)
const has = (args, ...xs) => args.some(a => xs.includes(a) || xs.some(x => x.endsWith('=') && a.startsWith(x)));
const SUB = {
  systemctl: (a) => ['status', 'list-units', 'list-unit-files', 'list-timers', 'list-sockets', 'show', 'is-enabled', 'is-active', 'is-failed', 'cat', 'get-default', '--version'].includes(a.find(x => !x.startsWith('-'))) ? 'read' : 'change',
  journalctl: (a) => has(a, '--vacuum-size', '--vacuum-time', '--vacuum-files', '--rotate', '--flush', '--sync', '--relinquish-var', '--setup-keys', '--vacuum-size=', '--vacuum-time=', '--vacuum-files=') ? 'change' : 'read',
  dpkg: (a) => has(a, '-l', '--list', '-L', '--listfiles', '-s', '--status', '-V', '--verify', '-S', '--search', '--print-architecture', '--version') && !has(a, '-i', '--install', '-r', '--remove', '-P', '--purge', '--configure', '--unpack') ? 'read' : 'change',
  rpm: (a) => a.some(x => /^-(q|V)/.test(x) || x === '--verify' || x === '--query') && !a.some(x => /^-(i|U|F|e)/.test(x) || ['--install', '--upgrade', '--erase', '--import'].includes(x)) ? 'read' : 'change',
  apt: (a) => ['list', 'show', 'policy', 'search', 'depends', 'rdepends', 'changelog'].includes(a.find(x => !x.startsWith('-'))) ? 'read' : 'change',
  'apt-cache': () => 'read',
  docker: (a) => ['ps', 'images', 'inspect', 'info', 'version', 'logs', 'stats', 'top', 'port', 'history', 'diff'].includes(a.find(x => !x.startsWith('-'))) && !has(a, '--follow', '-f') ? 'read' : 'change',
  crontab: (a) => a.length === 1 && a[0] === '-l' || (a.length === 3 && a[0] === '-l' && a[1] === '-u') || (a.length === 3 && a[0] === '-u' && a[2] === '-l') ? 'read' : 'forbidden',
  mount: (a) => a.length === 0 || (a.length <= 2 && a.every(x => ['-l', '-t'].includes(x) || /^[a-z0-9]+$/.test(x))) ? 'read' : 'change',
  iptables: (a) => has(a, '-L', '--list', '-S', '--list-rules', '-n', '-v', '--line-numbers', '-t') && !has(a, '-A', '-I', '-D', '-R', '-F', '-X', '-P', '-N', '-Z', '--append', '--insert', '--delete', '--flush', '--policy') ? 'read' : 'change',
  nft: (a) => a[0] === 'list' ? 'read' : 'change',
  ufw: (a) => a[0] === 'status' ? 'read' : 'change',
  ip: (a) => { const v = a.filter(x => !x.startsWith('-')); return v.length <= 1 || ['show', 'list', 'get', 'ls'].includes(v[1]) ? 'read' : 'change'; },
  find: (a) => has(a, '-delete', '-exec', '-execdir', '-ok', '-okdir', '-fprint', '-fprint0', '-fprintf', '-fls') ? 'forbidden' : 'read',
  sed: (a) => a.some(x => x === '-i' || x.startsWith('-i') || x.startsWith('--in-place')) ? 'change' : 'read',
  awk: (a) => a.some(x => /system\s*\(|\|\s*"|print\s*>|getline/.test(x)) ? 'forbidden' : 'read',
  curl: (a) => has(a, '-o', '--output', '-O', '--remote-name', '-T', '--upload-file', '-d', '--data', '--data-binary', '--data-raw', '--data-urlencode', '-F', '--form', '-K', '--config') || a.some((x, i) => (x === '-X' || x === '--request') && !['GET', 'HEAD'].includes(String(a[i + 1]).toUpperCase())) ? 'change' : 'read',
  openssl: (a) => ['x509', 's_client', 'version', 'verify', 'ciphers', 'crl', 'asn1parse', 'dgst'].includes(a[0]) && !has(a, '-out', '-keyout') ? 'read' : 'change',
  printenv: () => 'read', // 出力は保存前に伏せ字にする (鍵が混じることがある)
  show: () => 'read', display: () => 'read', get: () => 'read', // ネットワーク機器・Windows の読み取り
};

// argv: string[]。target_kind はいまは判定に使わない (将来、機器ごとの決まりを足す)
import { ROOT_STEPS } from './rootsteps.js';
const ROOT_ALLOWED = new Set(Object.values(ROOT_STEPS).flat().map(a => JSON.stringify(a)));
export function classifyCommand(argv, { target_kind = 'ssh' } = {}) {
  const reasons = [];
  // root の読み取り: sudo -n + rootsteps.js の完全一致のコマンドだけ (それ以外の sudo は使えない)
  if (Array.isArray(argv) && argv[0] === 'sudo') {
    if (argv[1] === '-n' && ROOT_ALLOWED.has(JSON.stringify(argv.slice(2)))) return { class: 'read', reasons: ['root でしか読めないものを、決まったコマンドで読む (sudoers に完全一致で書いたもの)'], by: 'rule', program: argv[2], root: true };
    return { class: 'forbidden', reasons: ['sudo は、まもり帳が決めた読むだけのコマンドにしか使えません'], by: 'rule', program: 'sudo' };
  }
  if (!Array.isArray(argv) || !argv.length || argv.some(x => typeof x !== 'string')) return { class: 'forbidden', reasons: ['コマンドは [プログラム, 引数...] の並びで渡してください'], by: 'rule' };
  if (argv.length > 40 || argv.some(x => x.length > 400)) return { class: 'forbidden', reasons: ['コマンドが長すぎます (40 個・1 つ 400 文字まで)'], by: 'rule' };
  if (argv.some(x => META.test(x))) return { class: 'forbidden', reasons: ['パイプ・リダイレクト・つなぎ (| ; & > < $( ` 改行) は使えません。1 つのコマンドにしてください'], by: 'rule' };
  const prog = String(argv[0]).split('/').pop().toLowerCase(); const args = argv.slice(1);
  if (prog === 'crontab' && args.includes('-e')) return { class: 'forbidden', reasons: ['crontab の書き換えは使えません'], by: 'rule' };
  if (FORBIDDEN.has(prog)) { reasons.push(`${prog} は使えません (消す・止める・権限を変える・任意のプログラムを動かす・別の機械へつなぐもの)`); return { class: 'forbidden', reasons, by: 'rule', program: prog }; }
  if (CHANGE.has(prog)) { reasons.push(`${prog} は状態を変えるおそれがあります`); return { class: 'change', reasons, by: 'rule', program: prog }; }
  if (READ.has(prog)) {
    const sub = SUB[prog]?.(args, target_kind) || 'read';
    if (sub === 'read') return { class: 'read', reasons: [`${prog} は読むだけ`], by: 'rule', program: prog };
    reasons.push(sub === 'forbidden' ? `${prog} のこの使い方は使えません` : `${prog} のこの使い方は状態を変えるおそれがあります`);
    return { class: sub, reasons, by: 'rule', program: prog };
  }
  reasons.push(`${prog} はルールで判定できません。状態を変えるおそれがあるものとして扱います`);
  return { class: 'change', reasons, by: 'unknown', program: prog };
}

// ---- AI の見立て (OpenVons 型の選択肢判断) ----
//   decision_head (Akigrid /v1/decision の head 名) が設定されていればそれを使う。無ければ、箱の LLM に A/B/C の 1 文字で答えさせ、
//   先頭トークンの確率 (logprobs) を読む。どちらも承認者への参考で、classifyCommand の判定を軽くはしない
const CHOICES = [{ id: 'read', letter: 'A', description: '読むだけ (何も変えない)' }, { id: 'change', letter: 'B', description: '状態を変えるおそれがある (書く・入れる・設定する・止める)' }, { id: 'forbidden', letter: 'C', description: '危険 (消す・壊す・権限を変える・外へ送る)' }];
export async function llmJudge(argv, { akigrid, head = null, explanation = '' } = {}) {
  const cmd = argv.map(a => (/^[A-Za-z0-9_./:=@%+,-]+$/.test(a) ? a : JSON.stringify(a))).join(' ');
  const state = `コマンド: ${cmd}\n提案者の説明: ${String(explanation).slice(0, 400)}`;
  try {
    if (head) {
      const r = await akigrid.req('/v1/decision', { method: 'POST', tenant: true, timeout_ms: 60000, body: { head, state, questions: [{ key: 'risk', type: 'choice', question: 'このコマンドを調査対象の機械で実行したときの影響はどれか', choices: CHOICES.map(({ id, description }) => ({ id, description })) }] } });
      const p = r?.results?.risk?.probabilities; if (p) return { probabilities: p, via: `decision:${head}` };
    }
    const prompt = `次のコマンドを、調査対象の機械で実行したときの影響を 1 文字で答えてください。\nA: ${CHOICES[0].description}\nB: ${CHOICES[1].description}\nC: ${CHOICES[2].description}\n\n${state}\n\n答え (A か B か C の 1 文字):`;
    const r = await akigrid.req('/v1/chat/completions', { method: 'POST', tenant: true, timeout_ms: 60000, body: { model: 'llm_chat_quality', messages: [{ role: 'user', content: prompt }], max_tokens: 1, temperature: 0, logprobs: true, top_logprobs: 10, chat_template_kwargs: { enable_thinking: false } } });
    const tops = r?.choices?.[0]?.logprobs?.content?.[0]?.top_logprobs || [];
    const p = { read: 0, change: 0, forbidden: 0 };
    for (const t of tops) { const k = String(t.token || '').trim().toUpperCase(); const c = CHOICES.find(x => x.letter === k); if (c) p[c.id] += Math.exp(t.logprob); }
    const sum = p.read + p.change + p.forbidden; if (!sum) return { probabilities: null, via: 'logprobs', note: '確率を読めませんでした' };
    for (const k of Object.keys(p)) p[k] = Math.round(p[k] / sum * 1000) / 1000;
    return { probabilities: p, via: 'logprobs' };
  } catch (e) { return { probabilities: null, via: head ? `decision:${head}` : 'logprobs', note: `AI の見立てを取れませんでした: ${String(e.message || e).slice(0, 120)}` }; }
}
