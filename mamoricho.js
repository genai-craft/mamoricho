// まもり帳 (docs/MAMORICHO_DESIGN.md)。平時の点検 = 聞き取り → 確かめる → 記録 → 宿題 → 定期の見直し。
//   骨格はルール: 点検の項目 (checklist.js) は固定、言箱自身の自己点検は機械的、記録は 1 件ごとに前のハッシュを含めて箱の鍵で署名 (後から書き換えると分かる)。
//   AI は「利用者の答えを状態に翻訳して提案する」役だけ (interview)。状態を決めるのは人。「安全」とは言わせない。
import crypto from 'node:crypto';
import { getDb, J, metaGet } from '../db.js';
import { HttpError, id, nowIso, sha256, redact } from '../util.js';
import { audit } from '../audit.js';
import { requireRole, listUsers } from '../auth.js';
import { ensureLocalPublisherKey } from '../signing.js';
import { notify } from '../notify.js';
import * as mfa from '../mfa.js';
import { timeStatus } from '../timesync.js';
import { ITEMS, CATEGORIES, BASELINE, STATUSES, byId } from './checklist.js';
import { ROOT_STEPS } from '../probe/rootsteps.js';
import { OUTPUT_KEEP, NO_OUTPUT, STDERR_MARK } from '../probe/probe.js';

export const TEMPLATES = [
  // 読むだけの調査の型。OS の版と一緒に配られる (= 署名つき)。各 step は probe の判定 (read) を通ったものだけ使う
  { id: 'linux.basic', kind: ['ssh'], label: '基本 (OS・起動時間・ログイン中)', steps: [['uname', '-a'], ['uptime'], ['who'], ['cat', '/etc/os-release']] },
  { id: 'linux.ports', kind: ['ssh'], label: '待ち受けているポート', steps: [['ss', '-tlnpH'], ['ss', '-ulnH'], ['netstat', '-tln']] },
  { id: 'linux.logins', kind: ['ssh'], label: '最近のログイン', steps: [['last', '-n', '30', '-F'], ['lastlog']] },
  { id: 'linux.users', kind: ['ssh'], label: 'アカウントと管理者', steps: [['getent', 'passwd'], ['getent', 'group', 'sudo'], ['getent', 'group', 'wheel'], ['getent', 'group', 'docker']] },
  { id: 'linux.autostart', kind: ['ssh'], label: '自動で動くもの (タイマー・cron)', steps: [['systemctl', 'list-timers', '--all', '--no-pager'], ['crontab', '-l'], ['ls', '-la', '/etc/cron.d', '/etc/cron.daily'], ['cat', '/etc/crontab']] },
  { id: 'linux.updates', kind: ['ssh'], label: '更新の状況', steps: [['apt', 'list', '--upgradable'], ['ls', '-la', '--time-style=long-iso', '/var/log/apt'], ['tail', '-n', '40', '/var/log/apt/history.log'], ['cat', '/etc/apt/apt.conf.d/20auto-upgrades']] },
  { id: 'linux.ssh', kind: ['ssh'], label: 'SSH の設定', steps: [['cat', '/etc/ssh/sshd_config'], ['ls', '-la', '/etc/ssh/sshd_config.d'], ['cat', '/root/.ssh/authorized_keys']] },
  { id: 'linux.firewall', kind: ['ssh'], label: 'ファイアウォール', steps: [['ufw', 'status', 'verbose'], ['iptables', '-L', '-n', '--line-numbers'], ['nft', 'list', 'ruleset']] },
  { id: 'linux.docker', kind: ['ssh'], label: 'コンテナ', steps: [['docker', 'ps', '-a'], ['docker', 'images']] },
  { id: 'linux.webroot', kind: ['ssh'], label: '公開フォルダで最近変わったファイル (7 日)', steps: [['find', '/var/www', '-type', 'f', '-mtime', '-7', '-newer', '/etc/hostname'], ['find', '/var/www', '-type', 'f', '-name', '*.php', '-mtime', '-7']] },
  { id: 'linux.backup', kind: ['ssh'], label: 'バックアップの実態 (最終更新)', steps: [['ls', '-la', '--time-style=long-iso', '/backup'], ['ls', '-la', '--time-style=long-iso', '/mnt/backup'], ['ls', '-la', '--time-style=long-iso', '/var/backups'], ['df', '-h']] },
  { id: 'web.head', kind: ['web'], label: '応答とヘッダ (証明書・セキュリティヘッダ)', steps: [['curl', '-I', '-v', '/']] },
  { id: 'web.redirect', kind: ['web'], label: 'http で来た人を https へ誘導しているか', steps: [['curl', '-I', '--plain-http', '/']] },
  // トップページの中身は毎回少しずつ変わる (日時・トークン) ので生の差分は取らず、構造 (外部スクリプト・送り先・証明書・向き先) の変化で比べる (digest)
  { id: 'web.home', kind: ['web'], label: 'トップページの中身 (改ざんの痕跡・外部への送り先・検索エンジン向けの偽装)', nodiff: true, steps: [['curl', '/'], ['curl', '-A', 'googlebot', '/']] },
  { id: 'web.dns', kind: ['web'], label: 'DNS (名前の向き先・なりすましメール対策 SPF/DMARC)', steps: [['dig', '+short', 'A', '{host}'], ['dig', '+short', 'NS', '{apex}'], ['dig', '+short', 'MX', '{apex}'], ['dig', '+short', 'TXT', '{apex}'], ['dig', '+short', 'TXT', '_dmarc.{apex}'], ['dig', '+short', 'CAA', '{apex}']] },
  { id: 'web.exposed', kind: ['web'], label: '出てはいけないファイル・開けてはいけない場所', steps: [['curl', '-I', '/mamoricho-check-this-page-should-not-exist'], ['curl', '-I', '/.git/HEAD'], ['curl', '-I', '/.git/config'], ['curl', '-I', '/.env'], ['curl', '-I', '/.htpasswd'], ['curl', '-I', '/wp-config.php.bak'], ['curl', '-I', '/config.php.bak'], ['curl', '-I', '/backup.zip'], ['curl', '-I', '/backup.tar.gz'], ['curl', '-I', '/dump.sql'], ['curl', '-I', '/db.sql'], ['curl', '-I', '/id_rsa'], ['curl', '-I', '/.aws/credentials'], ['curl', '-I', '/phpinfo.php'], ['curl', '-I', '/.DS_Store'], ['curl', '-I', '/wp-content/debug.log'], ['curl', '-I', '/server-status'], ['curl', '-I', '/wp-login.php'], ['curl', '-I', '/administrator/'], ['curl', '-I', '/phpmyadmin/'], ['curl', '-I', '/xmlrpc.php'], ['curl', '-I', '/wp-json/wp/v2/users']] },
  { id: 'web.robots', kind: ['web'], label: 'robots・security.txt・版の目印', steps: [['curl', '/robots.txt'], ['curl', '/.well-known/security.txt'], ['curl', '-I', '/readme.html'], ['curl', '-I', '/wp-json/']] },
  // ネットワーク機器は機種で命令が違う (Cisco 系 running-config / YAMAHA config / Fortigate system status)。無い命令は「この機械には無い」で済む
  { id: 'network.show', kind: ['network'], label: 'ネットワーク機器の版と設定 (show)', steps: [['show', 'version'], ['show', 'running-config'], ['show', 'config'], ['show', 'system', 'status']] },
  { id: 'network.state', kind: ['network'], label: 'ネットワーク機器の状態 (利用者・インターフェース・時刻・ログ)', steps: [['show', 'users'], ['show', 'ip', 'interface', 'brief'], ['show', 'clock'], ['show', 'environment'], ['show', 'logging']] },
  // ---- 初動 (有事) 向け。消えやすい順に読む。平時の記録があれば、前回との差分が出る
  { id: 'linux.processes', kind: ['ssh'], label: '動いているプロセス', incident: true, steps: [['ps', 'auxww']] },
  { id: 'linux.connections', kind: ['ssh'], label: '通信の相手 (つながっている先)', incident: true, steps: [['ss', '-tnpH', 'state', 'established'], ['netstat', '-tn']] },
  { id: 'linux.rootusers', kind: ['ssh'], label: '管理者と同じ権限 (UID 0) のアカウント', incident: true, steps: [['awk', '-F:', '$3==0{print}', '/etc/passwd'], ['getent', 'group', 'sudo'], ['getent', 'group', 'wheel']] },
  { id: 'linux.authkeys', kind: ['ssh'], label: '鍵でのログインが許されている先 (authorized_keys)', incident: true, steps: [['find', '/home', '/etc/ssh', '-name', 'authorized_keys', '-type', 'f']] },
  { id: 'linux.sudoers', kind: ['ssh'], label: 'sudo の設定', incident: true, steps: [['ls', '-la', '/etc/sudoers.d']] },
  { id: 'linux.preload', kind: ['ssh'], label: '仕込みに使われる場所 (ld.so.preload・rc.local・profile.d)', incident: true, steps: [['cat', '/etc/ld.so.preload'], ['cat', '/etc/rc.local'], ['ls', '-la', '--time-style=long-iso', '/etc/profile.d']] },
  { id: 'linux.trojan', kind: ['ssh'], label: '乗っ取り・トロイの木馬のよくある痕跡 (一時フォルダ・cron・DNS・属性・カーネル)', incident: true, steps: [
    ['find', '/tmp', '/var/tmp', '/dev/shm', '-xdev', '-type', 'f', '(', '-perm', '-u+x', '-o', '-name', '.*', ')', '-ls'],
    ['cat', '/etc/crontab'], ['ls', '-la', '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly'],
    ['grep', '-rsH', '-e', 'curl ', '-e', 'wget ', '-e', 'base64', '-e', '/tmp/', '-e', '/dev/shm', '-e', 'bash -i', '-e', 'nc ', '-e', 'python -c', '-e', 'perl -e', '/etc/crontab', '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/rc.local', '/etc/profile.d', '/etc/profile', '/etc/bash.bashrc'],
    ['find', '/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system', '-xdev', '-type', 'f', '-mtime', '-7'],
    ['lsattr', '/etc/passwd', '/etc/group', '/etc/hosts', '/etc/resolv.conf', '/etc/crontab'], ['cat', '/etc/hosts'], ['cat', '/etc/resolv.conf'], ['lsmod']] },
  { id: 'linux.suid', kind: ['ssh'], label: '特権で動くプログラム (SUID)', incident: true, steps: [['find', '/', '-xdev', '-perm', '-4000', '-type', 'f']] },
  { id: 'linux.integrity', kind: ['ssh'], label: 'パッケージの改ざん確認 (dpkg -V / rpm -Va)', incident: true, steps: [['dpkg', '-V'], ['rpm', '-Va']] },
  { id: 'linux.recent_etc', kind: ['ssh'], label: '3 日以内に変わった設定・プログラム', incident: true, steps: [['find', '/etc', '/usr/bin', '/usr/sbin', '/usr/local/bin', '-xdev', '-type', 'f', '-mtime', '-3']] },
  { id: 'linux.logs_auth', kind: ['ssh'], label: 'ログインのログ (直近)', incident: true, steps: [['last', '-n', '30', '-F']] },
];
// 初動セット: 消えやすいものから順に (メモリの中身 → 通信 → ログイン → 仕込まれやすい場所 → ログ)
export const INCIDENT_SET = ['linux.processes', 'linux.connections', 'linux.logins', 'linux.rootusers', 'linux.users', 'linux.authkeys', 'linux.sudoers', 'linux.autostart', 'linux.preload', 'linux.trojan', 'linux.ports', 'linux.suid', 'linux.integrity', 'linux.recent_etc', 'linux.webroot', 'linux.docker', 'linux.logs_auth'];

// 行の差分 (順序は問わない): 増えた行と消えた行。時刻や PID のような毎回変わる値は、荒く正規化して比べる
// 乗っ取り・トロイの木馬の兆候を探すセット (平時の「気休め程度」の確認用。初動セットとほぼ同じ材料を、痕跡の判定つきで)
export const COMPROMISE_SET = ['linux.trojan', 'linux.processes', 'linux.connections', 'linux.ports', 'linux.rootusers', 'linux.authkeys', 'linux.sudoers', 'linux.autostart', 'linux.preload', 'linux.suid', 'linux.integrity', 'linux.recent_etc', 'linux.logs_auth'];
// まとめて診断 = 対象のふつうの型 (ボタンの並び) + 兆候のセット。1 回でスナップショットを作り、前回と比べる
export const FULL_SET = [...new Set([...TEMPLATES.filter(t => t.kind.includes('ssh') && !t.incident).map(t => t.id), ...COMPROMISE_SET])];
export const SETS = {
  full: { label: 'まとめて診断', kinds: ['ssh', 'web', 'network'], ids: (kind) => (kind === 'ssh' ? FULL_SET : TEMPLATES.filter(t => t.kind.includes(kind) && !t.incident).map(t => t.id)), signs: true, note: 'その対象のすべての型を 1 回で流し、兆候の目安をつけてスナップショットとして残します' },
  compromise: { label: '乗っ取り・トロイの木馬の兆候', kinds: ['ssh'], ids: () => COMPROMISE_SET, signs: true, note: 'よくある手口の痕跡を読むだけで探します。見つからなくても安全とは言えません' },
  incident: { label: '初動セット', kinds: ['ssh'], ids: () => INCIDENT_SET, signs: true, note: '消えやすいものから順に読み、前回との差分を先に出します' },
};
export const setIds = (set, kind) => (SETS[set] && SETS[set].kinds.includes(kind) ? SETS[set].ids(kind) : []);
const SIGN_RULES_NOTE = '機械的な目安です。見つからなくても「安全」という意味ではありません (巧妙なものは隠れます・ここで分かるのは一部です)。見つかったものも、正規の運用で説明がつくことがあります';
const BAD_NAMES = /\b(xmrig|kdevtmpfsi|kinsing|minerd|cryptonight|xmr-stak|cpuminer|tsunami|watchbog|sustes|kworkerds|bioset|\.x)\b/i;
const TMP_PATH = /(^|\s)(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/;
const BAD_PORTS = new Set(['4444', '1337', '31337', '6667', '6697', '3333', '14444', '5555', '7777', '9999']);
const stepsOf = (sections, template_id, pick) => (sections.find(s => s.template_id === template_id)?.results || sections.find(s => s.template_id === template_id)?.steps || []).filter(x => !pick || pick(x));
// 兆候の判定は標準出力だけを見る (エラー出力は「読めなかった」の知らせで、痕跡ではない)
const linesOf = (x) => String(x?.output || '').split(STDERR_MARK)[0].split('\n').map(l => l.trim()).filter(l => l && l !== NO_OUTPUT && !/^(\/usr\/bin\/)?(find|ls|cat|grep|lsattr|lsmod|getent|awk|ps|ss|netstat|sudo): /.test(l) && !/^ERROR: ld\.so/.test(l));
// ---- 公開 HP: 読んだ応答の整理 (digest) と兆候 ----
const statusOf = (out) => { const m = String(out || '').match(/^HTTP\/[\d.]+\s+(\d{3})/m); return m ? Number(m[1]) : null; };
const headersOf = (out) => { const h = {}; for (const l of String(out || '').split(STDERR_MARK)[0].split('\n')) { const m = l.match(/^([A-Za-z0-9-]+):\s*(.*)$/); if (m) h[m[1].toLowerCase()] = (h[m[1].toLowerCase()] ? h[m[1].toLowerCase()] + ', ' : '') + m[2].trim(); } return h; };
const hostOf = (u) => { const m = String(u || '').match(/^(?:https?:)?\/\/([^/:?#]+)/i); return m ? m[1].toLowerCase() : null; };
const isOwnHost = (h, host) => { if (!h) return true; const apex = String(host).replace(/^www\./, '').toLowerCase(); h = h.toLowerCase(); return h === host.toLowerCase() || h === apex || h.endsWith('.' + apex); };
const bodyOf = (x) => String(x?.output || '').split(STDERR_MARK)[0];
const titleOf = (html) => (String(html).match(/<title[^>]*>([^<]{0,200})<\/title>/i)?.[1] || '').replace(/\s+/g, ' ').trim();
const attrs = (html, tag, attr) => [...String(html).matchAll(new RegExp(`<${tag}\\b[^>]*?\\s${attr}\\s*=\\s*["']?([^"'\\s>]+)`, 'gi'))].map(m => m[1]);
const SPAM = /viagra|cialis|casino|カジノ|スーパーコピー|ブランドコピー|偽ブランド|replica (?:watches|bags)|出会い系|闇金|オンラインカジノ|payday loan/i;
// curl -v の証明書の行 (*  expire date: Oct  8 00:00:00 2026 GMT)
const certOf = (out) => { const err = String(out || '').split(STDERR_MARK)[1] || ''; const g = (k) => err.match(new RegExp(`^\\*\\s+${k}:\\s*(.+)$`, 'm'))?.[1]?.trim() || null; const exp = g('expire date'); let days = null; if (exp) { const m = exp.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+GMT$/); const d = m ? new Date(`${m[1]} ${m[2]}, ${m[4]} ${m[3]} GMT`) : new Date(exp); if (!isNaN(d)) days = Math.floor((d - Date.now()) / 86400e3); } return (exp || g('issuer')) ? { issuer: g('issuer'), subject: g('subject'), expire: exp, days_left: days } : null; };
export function webDigest(sections, host) {
  const head = stepsOf(sections, 'web.head')[0]; const home = stepsOf(sections, 'web.home', x => !x.argv?.includes('-A'))[0]; const html = bodyOf(home);
  const h = headersOf(head?.output); const ext = (list) => [...new Set(list.map(hostOf).filter(x => x && !isOwnHost(x, host)))].sort();
  const dns = (type, name) => stepsOf(sections, 'web.dns', x => x.argv?.[2] === type && x.argv?.[3] === name).flatMap(linesOf).map(l => l.replace(/"/g, '')).sort();
  return { status: statusOf(head?.output), title: titleOf(html), body_len: html.length, scripts_ext: ext(attrs(html, 'script', 'src')), iframes: attrs(html, 'iframe', 'src').slice(0, 20), forms_ext: ext(attrs(html, 'form', 'action')), meta_refresh: (html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>/i)?.[0] || '').slice(0, 200) || null, cert: certOf(head?.output), server: h.server || null, powered: h['x-powered-by'] || null, a: dns('A', '{host}'), ns: dns('NS', '{apex}'), mx: dns('MX', '{apex}') };
}
// 2 つの digest の違い (構造の変化)
export function digestDiff(a, b) {
  if (!a || !b) return [];
  const out = []; const arr = (k, label) => { const A = new Set(a[k] || []), B = new Set(b[k] || []); const add = [...B].filter(x => !A.has(x)), rem = [...A].filter(x => !B.has(x)); if (add.length || rem.length) out.push({ key: k, label, added: add, removed: rem }); };
  const val = (k, label, f = (x) => x) => { const va = f(a[k]), vb = f(b[k]); if (String(va ?? '') !== String(vb ?? '')) out.push({ key: k, label, from: va ?? null, to: vb ?? null }); };
  val('title', 'タイトル'); val('status', '応答コード'); arr('scripts_ext', '外部から読み込むスクリプトの置き場'); arr('forms_ext', '入力フォームの送り先 (外部)'); arr('iframes', '埋め込み (iframe)'); val('meta_refresh', '自動の転送 (meta refresh)');
  val('cert', '証明書の発行者', (c) => c?.issuer); val('server', 'サーバーの名乗り'); arr('a', '名前の向き先 (A)'); arr('ns', 'ネームサーバー (NS)'); arr('mx', 'メールの受け口 (MX)');
  return out;
}
const WEB_NOTE = '外から見える範囲 (トップページ・決まった場所・DNS) だけの機械的な目安です。見つからなくても「安全」という意味ではありません (中身の改ざんは巧妙に隠れますし、ログインの先は見ていません)。見つかったものも、正規の設定で説明がつくことがあります';
export function webSigns(sections, { host, digest, prevDigest = null } = {}) {
  const signs = []; const add = (level, label, why, lines, template_id) => { if (lines.length) signs.push({ level, label, why, lines: lines.slice(0, 20), count: lines.length, template_id }); };
  const d = digest || webDigest(sections, host);
  // 無いページにも 200 を返す HP では、ファイルの有無が判定できない
  const canary = stepsOf(sections, 'web.exposed', x => /should-not-exist/.test(x.argv?.at(-1) || ''))[0]; const catchAll = canary && statusOf(canary.output) === 200;
  const ex = stepsOf(sections, 'web.exposed', x => !/should-not-exist/.test(x.argv?.at(-1) || '')).map(x => ({ path: x.argv.at(-1), status: statusOf(x.output) })).filter(x => x.status);
  const SECRET = /\.(git|env|htpasswd|aws|DS_Store)|\.bak$|backup\.|\.sql$|id_rsa|phpinfo|debug\.log|server-status/;
  if (catchAll) add('check', '無いページにも 200 を返す HP (ファイルの有無を外から判定できない)', '「出てはいけないファイル」の判定はこの HP では効きません。公開フォルダの中身は、サーバー側で直接確かめてください', ['/mamoricho-check-this-page-should-not-exist → 200'], 'web.exposed');
  else {
    add('warn', '外から見えてはいけないファイルが見える', 'ソース管理の中身・設定・バックアップ・鍵・phpinfo は、パスワードやデータベースの接続情報を含むことが多く、乗っ取りの入口になります。すぐに消すか、外から見えないようにしてください', ex.filter(x => x.status === 200 && SECRET.test(x.path)).map(x => `${x.path} → 200`), 'web.exposed');
    add('check', '管理画面・API が誰でも開ける', 'ログイン画面や API が全世界に開いていると、総当たりや既知の穴の的になります。社内や VPN からだけにするか、多要素認証を', ex.filter(x => (x.status === 200 || x.status === 405) && /wp-login|administrator|phpmyadmin|xmlrpc|wp\/v2\/users/.test(x.path)).map(x => `${x.path} → ${x.status}`), 'web.exposed');
  }
  // 証明書
  if (d.cert?.days_left != null) { if (d.cert.days_left < 7) add('warn', d.cert.days_left < 0 ? '証明書の期限が切れている' : '証明書の期限が 7 日以内', '期限が切れるとブラウザが警告を出し、お客様が離れます。自動更新が止まっていないか確かめてください', [`期限: ${d.cert.expire} (残り ${d.cert.days_left} 日)`], 'web.head'); else if (d.cert.days_left < 30) add('check', '証明書の期限が 30 日以内', '自動更新なら問題ありません。手動なら、更新の予定を', [`期限: ${d.cert.expire} (残り ${d.cert.days_left} 日)`], 'web.head'); }
  if (prevDigest?.cert?.issuer && d.cert?.issuer && prevDigest.cert.issuer !== d.cert.issuer) add('check', '証明書の発行者が前回と違う', '発行元を変えた覚えが無ければ、名前の乗っ取りやサーバーのすり替えのおそれ', [`前回: ${prevDigest.cert.issuer}`, `今回: ${d.cert.issuer}`], 'web.head');
  // ヘッダ
  const head = stepsOf(sections, 'web.head')[0]; const h = headersOf(head?.output);
  if (head && statusOf(head.output)) {
    const miss = []; if (!h['strict-transport-security']) miss.push('Strict-Transport-Security (https を強制)'); if (!h['x-content-type-options']) miss.push('X-Content-Type-Options: nosniff'); if (!h['content-security-policy'] && !h['x-frame-options']) miss.push('X-Frame-Options か Content-Security-Policy (別サイトへの埋め込みを防ぐ)');
    add('check', 'セキュリティのヘッダが足りない', '無くてもすぐ乗っ取られるわけではありませんが、クリックジャッキングや混在コンテンツを防ぐ基本の設定です。ホスティングの設定で足せます', miss, 'web.head');
    const ver = [h.server, h['x-powered-by']].filter(Boolean).filter(v => /\d+\.\d+/.test(v));
    add('check', 'サーバーやアプリの版が外に見えている', '版が分かると、その版の既知の穴を狙われやすくなります。版の表示を消す設定を', ver.map(v => v.slice(0, 80)), 'web.head');
  }
  // http → https
  const rd = stepsOf(sections, 'web.redirect')[0];
  if (rd && statusOf(rd.output)) { const st = statusOf(rd.output); const loc = headersOf(rd.output).location || ''; if (!([301, 302, 307, 308].includes(st) && /^https:/i.test(loc))) add('check', 'http で来た人を https へ誘導していない', 'http のままだと通信を盗み見・書き換えされます。http → https の転送 (301) を', [`http://${host}/ → ${st}${loc ? ' Location: ' + loc.slice(0, 80) : ''}`], 'web.redirect'); }
  // トップページの中身
  const home = stepsOf(sections, 'web.home', x => !x.argv?.includes('-A'))[0]; const bot = stepsOf(sections, 'web.home', x => x.argv?.includes('googlebot'))[0];
  const html = bodyOf(home), bhtml = bodyOf(bot);
  if (html) {
    const bad = [];
    if (/eval\s*\(\s*(unescape|atob)\s*\(/i.test(html)) bad.push('eval(unescape/atob(…)) (難読化したスクリプトの実行)');
    if ((html.match(/String\.fromCharCode\s*\(/g) || []).length >= 5) bad.push('String.fromCharCode の多用 (文字コードで隠した文字列)');
    if (/document\.write\s*\(\s*unescape\s*\(/i.test(html)) bad.push('document.write(unescape(…))');
    if (/<script[^>]*>[^<]*[A-Za-z0-9+/=]{400,}/i.test(html)) bad.push('スクリプト内の長い base64 (400 文字以上)');
    for (const m of html.matchAll(/<iframe\b[^>]*>/gi)) if (/display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["']?0|height\s*=\s*["']?0|width\s*:\s*0|height\s*:\s*0/i.test(m[0])) bad.push(`隠した iframe: ${m[0].slice(0, 120)}`);
    if (d.meta_refresh && !isOwnHost(hostOf(d.meta_refresh.match(/url\s*=\s*["']?([^"'\s>]+)/i)?.[1]), host)) bad.push(`外部への自動転送: ${d.meta_refresh.slice(0, 120)}`);
    add('warn', '改ざんされた HP によく見る書き方がトップページにある', '難読化したスクリプト・隠した iframe・外部への自動転送は、訪問者を偽サイトやマルウェアへ送る改ざんの典型。心当たりが無ければ、ホスティングのバックアップと見比べてください', bad, 'web.home');
    const spam = [...new Set([...(html.match(SPAM) || []), ...(bhtml.match(SPAM) || [])])];
    add('warn', 'スパムの文言 (乗っ取られた HP によく出る) がトップページにある', '薬・カジノ・偽ブランドの文言は、検索エンジン向けのスパムを仕込まれた HP の典型', spam.map(w => `「${w}」`), 'web.home');
    add('warn', '入力フォームの送り先が外部のサーバー', '問い合わせやカード入力のフォームが外部へ送られているなら、入力の横取り (スキミング) のおそれ。外部のフォームサービスを使っているなら、その名前か確かめてください', d.forms_ext, 'web.home');
    if (bhtml && statusOf(home?.output) !== 403) {
      const t1 = d.title, t2 = titleOf(bhtml); const r = bhtml.length / Math.max(1, html.length); const spamOnlyBot = !SPAM.test(html) && SPAM.test(bhtml);
      const why = []; if (t1 && t2 && t1 !== t2) why.push(`タイトルが違う: 「${t1.slice(0, 40)}」 / 検索エンジン向け「${t2.slice(0, 40)}」`); if (r > 2 || r < 0.5) why.push(`大きさが大きく違う: ${html.length} 文字 / 検索エンジン向け ${bhtml.length} 文字`); if (spamOnlyBot) why.push('検索エンジン向けにだけスパムの文言');
      add('warn', '検索エンジン (Googlebot) にだけ別の内容を見せている (クローキング)', '乗っ取られた HP は、人には普通のページを、検索エンジンにはスパムを見せることがあります。訪問者には見えないので気づきにくい手口です', why, 'web.home');
    }
    add('check', 'https のページに http の部品が混ざっている (混在コンテンツ)', 'http で読む画像やスクリプトは途中で差し替えられるおそれがあり、ブラウザも警告します', [...new Set([...html.matchAll(/\s(?:src|href)\s*=\s*["']http:\/\/[^"'\s>]+/gi)].map(m => m[0].trim().slice(0, 100)))].slice(0, 10), 'web.home');
    if (prevDigest) { const ns = d.scripts_ext.filter(x => !(prevDigest.scripts_ext || []).includes(x)); const nf = d.forms_ext.filter(x => !(prevDigest.forms_ext || []).includes(x)); add('warn', '前回より増えた、外部スクリプトの置き場・フォームの送り先', '知らないうちに外部スクリプトが増えるのは、入力の横取り (Magecart 型) の典型。自分で足したものか確かめてください', [...ns.map(x => `スクリプト: ${x}`), ...nf.map(x => `フォーム: ${x}`)], 'web.home'); }
    else add('check', '外部から読み込んでいるスクリプトの置き場 (次回から、増えたら知らせます)', '外部スクリプトは便利ですが、その置き場が乗っ取られると HP ごと巻き込まれます。知っているものか確かめてください', d.scripts_ext, 'web.home');
  }
  // DNS
  const txt = stepsOf(sections, 'web.dns', x => x.argv?.[2] === 'TXT' && x.argv?.[3] === '{apex}').flatMap(linesOf); const dm = stepsOf(sections, 'web.dns', x => x.argv?.[3] === '_dmarc.{apex}').flatMap(linesOf); const mx = d.mx;
  const dnsRan = stepsOf(sections, 'web.dns').some(x => x.exit_code === 0);
  // 「0 .」はメールを受けない宣言 (null MX) なので、SPF/DMARC は求めない
  if (dnsRan && mx.filter(m => !/^0 \.?$/.test(m)).length) { if (!txt.some(l => /v=spf1/i.test(l))) add('check', 'なりすましメール対策 SPF が無い', 'このドメイン名義の偽メールを相手に見分けてもらうための DNS の記述です。メールの管理会社の手順で足せます', [`${host.replace(/^www\./, '')} の TXT に v=spf1 が無い`], 'web.dns'); if (!dm.some(l => /v=DMARC1/i.test(l))) add('check', 'なりすましメール対策 DMARC が無い', 'SPF/DKIM に合わないメールの扱いを受け手に伝える記述です。まず p=none で様子見から', [`_dmarc.${host.replace(/^www\./, '')} の TXT に v=DMARC1 が無い`], 'web.dns'); }
  if (prevDigest?.a?.length && d.a.length && !d.a.some(x => prevDigest.a.includes(x))) add('warn', 'HP の名前の向き先 (A レコード) が前回と全部違う', 'サーバーを移した覚えが無ければ、DNS の乗っ取りのおそれ。登録事業者の管理画面を確かめてください', [`前回: ${prevDigest.a.join(', ')}`, `今回: ${d.a.join(', ')}`], 'web.dns');
  if (prevDigest?.ns?.length && d.ns.length && !d.ns.some(x => prevDigest.ns.includes(x))) add('warn', 'ネームサーバー (NS) が前回と全部違う', '移管した覚えが無ければ、ドメインの乗っ取りのおそれ', [`前回: ${prevDigest.ns.join(', ')}`, `今回: ${d.ns.join(', ')}`], 'web.dns');
  signs.sort((a, b) => (a.level === b.level ? 0 : a.level === 'warn' ? -1 : 1));
  return { title: '改ざん・乗っ取り・設定の不備の兆候', signs, note: WEB_NOTE, warn: signs.filter(x => x.level === 'warn').length, check: signs.filter(x => x.level === 'check').length };
}
// ---- ネットワーク機器: 設定の写しに対する兆候 (Cisco 系 / YAMAHA の書き方) ----
const NET_NOTE = '設定の写し (show) に対する機械的な目安です。機種によって書き方が違うので、拾えないものもあります。本当の守りは「設定が前回から変わっていないか」の差分です';
export function networkSigns(sections) {
  const signs = []; const add = (level, label, why, lines, template_id) => { if (lines.length) signs.push({ level, label, why, lines: lines.slice(0, 20), count: lines.length, template_id }); };
  const cfg = stepsOf(sections, 'network.show', x => /config/.test(x.argv?.join(' ') || '')).flatMap(linesOf);
  if (!cfg.length) return { title: '設定の不備・変化の兆候', signs, note: NET_NOTE, warn: 0, check: 0 };
  add('warn', 'SNMP のコミュニティ名が既定 (public / private)', '誰でも機器の情報を読めたり (private なら書き換えも) します。別の名前にするか、SNMPv3 に', cfg.filter(l => /snmp(-server)?\s+community\s+(public|private)\b/i.test(l)), 'network.show');
  add('warn', 'telnet (暗号化なし) で管理できる', 'パスワードが平文で流れます。ssh だけにしてください', cfg.filter(l => /transport input (telnet|all)|telnetd (service|host) (on|any)|^\s*telnet\b/i.test(l)), 'network.show');
  add('warn', '管理者のパスワードが平文か、戻せる形 (type 7) で書かれている', '設定の写しを見た人に分かってしまいます。enable secret / service password-encryption / type 8・9 に', cfg.filter(l => /^\s*enable password\s|password 7 |password 0 |no service password-encryption/i.test(l)).map(l => l.replace(/(password \d?\s*)\S+/, '$1<伏せ字>')), 'network.show');
  add('warn', 'ssh の古い版 (version 1) を許している', '既知の弱点があります。version 2 だけに', cfg.filter(l => /ip ssh version 1\b/i.test(l)), 'network.show');
  add('check', '暗号化なしの http で管理画面を開いている', 'https (secure-server) だけにするか、管理は社内からだけに', cfg.filter(l => /^\s*ip http server\b|httpd service on/i.test(l) && !/secure/.test(l)), 'network.show');
  if (!cfg.some(l => /logging (host|server|\d+\.\d+)|syslog (host|server)/i.test(l))) add('check', 'ログの送り先 (syslog) が無い', '機器の中のログは再起動で消えます。言箱や別のサーバーへ送る設定を', ['logging host / syslog host の行が無い'], 'network.show');
  if (!cfg.some(l => /ntp (server|peer)|ntpdate|sntp/i.test(l))) add('check', '時刻合わせ (NTP) が無い', 'ログの時刻が狂うと、もしものときに突き合わせできません', ['ntp server の行が無い'], 'network.show');
  add('check', '誰でもつなげる管理の許可 (0.0.0.0 any / permit any)', '管理のアクセス元を社内の範囲に絞ってください', cfg.filter(l => /access-class|permit (ip )?any any|permit any\b/i.test(l) && /any/.test(l)).slice(0, 5), 'network.show');
  signs.sort((a, b) => (a.level === b.level ? 0 : a.level === 'warn' ? -1 : 1));
  return { title: '設定の不備・変化の兆候', signs, note: NET_NOTE, warn: signs.filter(x => x.level === 'warn').length, check: signs.filter(x => x.level === 'check').length };
}
// 乗っ取り・トロイの木馬の兆候 (読んだ出力への機械的な目安)。warn = 説明がつかなければ疑う、check = 正規の運用でも出るので確かめる
export function compromiseSigns(sections) {
  const signs = []; const add = (level, label, why, lines, template_id) => { if (lines.length) signs.push({ level, label, why, lines: lines.slice(0, 20), count: lines.length, template_id }); };
  // UID 0 が root 以外
  add('warn', 'root 以外に、管理者と同じ権限 (UID 0) のアカウント', '攻撃者が自分用の裏口として作る典型。正規に作ることはまずありません', stepsOf(sections, 'linux.rootusers', x => x.argv?.[0] === 'awk').flatMap(linesOf).filter(l => !/^root:/.test(l)), 'linux.rootusers');
  // ld.so.preload
  add('warn', '/etc/ld.so.preload に読み込み指定がある', 'すべてのプログラムに共通ライブラリを割り込ませる仕組みで、ユーザー空間ルートキットの常套手段。正規の用途はまれ (性能計測ツールなど)', stepsOf(sections, 'linux.preload', x => x.argv?.[1] === '/etc/ld.so.preload' && x.exit_code === 0).flatMap(linesOf).filter(l => !l.startsWith('#')), 'linux.preload');
  // 一時フォルダの実行ファイル・隠しファイル
  add('warn', '一時フォルダ (/tmp /var/tmp /dev/shm) に実行ファイルか隠しファイル', '不正プログラムは消されにくい一時フォルダに置かれることが多い。インストーラの残骸のこともあります', stepsOf(sections, 'linux.trojan', x => x.argv?.[0] === 'find' && x.argv?.[1] === '/tmp').flatMap(linesOf), 'linux.trojan');
  // プロセス: 既知の名前・一時フォルダから起動・CPU 占有
  const ps = stepsOf(sections, 'linux.processes', x => x.argv?.[0] === 'ps').flatMap(linesOf).filter(l => !/^USER\s+PID/.test(l) && !/\bmamoricho\b/.test(l));
  add('warn', '不正プログラムとしてよく知られた名前のプロセス', '暗号資産の採掘 (マイニング) やボットの名前です。偽装されることもあるので、無いからといって安心はできません', ps.filter(l => BAD_NAMES.test(l)), 'linux.processes');
  add('warn', '一時フォルダから起動しているプロセス', '正規のサービスが /tmp や /dev/shm から動くことはほぼありません', ps.filter(l => TMP_PATH.test(l) && !/\b(find|ls|grep)\b/.test(l)), 'linux.processes');
  add('check', 'CPU を大きく使い続けているプロセス (80% 以上)', '採掘の典型ですが、バックアップや集計など正規の処理でも出ます。心当たりがあるか確かめてください', ps.filter(l => { const m = l.match(/^\S+\s+\d+\s+([\d.]+)\s/); return m && Number(m[1]) >= 80; }), 'linux.processes');
  // 通信先の不審なポート
  const conn = stepsOf(sections, 'linux.connections').flatMap(linesOf);
  add('check', '不審なポートへの通信 (4444/1337/6667/3333/14444 など)', '遠隔操作や採掘プールでよく使われるポートです。正規の用途もあるので相手の住所を確かめてください', conn.filter(l => { const m = [...l.matchAll(/(\d+\.\d+\.\d+\.\d+|\[[0-9a-f:]+\]):(\d+)/g)]; const peer = m.at(-1); return peer && BAD_PORTS.has(peer[2]); }), 'linux.connections');
  // 自動実行の中の怪しい書き方
  add('check', '自動実行 (cron・rc.local・profile) に curl / wget / base64 / 一時フォルダ などの記述', '外から持ってきて実行する・難読化する手口の典型ですが、正規の運用スクリプトにもよくあります。中身を読んでください', stepsOf(sections, 'linux.trojan', x => x.argv?.[0] === 'grep').flatMap(linesOf).filter(l => !/:\s*#/.test(l)), 'linux.trojan');
  // 変更禁止属性
  add('warn', '変更禁止 (immutable) 属性がついた設定ファイル', '攻撃者が自分の仕込みを消させないために付けることがあります。管理者が意図して付けたのでなければ疑ってください', stepsOf(sections, 'linux.trojan', x => x.argv?.[0] === 'lsattr').flatMap(linesOf).filter(l => /^[-a-zA-Z]*i[-a-zA-Z]*\s+\//.test(l)), 'linux.trojan');
  // 消された実行ファイルで動くプロセス
  add('warn', 'ディスクから消された実行ファイルで動いているプロセス', 'メモリだけで動く不正プログラムの手口。ただし、更新のあと再起動していないサービスでも同じ表示になります', stepsOf(sections, 'linux.trojan', x => x.argv?.includes('/proc')).flatMap(linesOf).filter(l => /\/proc\/\d+\/exe/.test(l)), 'linux.trojan');
  // hosts の書き換え (更新サーバー・セキュリティ関連の名前を乗っ取る)
  add('check', '/etc/hosts で更新・セキュリティ関連の名前が別の住所に向けられている', '更新を止めたり偽サイトへ誘導したりする手口。社内で意図して書いたものなら問題ありません', stepsOf(sections, 'linux.trojan', x => x.argv?.[1] === '/etc/hosts').flatMap(linesOf).filter(l => !l.startsWith('#') && /(update|security|ubuntu\.com|debian\.org|microsoft|google|kotohako|akigrid|antivirus|clamav|virustotal)/i.test(l) && !/^(127\.|::1)/.test(l)), 'linux.trojan');
  // sudo NOPASSWD (まもり帳以外)
  add('check', 'パスワードなしの sudo (NOPASSWD) が、まもり帳以外にある', '裏口として足されることがあります。クラウドの初期ユーザーや自動化で正規に使うこともあります', stepsOf(sections, 'linux.sudoers', x => (x.argv?.[0] === 'grep' || x.argv?.[2] === '/usr/bin/grep' || x.argv?.[1] === '/etc/sudoers' || x.argv?.[2] === '/usr/bin/cat')).flatMap(linesOf).filter(l => /NOPASSWD/.test(l) && !/mamoricho/.test(l) && !/:\s*#|^#/.test(l)), 'linux.sudoers');
  // root の鍵
  add('check', 'root に鍵でのログインが許されている', 'root の鍵は攻撃者が残す裏口の定番。運用で使っているなら、鍵の持ち主が分かるか確かめてください', stepsOf(sections, 'linux.authkeys', x => x.argv?.[2] === '/usr/bin/grep').flatMap(linesOf).filter(l => l.startsWith('/root/.ssh/authorized_keys:')), 'linux.authkeys');
  // パッケージの改ざん (設定ファイル以外)
  add('warn', 'パッケージのプログラムが配布時と違う (dpkg -V / rpm -V)', '正規の更新では起きません。プログラム本体の書き換えはルートキットやバックドアの典型 (設定ファイル c は除外しています)', stepsOf(sections, 'linux.integrity').flatMap(linesOf).filter(l => /^\S*5\S*\s+(?!c\s)\S*\s*\/(usr\/)?(s?bin|lib|libexec)\//.test(l) || /^S\.5/.test(l)), 'linux.integrity');
  // 重要な設定の最近の変更
  add('check', '重要な設定 (passwd・shadow・sudoers・ssh・cron・preload) が 3 日以内に変わった', '管理者の作業でも変わります。心当たりが無ければ、何が変わったか見てください', stepsOf(sections, 'linux.recent_etc').flatMap(linesOf).filter(l => /\/etc\/(passwd|shadow|group|sudoers|ld\.so\.preload|crontab|cron\.d\/|rc\.local|ssh\/)|\.ssh\/authorized_keys/.test(l) && !/sudoers\.d\/mamoricho/.test(l)), 'linux.recent_etc');
  // 見慣れない場所の SUID
  add('check', '見慣れない場所にある SUID プログラム', 'root の権限で動くプログラムです。/usr/bin などの定位置以外にあるのは珍しく、権限昇格の裏口のことがあります', stepsOf(sections, 'linux.suid').flatMap(linesOf).filter(l => l.startsWith('/') && !/^\/(usr\/)?(bin|sbin|lib|lib32|lib64|libexec|snap|opt|var\/lib\/snapd)\//.test(l)), 'linux.suid');
  signs.sort((a, b) => (a.level === b.level ? 0 : a.level === 'warn' ? -1 : 1));
  return { title: '乗っ取り・トロイの木馬の兆候', signs, note: SIGN_RULES_NOTE, warn: signs.filter(x => x.level === 'warn').length, check: signs.filter(x => x.level === 'check').length };
}
// 手順の半分以上 (3 つ以上) に同じ「増えた行」(または「消えた行」) があれば、それは 1 つの手順の変化ではなく機械全体の異常 (壊れた preload が全コマンドに出す ERROR など)。
// 抜き出して返し、各手順の差分からは外す (steps の diff を書き換える)。増えた側が警告、消えた側は「前回の異常が消えた」の知らせ
export function splitCommonLines(steps) {
  const out = { added: [], removed: [] };
  if (steps.length < 3) return out;
  for (const side of ['added', 'removed']) {
    const count = new Map();
    for (const x of steps) for (const l of new Set(x.diff[side])) count.set(l, (count.get(l) || 0) + 1);
    const common = [...count].filter(([, n]) => n >= Math.max(3, Math.ceil(steps.length * 0.5))).map(([l]) => l);
    if (common.length) for (const x of steps) { x.diff[side] = x.diff[side].filter(l => !common.includes(l)); x.diff[`${side}_count`] = x.diff[side].length; }
    out[side] = common;
  }
  return out;
}
export const splitCommonAdded = (steps) => splitCommonLines(steps).added;
// ps aux の行は、PID・CPU・メモリ・開始時刻・経過時間の列を落として「利用者 + コマンド」で比べる (毎回変わる数字で差分が埋まらないように)
const PS_LINE = /^(\S+)\s+\d+\s+[\d.]+\s+[\d.]+\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+[\d:.]+\s+(.*)$/;
// HTTP の応答で毎回変わるヘッダ (日時・CDN の追跡 id・cookie・キャッシュの印)。curl -v の echo (< / >) にも同じものが出る
const VOLATILE_HEADER = /^(?:[<>]\s*)?(date|cf-ray|set-cookie|report-to|nel|age|expires|etag|last-modified|x-request-id|x-amz-cf-id|x-amz-request-id|x-amz-cf-pop|server-timing|cf-cache-status|x-cache|x-cache-hits|via|x-served-by|x-timer|content-length|x-runtime|x-trace-id|traceparent|x-correlation-id|keep-alive):/i;
export function diffLines(prev, cur) {
  const norm = (raw) => { const l = raw.replace(/\r$/, ''); return norm1(l); }; // HTTP の行末の CR は落とす ($ が効かず、可変ヘッダの正規化が外れていた)
  const norm1 = (l) => PS_LINE.test(l) ? l.replace(PS_LINE, '$1 <ps> $2') : VOLATILE_HEADER.test(l) ? l.replace(VOLATILE_HEADER, '$1:').replace(/:.*$/, ': <可変>') : /^[{}] \[\d+ bytes data\]$/.test(l) ? '<curl の通信の断片>' : /^\*\s+(Connected to|IPv[46]:|Host .* was resolved|Trying )/.test(l) ? l.replace(/\s+/g, ' ').replace(/\(?\d+\.\d+\.\d+\.\d+\)?|\[[0-9a-f:.]+\]|(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}/gi, '<住所>') : l.replace(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b/g, '<時刻>').replace(/\b\d{1,2}:\d{2}(:\d{2})?\b/g, '<時刻>').replace(/\b(pid=|users:\(\("[^"]+",pid=)\d+/g, '$1<pid>').replace(/\/proc\/\d+\//g, '/proc/<pid>/').replace(/:(3276[89]|327[7-9]\d|32[89]\d{2}|3[3-9]\d{3}|[4-5]\d{4}|6[0-5]\d{3})\b/g, ':<一時ポート>').replace(/\s+/g, ' ').trim();
  // 「(出力なし)」は出力が無かった目印で、行ではない (前回が空・今回にエラー行だけ、で「消えた 1」と出ていた)
  const a = new Map(); for (const l of String(prev || '').split('\n')) { const k = norm(l); if (k && k !== NO_OUTPUT) a.set(k, (a.get(k) || 0) + 1); }
  const b = new Map(); for (const l of String(cur || '').split('\n')) { const k = norm(l); if (k && k !== NO_OUTPUT) b.set(k, (b.get(k) || 0) + 1); }
  const added = [], removed = [];
  for (const [k, n] of b) if (!a.has(k)) added.push(k); for (const [k, n] of a) if (!b.has(k)) removed.push(k);
  return { added: added.slice(0, 200), removed: removed.slice(0, 200), added_count: added.length, removed_count: removed.length };
}

const SELF_CHECKS = [
  { id: 'self.mfa_remote', label: '外からのログインに多要素認証を求めている', item: 'entry.mfa_remote' },
  { id: 'self.mfa_admins', label: 'Owner・管理者の全員が多要素認証を登録している', item: 'entry.mfa_admin' },
  { id: 'self.login_lock', label: 'ログイン失敗が続くとロックする', item: 'entry.lockout' },
  { id: 'self.updates_auto', label: '更新を自動で当てている (配信元の設定あり)', item: 'patch.updates' },
  { id: 'self.audit_retention', label: '監査ログを 1 年以上保管する設定', item: 'detect.logs' },
  { id: 'self.backup_recent', label: '2 日以内にバックアップが取れている', item: 'backup.exists' },
  { id: 'self.backup_offsite', label: '外部保管先があり、最後の保管が成功している', item: 'backup.offline' },
  { id: 'self.ntp', label: '時刻が合っている (NTP)', item: null },
  { id: 'self.https', label: 'https で画面を出している', item: 'leak.encrypt' },
  { id: 'self.remote_url', label: '公開 URL (インターネットからの入口) の有無', item: null },
];

export class Mamoricho {
  constructor(cfg, { probe = null, llm = null, rag = null, backup = null, updates = null, remote = null } = {}) {
    Object.assign(this, { cfg, probe, llm, rag, backup, updates, remote }); this.timer = null;
  }
  db() { return getDb(); }

  // ---- 点検の項目と答え ----
  checklist(actor) {
    requireRole(actor, 'viewer');
    const answers = Object.fromEntries(this.db().prepare('SELECT * FROM mamoricho_answers').all().map(a => [a.item_id, { ...a, evidence: J.parse(a.evidence, []) }]));
    return { baseline: BASELINE, statuses: STATUSES, categories: CATEGORIES, items: ITEMS.map(i => ({ ...i, answer: answers[i.id] || null })) };
  }
  // 状態を決めるのは人 (operator 以上)。AI の提案はここに来る前に画面で見せる
  answer(actor, { item_id, status, note = '', evidence = null } = {}) {
    requireRole(actor, 'operator');
    const item = byId[item_id]; if (!item) throw new HttpError(404, 'not_found', '点検の項目が見つかりません');
    if (!STATUSES[status]) throw new HttpError(400, 'bad_status', `status は ${Object.keys(STATUSES).join(' / ')}`);
    const prev = this.db().prepare('SELECT * FROM mamoricho_answers WHERE item_id=?').get(item_id);
    const ev = Array.isArray(evidence) ? evidence.slice(0, 20).map(e => ({ kind: String(e.kind || 'note').slice(0, 20), ref: String(e.ref || '').slice(0, 200), label: String(e.label || '').slice(0, 120) })) : (prev ? J.parse(prev.evidence, []) : []);
    const t = nowIso();
    this.db().prepare('INSERT INTO mamoricho_answers(item_id,status,note,evidence,updated_by,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(item_id) DO UPDATE SET status=excluded.status, note=excluded.note, evidence=excluded.evidence, updated_by=excluded.updated_by, updated_at=excluded.updated_at')
      .run(item_id, status, String(note).slice(0, 2000), J.str(ev), actor.id, t);
    const rec = this.record(actor, 'answer', { item_id, status, note: String(note).slice(0, 2000), evidence: ev, previous: prev ? { status: prev.status, updated_at: prev.updated_at } : null });
    audit({ actor, action: 'mamoricho.answer', target: item_id, detail: { status, previous: prev?.status || null, record: rec.id } });
    return { item_id, status, note, evidence: ev, updated_at: t, record_id: rec.id };
  }

  // ---- 記録の連鎖 (1 件ごとに前の hash を含め、箱の鍵で署名) ----
  record(actor, kind, payload) {
    const db = this.db(); const last = db.prepare('SELECT hash FROM mamoricho_records ORDER BY seq DESC LIMIT 1').get();
    const rec = { id: id('mrec'), kind, payload: J.str(payload), by_id: actor?.id || 'system', by_name: actor?.display_name || actor?.username || 'system', at: nowIso(), prev_hash: last?.hash || '', baseline: BASELINE.id };
    rec.hash = sha256([rec.id, rec.kind, rec.payload, rec.by_id, rec.at, rec.prev_hash, rec.baseline].join('\n'));
    try { const { privateKey } = ensureLocalPublisherKey(); rec.sig = crypto.sign(null, Buffer.from(rec.hash), privateKey).toString('base64'); } catch { rec.sig = null; }
    db.prepare('INSERT INTO mamoricho_records(id,kind,payload,by_id,by_name,at,prev_hash,hash,sig,baseline) VALUES(?,?,?,?,?,?,?,?,?,?)').run(rec.id, rec.kind, rec.payload, rec.by_id, rec.by_name, rec.at, rec.prev_hash, rec.hash, rec.sig, rec.baseline);
    return rec;
  }
  records(actor, { limit = 200, kind = null } = {}) {
    requireRole(actor, 'viewer');
    const rows = kind ? this.db().prepare('SELECT * FROM mamoricho_records WHERE kind=? ORDER BY seq DESC LIMIT ?').all(kind, limit) : this.db().prepare('SELECT * FROM mamoricho_records ORDER BY seq DESC LIMIT ?').all(limit);
    return rows.map(r => ({ ...r, payload: J.parse(r.payload, {}) }));
  }
  // 連鎖を最初から確かめる: hash のつながりと署名
  verify(actor) {
    requireRole(actor, 'viewer');
    const rows = this.db().prepare('SELECT * FROM mamoricho_records ORDER BY seq').all(); let prev = ''; let pub = null;
    try { pub = crypto.createPublicKey(ensureLocalPublisherKey().privateKey); } catch { /* 署名は確かめられない */ }
    for (const r of rows) {
      const h = sha256([r.id, r.kind, r.payload, r.by_id, r.at, r.prev_hash, r.baseline].join('\n'));
      if (r.prev_hash !== prev) return { ok: false, count: rows.length, broken_at: r.seq, reason: '前の記録とのつながりが切れています (消された・差し替えられた記録があります)' };
      if (h !== r.hash) return { ok: false, count: rows.length, broken_at: r.seq, reason: '記録の中身が書き換えられています' };
      if (pub && r.sig && !crypto.verify(null, Buffer.from(r.hash), pub, Buffer.from(r.sig, 'base64'))) return { ok: false, count: rows.length, broken_at: r.seq, reason: '署名が合いません' };
      prev = r.hash;
    }
    return { ok: true, count: rows.length, head: prev || null, signed: !!pub };
  }

  // ---- 言箱自身の自己点検 (機械的) ----
  async selfCheck(actor, { save = false } = {}) {
    requireRole(actor, 'viewer');
    const pol = mfa.policy(this.cfg); const out = [];
    const push = (id_, ok, detail, level = 'check') => out.push({ ...SELF_CHECKS.find(s => s.id === id_), ok, detail, level });
    push('self.mfa_remote', pol.require_remote, pol.require_remote ? '外からのログインは多要素認証が必須' : '外からのログインに多要素認証を求めていません (System › 設定)');
    const admins = (actor.tenant_id ? listUsers(actor.tenant_id) : []).filter(u => ['owner', 'admin'].includes(u.role) && u.status === 'active');
    const missing = admins.filter(u => !u.mfa_factors).map(u => u.username);
    push('self.mfa_admins', admins.length > 0 && !missing.length, missing.length ? `未登録: ${missing.join(', ')}` : `${admins.length} 人とも登録済み`);
    push('self.login_lock', true, `同じ名前+接続元で ${this.cfg.security?.login_max_failures ?? 5} 回、名前だけで ${this.cfg.security?.login_max_failures_user ?? 20} 回でロック`);
    const us = this.updates?.status?.(); push('self.updates_auto', !!(us?.auto_apply && us?.url), us ? `自動更新 ${us.auto_apply ? 'あり' : 'なし'}・配信元 ${us.url || '未設定'}・いまの版 ${us.current || '-'}` : '更新の状態を読めません');
    const days = Number(this.cfg.audit?.retention_days ?? 0); push('self.audit_retention', days === 0 || days >= 365, days === 0 ? '無期限' : `${days} 日`);
    const bs = this.backup?.status?.(); const lastAt = bs?.last_at ? Date.parse(bs.last_at) : 0; push('self.backup_recent', !!lastAt && Date.now() - lastAt < 2 * 86400e3, bs?.last_at ? `最後: ${bs.last_at} (${bs.count} 世代)` : 'まだ取っていません (System › デバイス › バックアップ)');
    push('self.backup_offsite', !!(bs?.remote && bs?.offsite_last?.ok), bs?.remote ? (bs.offsite_last?.ok ? `外部保管 ${bs.offsite_last.target || ''} (${bs.offsite_last.at})` : `外部保管先はあるが最後は失敗: ${bs.offsite_last?.error || '未実施'}`) : '外部保管先が未設定 (切り離した写しがありません)');
    let ts = null; try { ts = timeStatus(); } catch { /* timedatectl なし */ } push('self.ntp', !!ts?.synchronized, ts?.synchronized ? `合っている (${ts.server || ts.address || '-'})` : '時刻合わせができていません (System › 設定 › 時刻合わせ)');
    push('self.https', this.cfg.server?.https !== false, this.cfg.server?.https !== false ? `https :${this.cfg.server?.https_port || 7443}` : 'https を切っています');
    const rs = this.remote?.state?.(); push('self.remote_url', true, rs?.hostname ? `公開 URL あり: ${rs.hostname} (外からの入口。多要素認証が必須か確かめる)` : '公開 URL なし (社内だけ)', 'info');
    const summary = { ok: out.filter(x => x.level === 'check' && x.ok).length, total: out.filter(x => x.level === 'check').length, at: nowIso() };
    if (save) { const rec = this.record(actor, 'selfcheck', { checks: out.map(({ id: cid, ok, detail }) => ({ id: cid, ok, detail })), summary }); summary.record_id = rec.id; }
    return { checks: out, summary };
  }

  // ---- まとめ (ホーム) ----
  async summary(actor) {
    requireRole(actor, 'viewer');
    const { items } = this.checklist(actor); const counts = { ok: 0, partial: 0, no: 0, unknown: 0, na: 0, unanswered: 0 };
    for (const i of items) counts[i.answer?.status || 'unanswered']++;
    const answered = items.length - counts.unanswered; const scoreBase = items.length - counts.na;
    const score = scoreBase ? Math.round(((counts.ok + counts.partial * 0.5) / scoreBase) * 100) : 0;
    const homework = items.filter(i => !i.answer || ['no', 'unknown', 'partial'].includes(i.answer.status)).sort((a, b) => (b.weight - a.weight) || a.id.localeCompare(b.id)).slice(0, 8)
      .map(i => ({ id: i.id, cat: i.cat, q: i.q, status: i.answer?.status || 'unanswered', min: i.min }));
    const lastFull = this.db().prepare("SELECT at FROM mamoricho_records WHERE kind='review' ORDER BY seq DESC LIMIT 1").get()?.at || null;
    const nextReview = lastFull ? new Date(Date.parse(lastFull) + 91 * 86400e3).toISOString() : null;
    const self = await this.selfCheck(actor);
    const settings = this.settings();
    return { baseline: BASELINE, counts, answered, total: items.length, score, homework, last_review_at: lastFull, next_review_at: nextReview, self: self.summary, self_failed: self.checks.filter(c => c.level === 'check' && !c.ok).map(c => c.label),
      chain: this.verify(actor), emergency_ready: !!(settings.contacts?.lead && settings.contacts?.it), targets: this.probe ? this.probe.listTargets({ ...actor, role: actor.role === 'viewer' ? 'operator' : actor.role }).length : 0 };
  }
  // 四半期の見直しを「終えた」と記録する (全部答えたとき)
  closeReview(actor, { note = '' } = {}) {
    requireRole(actor, 'operator'); const s = this.db().prepare('SELECT COUNT(*) c FROM mamoricho_answers').get().c;
    if (s < ITEMS.length) throw new HttpError(409, 'incomplete', `まだ答えていない項目が ${ITEMS.length - s} 個あります`);
    const rec = this.record(actor, 'review', { note: String(note).slice(0, 1000), answers: this.db().prepare('SELECT item_id,status FROM mamoricho_answers').all() });
    audit({ actor, action: 'mamoricho.review_closed', target: rec.id }); return { record_id: rec.id, at: rec.at };
  }

  // ---- 対話: 利用者の答えを状態に翻訳して提案する (決めるのは人) ----
  async interview(actor, { item_id, text = '', history = [] } = {}) {
    requireRole(actor, 'operator'); const item = byId[item_id]; if (!item) throw new HttpError(404, 'not_found', '点検の項目が見つかりません');
    if (!this.llm) return { proposal: null, note: 'AI が使えません。状態を自分で選んでください' };
    const sys = `あなたは中小企業の情報セキュリティの点検を手伝う担当者です。利用者の答えを読んで、点検項目の状態を 1 つ提案し、理由を 1 文で書き、曖昧なら確認の質問を 1 つだけします。
状態は ok (できている) / partial (一部できている) / no (できていない) / unknown (分からない) / na (対象外) のどれか。
断定を避け、「安全」「問題なし」とは書かない。できていない点は責めず、最低ラインを 1 つ示す。
必ず次の JSON だけを返す: {"status":"ok|partial|no|unknown|na","confidence":0.0-1.0,"note":"記録に残す 1 文 (40 字以内)","follow_up":"確認の質問 (無ければ空)","tip":"最低ラインに向けた一言 (無ければ空)"}`;
    const user = `点検項目: ${item.q}\n基準の最低ライン: ${item.min}\n推奨: ${item.rec}\n背景: ${item.why}\n\nこれまでのやりとり:\n${history.slice(-6).map(h => `${h.role === 'assistant' ? 'AI' : '利用者'}: ${String(h.text).slice(0, 300)}`).join('\n')}\n利用者の答え: ${String(text).slice(0, 1200)}`;
    try {
      const r = await this.llm.chat([{ role: 'system', content: sys }, { role: 'user', content: user }], { temperature: 0.1, max_tokens: 400 });
      const m = /\{[\s\S]*\}/.exec(r?.content || ''); const p = m ? JSON.parse(m[0]) : null;
      if (!p || !STATUSES[p.status]) return { proposal: null, note: 'AI の答えを読めませんでした。状態を自分で選んでください' };
      return { proposal: { status: p.status, confidence: Math.max(0, Math.min(1, Number(p.confidence) || 0)), note: String(p.note || '').slice(0, 200), follow_up: String(p.follow_up || '').slice(0, 300), tip: String(p.tip || '').slice(0, 300) } };
    } catch (e) { return { proposal: null, note: `AI に聞けませんでした: ${String(e.message || e).slice(0, 120)}` }; }
  }
  // 相談 (安全の文脈に絞る)。社内の文書を読み込んでいれば、その内容を根拠に添える (ragnarok)
  async consult(actor, { question = '', workspace_id = null } = {}) {
    requireRole(actor, 'viewer'); const q = String(question || '').trim(); if (!q) throw new HttpError(400, 'empty', '相談の内容を入れてください');
    let docs = null; if (this.rag && workspace_id) { try { docs = await this.rag.ask(actor, { workspace_id, question: q, k: 4, answer: false }); } catch { docs = null; } }
    if (!this.llm) return { answer: 'AI が使えません。', sources: [] };
    const ctx = docs?.hits?.length ? `社内の文書からの抜粋:\n${docs.hits.slice(0, 4).map((h, i) => `[${i + 1}] ${h.name || h.asset_name || ''}: ${String(h.text || h.snippet || '').slice(0, 500)}`).join('\n')}\n` : '';
    const sys = `あなたは中小企業の情報セキュリティの相談相手です。個人情報保護委員会の 2026-10-07 の注意喚起 (アクセス制御・識別と認証・不正アクセスの防止・漏えいの防止・検知、不要な個人データの消去) と WARNING の 9 事例を基準に、ふつうの言葉で、まず何をすべきかを順番に答えます。
断定を避け「安全」「問題なし」とは書かない。手に負えない事案 (侵入の疑い・大量の漏えい) は、ネットワークからの切り離しと専門家への連絡、委員会への速報 (おおむね 3〜5 日) を先に伝える。社内の文書の抜粋があれば、それを根拠に引く。400 字以内。`;
    try { const r = await this.llm.chat([{ role: 'system', content: sys }, { role: 'user', content: `${ctx}相談: ${q}` }], { temperature: 0.2, max_tokens: 700 }); return { answer: r?.content || '', sources: (docs?.hits || []).slice(0, 4).map(h => ({ name: h.name || h.asset_name || '', asset_id: h.asset_id || h.id || null })) }; }
    catch (e) { return { answer: `AI に聞けませんでした: ${String(e.message || e).slice(0, 120)}`, sources: [] }; }
  }

  // ---- 調査の型 (読むだけ) を対象に流す。各 step は probe の判定を通る (forbidden/change が混じれば止める) ----
  templates() { return TEMPLATES.map(({ id: tid, kind, label, steps, incident }) => ({ id: tid, kind, label, steps, incident: !!incident })); }
  async runTemplate(actor, { target_id, template_id, item_id = null, record = true } = {}) {
    requireRole(actor, 'operator'); if (!this.probe) throw new HttpError(503, 'no_probe', '調査の仕組みがありません');
    const tpl = TEMPLATES.find(t => t.id === template_id); if (!tpl) throw new HttpError(404, 'not_found', '調査の型が見つかりません');
    const t = this.probe.getTarget(target_id); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    if (!tpl.kind.includes(t.kind)) throw new HttpError(400, 'bad_kind', `この型は ${tpl.kind.join('/')} の対象向けです`);
    const results = [];
    const rootSteps = ROOT_STEPS[template_id] || []; const rootRead = !!J.parse(t.verify, {})?.root_read;
    // root で同じコマンドを読むなら、一般ユーザー側の同じ手順は省く (dpkg -V を 2 回走らせない)
    const cmdKey = (a) => [String(a[0]).replace(/^.*\//, ''), ...a.slice(1)].join(' '); const rootKeys = new Set(rootRead ? rootSteps.map(cmdKey) : []);
    const plan = [...tpl.steps.filter(a => !rootKeys.has(cmdKey(a))).map(a => ({ argv: a })), ...rootSteps.map(a => rootRead ? { argv: ['sudo', '-n', ...a], root: true } : { argv: a, needs_root: true })];
    for (const { argv, root, needs_root } of plan) {
      if (needs_root) { results.push({ argv, needs_root: true, error: 'root の権限が要ります (登録時に「root の読み取りも許す」を選んだ対象だけ読めます)' }); continue; }
      try {
        const prev = tpl.nodiff ? null : this.probe.previousOutput(target_id, template_id, argv); // 走らせる前に「前回」を取る (今回を混ぜない)。nodiff の型は構造 (digest) で比べる
        const r = await this.probe.run(actor, { target_id, argv, template_id, explanation: tpl.label });
        // 前回は記録に残した長さ (OUTPUT_KEEP) で切れているので、今回も同じ長さで比べる (全文と比べると切れた先が全部「増えた」になる)
        const truncated = r.output.length > OUTPUT_KEEP;
        const diff = prev ? { ...diffLines(prev.output, r.output.slice(0, OUTPUT_KEEP)), previous_at: prev.at, ...(truncated ? { truncated: true } : {}) } : null;
        const stale = root && r.exit_code === 1 && /password is required|not allowed to execute/.test(r.output);
        const partial = r.exit_code !== 0 && !stale && r.output.split(STDERR_MARK)[0].trim() !== '' && r.output.split(STDERR_MARK)[0].trim() !== NO_OUTPUT; // 一部は読めた (find の Permission denied など)
        results.push({ argv, exit_code: r.exit_code, output: r.output.slice(0, 20000), run_id: r.run_id, diff, root: !!root, ...(partial ? { partial: true } : {}), ...(stale ? { stale_sudoers: true, error: 'この root の手順は登録のあとに増えたものです (対象で登録の 1 行をもう一度実行すると読めるようになります)' } : {}) });
      }
      catch (e) { results.push({ argv, error: e.message, code: e.code }); if (e.code === 'forbidden_command' || e.code === 'approval_required') break; }
    }
    const rec = record ? this.record(actor, 'probe', { target_id, target_name: t.name, template_id, item_id, runs: results.map(r => ({ argv: r.argv, exit_code: r.exit_code ?? null, run_id: r.run_id || null, error: r.error || null, added: r.diff?.added_count ?? null, removed: r.diff?.removed_count ?? null })) }) : null;
    if (record && item_id && byId[item_id]) {
      const prev = this.db().prepare('SELECT evidence FROM mamoricho_answers WHERE item_id=?').get(item_id); const ev = prev ? J.parse(prev.evidence, []) : [];
      ev.push({ kind: 'probe', ref: rec.id, label: `${t.name}: ${tpl.label} (${new Date().toLocaleDateString('ja-JP')})` });
      this.db().prepare('INSERT INTO mamoricho_answers(item_id,status,note,evidence,updated_by,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(item_id) DO UPDATE SET evidence=excluded.evidence, updated_at=excluded.updated_at').run(item_id, 'unknown', '', J.str(ev.slice(-20)), actor.id, nowIso());
    }
    return { record_id: rec?.id || null, target: { id: t.id, name: t.name, kind: t.kind }, template: tpl.label, results };
  }
  // 初動セット: 消えやすい順に型を流し、前回 (平時の記録) との差分をまとめる。1 つの記録 (incident_probe) に残す
  async runIncident(actor, { target_id } = {}) { return this.runSet(actor, { target_id, set: 'incident' }); }
  // セット (まとめて診断 / 兆候 / 初動) を流してスナップショットを残す。各手順は前回 (同じ対象・同じ手順の直近の記録) と比べる
  async runSet(actor, { target_id, set = 'full' } = {}) {
    requireRole(actor, 'operator'); if (!this.probe) throw new HttpError(503, 'no_probe', '調査の仕組みがありません');
    const def = SETS[set]; if (!def) throw new HttpError(400, 'bad_set', 'セットは full / compromise / incident のどれかです');
    const t = this.probe.getTarget(target_id); if (!t) throw new HttpError(404, 'not_found', '対象が見つかりません');
    if (!def.kinds.includes(t.kind)) throw new HttpError(400, 'bad_kind', `${def.label}は ${def.kinds.includes('web') ? 'この種類の対象' : 'サーバー・PC (SSH)'} の対象向けです`);
    const prevSnap = this.snapshots(actor, { target_id, limit: 1 }).find(x => x.comparable); const prevDigest = prevSnap ? (this.snapshot(actor, prevSnap.id).digest || null) : null;
    const sections = []; let baseline = false;
    for (const tid of def.ids(t.kind)) {
      const tpl = TEMPLATES.find(x => x.id === tid); if (!tpl) continue;
      try { const r = await this.runTemplate(actor, { target_id, template_id: tid, record: false }); for (const x of r.results) if (x.diff) baseline = true; sections.push({ template_id: tid, label: tpl.label, results: r.results }); }
      catch (e) { sections.push({ template_id: tid, label: tpl.label, error: e.message, results: [] }); }
    }
    // どの手順にも出る「増えた行」は、1 つの手順の変化ではなく機械全体の異常 (例: 壊れた ld.so.preload が全コマンドに出す ERROR)。1 か所にまとめ、各手順からは外す
    const common = splitCommonLines(sections.flatMap(sec => sec.results.filter(x => x.diff)));
    const summary = sections.map(sec => ({ template_id: sec.template_id, label: sec.label, steps: sec.results.length, ok: sec.results.filter(x => x.exit_code === 0).length, needs_root: sec.results.filter(x => x.needs_root || x.stale_sudoers).length, failed: sec.results.filter(x => x.error || (x.exit_code && x.exit_code !== 0)).length, added: sec.results.reduce((n, x) => n + (x.diff?.added_count || 0), 0), removed: sec.results.reduce((n, x) => n + (x.diff?.removed_count || 0), 0) }));
    const digest = t.kind === 'web' ? webDigest(sections, t.host) : null;
    if (digest && prevDigest) baseline = true;
    const signs = !def.signs ? null : t.kind === 'web' ? webSigns(sections, { host: t.host, digest, prevDigest }) : t.kind === 'network' ? networkSigns(sections) : compromiseSigns(sections);
    const digest_diff = digest && prevDigest ? digestDiff(prevDigest, digest) : [];
    const totals = { steps: summary.reduce((n, x) => n + x.steps, 0), ok: summary.reduce((n, x) => n + x.ok, 0), needs_root: summary.reduce((n, x) => n + x.needs_root, 0), failed: summary.reduce((n, x) => n + x.failed, 0), added: summary.reduce((n, x) => n + x.added, 0), removed: summary.reduce((n, x) => n + x.removed, 0), warn: signs?.warn || 0, check: signs?.check || 0 };
    // 記録には出力そのものは持たず (probe_runs にある)、手順ごとの run_id と差分の行 (40 行まで) を持つ。履歴の画面はこれで前回との変化を再現し、出力は run_id で読む
    const stored = sections.map(sec => ({ template_id: sec.template_id, label: sec.label, error: sec.error || null, steps: sec.results.map(x => ({ argv: x.argv, run_id: x.run_id || null, exit_code: x.exit_code ?? null, root: !!x.root, needs_root: !!x.needs_root, stale_sudoers: !!x.stale_sudoers, partial: !!x.partial, error: x.error || null, added_count: x.diff?.added_count ?? null, removed_count: x.diff?.removed_count ?? null, added: (x.diff?.added || []).slice(0, 40), removed: (x.diff?.removed || []).slice(0, 40), previous_at: x.diff?.previous_at || null, truncated: !!x.diff?.truncated })) }));
    const rec = this.record(actor, 'snapshot', { set, set_label: def.label, target_id, target_name: t.name, target_kind: t.kind, baseline, common_added: common.added.slice(0, 20), common_removed: common.removed.slice(0, 20), signs, totals, digest, digest_diff, sections: stored });
    audit({ actor, action: 'mamoricho.set_run', target: target_id, detail: { record: rec.id, set, baseline, added: totals.added, warn: totals.warn, check: totals.check } });
    return { record_id: rec.id, at: rec.at, set, set_label: def.label, target: { id: t.id, name: t.name, kind: t.kind }, baseline, digest, digest_diff, common_added: common.added.slice(0, 20), common_removed: common.removed.slice(0, 20), signs, totals, sections, summary, note: baseline ? '前回の記録と比べました。「増えた」ものを先に見てください' : 'この対象には前回の記録がありません。今回が基準になります (次回から差分が出ます)' };
  }
  // 対象のスナップショットの一覧 (新しい順)。古い initial の記録 (incident_probe) も載せる
  snapshots(actor, { target_id, limit = 50 } = {}) {
    requireRole(actor, 'viewer');
    const rows = this.db().prepare("SELECT * FROM mamoricho_records WHERE kind IN ('snapshot','incident_probe') ORDER BY seq DESC LIMIT 2000").all();
    const out = [];
    for (const r of rows) {
      const pl = J.parse(r.payload, {}); if (target_id && pl.target_id !== target_id) continue;
      if (r.kind === 'snapshot') out.push({ id: r.id, at: r.at, by_name: r.by_name, set: pl.set, set_label: pl.set_label, target_id: pl.target_id, target_name: pl.target_name, baseline: !!pl.baseline, totals: pl.totals, comparable: true });
      else out.push({ id: r.id, at: r.at, by_name: r.by_name, set: 'incident', set_label: '初動セット', target_id: pl.target_id, target_name: pl.target_name, baseline: !!pl.baseline, totals: { steps: (pl.sections || []).reduce((n, x) => n + (x.steps || 0), 0), ok: (pl.sections || []).reduce((n, x) => n + (x.ok || 0), 0), added: (pl.sections || []).reduce((n, x) => n + (x.added || 0), 0), removed: (pl.sections || []).reduce((n, x) => n + (x.removed || 0), 0), warn: 0, check: 0 }, comparable: false });
      if (out.length >= limit) break;
    }
    return out;
  }
  snapshot(actor, id) {
    requireRole(actor, 'viewer');
    const r = this.db().prepare("SELECT * FROM mamoricho_records WHERE id=? AND kind='snapshot'").get(id); if (!r) throw new HttpError(404, 'not_found', 'スナップショットが見つかりません');
    return { id: r.id, at: r.at, by_name: r.by_name, ...J.parse(r.payload, {}) };
  }
  // 2 つのスナップショット (古い a → 新しい b) を、同じ手順どうしの出力で比べる
  compareSnapshots(actor, { a, b } = {}) {
    requireRole(actor, 'operator');
    const A = this.snapshot(actor, a), B = this.snapshot(actor, b);
    if (A.target_id !== B.target_id) throw new HttpError(400, 'bad_pair', '同じ対象のスナップショットどうしで比べてください');
    const outOf = (run_id) => run_id ? (this.db().prepare('SELECT output FROM probe_runs WHERE id=?').get(run_id)?.output || '') : null;
    const sections = [];
    for (const sb of B.sections || []) {
      const sa = (A.sections || []).find(x => x.template_id === sb.template_id);
      const results = [];
      for (const xb of sb.steps || []) {
        const xa = sa?.steps?.find(y => J.str(y.argv) === J.str(xb.argv));
        const oa = xa ? outOf(xa.run_id) : null, ob = outOf(xb.run_id);
        results.push({ argv: xb.argv, exit_code: xb.exit_code, run_id: xb.run_id, root: xb.root, needs_root: xb.needs_root, error: xb.error, diff: oa !== null && ob !== null ? { ...diffLines(oa, ob), previous_at: A.at } : null, no_pair: !xa });
      }
      sections.push({ template_id: sb.template_id, label: sb.label, results });
    }
    const common = splitCommonLines(sections.flatMap(sec => sec.results.filter(x => x.diff)));
    const summary = sections.map(sec => ({ template_id: sec.template_id, label: sec.label, steps: sec.results.length, ok: sec.results.filter(x => x.exit_code === 0).length, needs_root: sec.results.filter(x => x.needs_root).length, failed: sec.results.filter(x => x.error).length, added: sec.results.reduce((n, x) => n + (x.diff?.added_count || 0), 0), removed: sec.results.reduce((n, x) => n + (x.diff?.removed_count || 0), 0) }));
    return { a: { id: A.id, at: A.at, set_label: A.set_label }, b: { id: B.id, at: B.at, set_label: B.set_label }, target: { id: B.target_id, name: B.target_name, kind: B.target_kind || null }, baseline: true, digest_diff: digestDiff(A.digest, B.digest), common_added: common.added.slice(0, 20), common_removed: common.removed.slice(0, 20), sections, summary, totals: { steps: summary.reduce((n, x) => n + x.steps, 0), added: summary.reduce((n, x) => n + x.added, 0), removed: summary.reduce((n, x) => n + x.removed, 0) }, note: `${new Date(A.at).toLocaleString('ja-JP')} のスナップショットと比べました` };
  }

  // 速報の下書き: 初動の記録・初動の調査・連絡先から、委員会への速報の形に (箱の AI。無ければ材料だけ並べる)。「安全」「原因は特定」とは書かせない
  async draftReport(actor, { discovered_at = null, summary = '' } = {}) {
    requireRole(actor, 'operator');
    const notes = this.records(actor, { kind: 'incident_note', limit: 100 }).reverse(); const probes = [...this.records(actor, { kind: 'snapshot', limit: 3 }), ...this.records(actor, { kind: 'incident_probe', limit: 3 })].sort((x, y) => (x.at < y.at ? 1 : -1)).slice(0, 3)
      .map(p => { const pl = p.payload; return { at: p.at, payload: { target_name: pl.target_name, baseline: pl.baseline, set_label: pl.set_label || '初動セット', signs: pl.signs?.signs || [], sections: (pl.sections || []).map(x => ({ label: x.label, added: x.added ?? (x.steps || []).reduce((n, y) => n + (y.added_count || 0), 0), removed: x.removed ?? (x.steps || []).reduce((n, y) => n + (y.removed_count || 0), 0) })) } }; });
    const st = this.settings(); const dl = discovered_at ? this.deadlines(discovered_at) : null;
    const material = `発覚日: ${dl?.discovered || '(未入力)'}\n報告の期限: ${dl ? `速報 ${dl.prompt_report.from}〜${dl.prompt_report.to} / 確報 ${dl.final_report.to} (不正の目的のおそれ ${dl.final_report_malicious.to})` : '(発覚日を入れると出ます)'}\n責任者: ${st.contacts?.lead || '(未設定)'} / 担当: ${st.contacts?.it || '(未設定)'}\n概要 (担当者の言葉): ${String(summary).slice(0, 1000) || '(未入力)'}\n\n初動の記録 (時系列):\n${notes.map(n => `- ${n.at.slice(0, 16).replace('T', ' ')} ${n.by_name}: ${n.payload.text}`).join('\n') || '- (まだありません)'}\n\n初動の調査:\n${probes.map(p => `- ${p.at.slice(0, 16).replace('T', ' ')} ${p.payload.target_name}: ${p.payload.baseline ? '前回と比べて ' + p.payload.sections.reduce((n, x) => n + x.added, 0) + ' 行増・' + p.payload.sections.reduce((n, x) => n + x.removed, 0) + ' 行減' : '基準を作成'}${p.payload.sections.filter(x => x.added > 0).map(x => `（${x.label}: +${x.added}）`).join('')}${p.payload.signs.filter(x => x.level === 'warn').length ? ' 兆候 (疑い): ' + p.payload.signs.filter(x => x.level === 'warn').map(x => x.label).join('、') : ''}`).join('\n') || '- (まだありません)'}`;
    const skeleton = `【個人情報保護委員会への速報 (下書き)】\n1. 発生・発覚の日時\n2. 事案の概要\n3. 漏えい等が発生し、またはそのおそれがある個人データの項目・件数 (分からなければ「調査中」)\n4. 原因 (分からなければ「調査中」)\n5. 二次被害またはそのおそれの有無\n6. 本人への対応の実施状況\n7. 公表の実施状況\n8. 再発防止のための措置\n9. その他参考となる事項\n\n--- 材料 ---\n${material}`;
    if (!this.llm) return { draft: skeleton, material, llm: false };
    try {
      const heads = ['1. 発生・発覚の日時', '2. 事案の概要', '3. 漏えい等が発生し、またはそのおそれがある個人データの項目・件数', '4. 原因', '5. 二次被害またはそのおそれの有無', '6. 本人への対応の実施状況', '7. 公表の実施状況', '8. 再発防止のための措置', '9. その他参考となる事項'];
      const r = await this.llm.chat([{ role: 'system', content: `中小企業の担当者に代わって、個人情報保護委員会への「速報」の下書きを日本語で書く。見出しは次の 9 つを **この文言のまま、この順で** 使い、増やしたり変えたりしない:\n${heads.join('\n')}\n各見出しの下に 1〜3 文。分からないことは「調査中」と書き、推測で断定しない。「安全」「問題なし」「原因を特定した」とは書かない。材料に無いことは書かない。最後に「※ 速報は分かっている範囲で早めに出し、確報で補う」と添える。` }, { role: 'user', content: `材料:\n${material}\n\n上の材料で 1〜9 を埋めてください。` }], { temperature: 0.1, max_tokens: 1200 });
      return { draft: r?.content || skeleton, material, llm: true };
    } catch (e) { return { draft: skeleton, material, llm: false, note: `AI に聞けませんでした: ${String(e.message || e).slice(0, 120)}` }; }
  }

  // ---- 安全の仕組み (調査が安全である理由を、ふつうの言葉で、生きている状態つきで) ----
  safety() {
    const image = this.probe ? this.probe._dk(['image', 'inspect', 'kotohako-probe:1']).status === 0 : false;
    const chain = this.db().prepare('SELECT COUNT(*) c FROM mamoricho_records').get().c;
    return { items: [
      { id: 'readonly', title: '読むだけのコマンドしか動かさない', body: 'コマンドは 1 つずつ「読むだけ / 変えるおそれ / 使えない」に機械的に判定します。消す・止める・入れる・権限を変える・別の機械へつなぐものは実行しません。知らないものは「変えるおそれ」側に倒し、Owner の承認と理由が要ります。', ok: true, detail: '判定の決まりは OS の版と一緒に配られ、調査の型 (16 + 15) はすべて「読むだけ」で固定' },
      { id: 'noshell', title: 'シェルを通さず、記号も通さない', body: 'パイプ・リダイレクト・つなぎ (| ; & > < $( `) は受け付けません。遠隔のコマンドは 1 本ずつ、対象の機械で展開されないように引用して渡します。', ok: true },
      { id: 'ledger', title: 'つなぐ先は台帳で固定', body: 'どの機械につなぐか (住所・ポート・利用者) は、まもり帳の台帳の値だけを使います。調査の型や AI は「その機械で何を読むか」しか決められず、台帳に無い機械へはつなげません。初めてつないだときの公開鍵を覚え、次から変わっていれば拒否します (なりすまし・経路のすり替え)。', ok: true },
      { id: 'container', title: '使い捨てのコンテナから', body: '調査は、読み取り専用・権限を落とした・root でないコンテナ (kotohako-probe) から行い、1 回ごとに消します。時間 (90 秒)・メモリ (256MB)・出力 (2MB) に上限があります。言箱本体のファイルや鍵には触れません。', ok: image, detail: image ? 'コンテナの材料はこの箱にあります' : 'コンテナの材料はまだありません (初回の調査で自動で用意します)' },
      { id: 'account', title: '対象には読み取り専用のユーザーだけ', body: '1 行の登録で作る mamoricho ユーザーは、パスワード無し・鍵だけ・ポート転送なし・端末なしです。root でしか読めないもの (root の鍵・sudo の設定・認証ログ) は、登録時に許した対象でだけ、あらかじめ決めた読むだけのコマンドを sudoers に完全一致で書いて読みます。任意のコマンドは root で動かせません。消し方は userdel -r mamoricho と rm -f /etc/sudoers.d/mamoricho の 2 つだけ。', ok: true },
      { id: 'secrets', title: '鍵や秘密は箱の金庫に、出力は伏せ字に', body: '秘密鍵・パスワードは箱の金庫 (暗号化) に入り、画面には出ません。調査の出力は、パスワードや鍵に見える行を伏せ字にしてから箱の中 (AI NAS の「まもり帳」フォルダ) に保存します。', ok: true },
      { id: 'inside', title: 'データは外に出ない', body: '調査の結果も、相談も、速報の下書きも、箱の中の AI (Akigrid) だけで処理します。箱の外の AI には送りません。外に出すのは、管理者が自分で書き出したときだけです。', ok: this.cfg.security?.external_ai !== 'enabled', detail: this.cfg.security?.external_ai === 'enabled' ? '注意: 箱の設定で外部 AI が有効です (System › 設定)' : '外部 AI は無効' },
      { id: 'records', title: '記録は書き換えられない', body: 'すべての答え・調査・初動の記録は、1 件ごとに前の記録のハッシュを含めて箱の鍵で署名しています。消したり書き換えたりすると「記録」の画面で分かります。実行は監査ログにも残ります。', ok: true, detail: `いまの記録 ${chain} 件` },
      { id: 'approval', title: '人が決める', body: 'AI の提案も、変えるおそれのあるコマンドも、最後に決めるのは人です。調査を始める前には毎回「これからやること / やらないこと」を示し、確認してから動きます。', ok: true },
    ], not_doing: ['設定を書き換えない', 'ファイルを消さない・作らない (対象の機械では mamoricho ユーザーと sudoers の 1 ファイル以外)', 'サービスの停止・再起動をしない', 'ソフトを入れない', '台帳に無い機械へつながない', 'データを箱の外へ送らない'] };
  }

  // ---- もしものときのカード (連絡先・体制) と初動の時系列 ----
  settings() { const r = this.db().prepare("SELECT value FROM mamoricho_settings WHERE key='emergency'").get(); return r ? J.parse(r.value, {}) : {}; }
  saveSettings(actor, patch = {}) {
    requireRole(actor, 'admin'); const cur = this.settings(); const next = { ...cur, ...redact(patch) };
    for (const k of Object.keys(next)) if (typeof next[k] === 'string') next[k] = next[k].slice(0, 500);
    if (next.contacts && typeof next.contacts === 'object') for (const k of Object.keys(next.contacts)) next.contacts[k] = String(next.contacts[k] ?? '').slice(0, 200);
    this.db().prepare("INSERT INTO mamoricho_settings(key,value) VALUES('emergency',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(J.str(next));
    this.record(actor, 'emergency_card', { contacts: next.contacts || {}, notes: next.notes || '' }); audit({ actor, action: 'mamoricho.emergency_card', target: 'emergency' });
    return next;
  }
  // 発覚日から、委員会への報告と本人通知の期限を出す (速報 3〜5 日・確報 30 日・不正の目的のおそれは 60 日)
  deadlines(discovered_at) {
    const d = Date.parse(discovered_at); if (!d) throw new HttpError(400, 'bad_date', '発覚した日を入れてください');
    const add = (n) => new Date(d + n * 86400e3).toISOString().slice(0, 10);
    return { discovered: new Date(d).toISOString().slice(0, 10), prompt_report: { from: add(3), to: add(5), label: '速報 (おおむね 3〜5 日以内)' }, final_report: { to: add(30), label: '確報 (30 日以内)' }, final_report_malicious: { to: add(60), label: '確報 (不正アクセスなど不正の目的のおそれがあるとき: 60 日以内)' }, notify_subjects: '本人への通知は事態の状況に応じて速やかに' };
  }
  addIncidentNote(actor, { text = '', at = null } = {}) {
    requireRole(actor, 'operator'); const s = String(text).trim(); if (!s) throw new HttpError(400, 'empty', '記録する内容を入れてください');
    const rec = this.record(actor, 'incident_note', { text: s.slice(0, 2000), observed_at: at || nowIso() }); audit({ actor, action: 'mamoricho.incident_note', target: rec.id }); return { record_id: rec.id, at: rec.at };
  }

  // ---- 定期の見直しの知らせ (1 日 1 回見る)。四半期の見直し期限・権限の棚卸し・自己点検の落ち ----
  start() { this.stop(); this.timer = setInterval(() => this.tick().catch(() => {}), 6 * 3600e3); setTimeout(() => this.tick().catch(() => {}), 60e3); }
  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; }
  async tick() {
    const day = new Date().toDateString(); if (metaGet('mamoricho.tick_day') === day) return; this.db().prepare("INSERT INTO meta(key,value) VALUES('mamoricho.tick_day',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(day);
    const sys = { id: 'system', username: 'system', role: 'owner', tenant_id: this.db().prepare('SELECT id FROM tenants ORDER BY created_at LIMIT 1').get()?.id || null, display_name: 'まもり帳' };
    const s = await this.summary(sys);
    if (s.next_review_at && Date.parse(s.next_review_at) < Date.now()) notify({ kind: 'mamoricho', severity: 'warning', title: 'まもり帳: 四半期の見直しの時期です', body: `前回の見直しから 3 か月たちました。点検を見直し、アクセス権の棚卸しをしてください`, dedupe_key: 'mamoricho.review', link: 'mamoricho:check' });
    if (s.self_failed.length) notify({ kind: 'mamoricho', severity: 'warning', title: `まもり帳: 言箱の自己点検で ${s.self_failed.length} 件が未達`, body: s.self_failed.slice(0, 3).join(' / '), dedupe_key: 'mamoricho.self', link: 'mamoricho:home' });
    if (!s.answered) notify({ kind: 'mamoricho', severity: 'info', title: 'まもり帳: 最初の点検を始めましょう', body: '15 分ほどで、基本の対策ができているかを記録に残せます', dedupe_key: 'mamoricho.start', link: 'mamoricho:check' });
  }
}
