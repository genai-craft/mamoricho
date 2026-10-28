// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まとめて診断の結果 (読むだけで取った出力) から、SCS 評価制度の評価基準の「裏づけの目安」を拾う。新しいコマンドは流さない (既にある記録を読み直すだけ)。
//   出すのは目安。「満たしている」と決めるのは人 (と、★3 では確認するセキュリティ専門家)
import { STDERR_MARK, NO_OUTPUT } from './output.js';
import { networkSigns } from './mamoricho.js';

const out = (o) => String(o || '').split(STDERR_MARK)[0];
const lines = (o) => out(o).split('\n').map(l => l.trim()).filter(l => l && l !== NO_OUTPUT);
// 標準のサポートが終わった OS (2026 年 10 月の時点で確かなものだけ。延長サポートを契約していれば別)。新しい版は足していく
const EOL = [
  { re: /^ubuntu$/, ver: (v) => { const [a, b] = v.split('.').map(Number); return a < 20 || (a === 20 && b <= 4) || (b !== 4 && a <= 25); }, label: 'Ubuntu (20.04 以前の LTS・25.10 以前の LTS でない版)' },
  { re: /^debian$/, ver: (v) => Number(v) <= 11, label: 'Debian 11 以前' },
  { re: /^centos$/, ver: () => true, label: 'CentOS (7・8 とも終了)' },
  { re: /^rhel$/, ver: (v) => Number(String(v).split('.')[0]) <= 7, label: 'Red Hat Enterprise Linux 7 以前' },
];
export function osEol(id, version) { const r = EOL.find(e => e.re.test(String(id || '').toLowerCase())); return r && version && r.ver(String(version)) ? r.label : null; }
const osRelease = (o) => { const kv = {}; for (const l of lines(o)) { const m = l.match(/^([A-Z_]+)=("?)(.*)\2$/); if (m) kv[m[1]] = m[3]; } return kv; };

// 1 台分 (SSH の対象) の目安。outputOf(run_id) → 出力
export function sshFacts(sections, outputOf) {
  const step = (tid, pick) => { for (const s of sections.filter(x => x.template_id === tid)) for (const x of s.steps || []) if (x.run_id && (!pick || pick(x.argv || []))) return outputOf(x.run_id); return null; };
  const f = {};
  const osr = osRelease(step('linux.basic', a => a[1] === '/etc/os-release')); if (osr.ID) { f.os = osr.PRETTY_NAME || `${osr.ID} ${osr.VERSION_ID || ''}`.trim(); f.os_id = osr.ID; f.os_version = osr.VERSION_ID || ''; f.eol = osEol(osr.ID, osr.VERSION_ID); }
  const up = step('linux.updates', a => a[0] === 'apt' && a[1] === 'list'); if (up != null) { const l = lines(up).filter(x => /\[upgradable from/.test(x)); f.upgradable = l.length; f.upgradable_security = l.filter(x => /-security/.test(x)).length; }
  const hist = step('linux.updates', a => a[0] === 'tail'); if (hist != null) { const d = [...out(hist).matchAll(/Start-Date:\s*(\d{4}-\d{2}-\d{2})/g)].map(m => m[1]).sort().at(-1); if (d) f.last_update = d; }
  const auto = step('linux.updates', a => /20auto-upgrades/.test(a[1] || '')); if (auto != null) f.auto_updates = /Unattended-Upgrade\s+"1"/.test(out(auto));
  const admins = []; for (const g of ['sudo', 'wheel']) { const o = step('linux.users', a => a[0] === 'getent' && a[1] === 'group' && a[2] === g); const m = lines(o).find(l => l.startsWith(g + ':')); if (m) admins.push(...(m.split(':')[3] || '').split(',').map(s => s.trim()).filter(Boolean)); } if (step('linux.users', a => a[0] === 'getent' && a[2] === 'sudo') != null) f.admins = [...new Set(admins)];
  const ports = step('linux.ports', a => a[0] === 'ss' && a[1] === '-tlnpH'); if (ports != null) { const ext = new Set(); for (const l of lines(ports)) { const m = l.match(/^\S+\s+\d+\s+\d+\s+(\S+):(\d+)\s/); if (m && !/^(127\.|\[::1\]|::1|localhost)/.test(m[1])) ext.add(Number(m[2])); } f.listen = [...ext].sort((a, b) => a - b); }
  const ufw = step('linux.firewall', a => a[0] === 'ufw'); const nft = step('linux.firewall', a => a[0] === 'nft'); const ipt = step('linux.firewall', a => a[0] === 'iptables');
  if (ufw != null || nft != null || ipt != null) f.firewall = /Status:\s*active/i.test(out(ufw)) ? 'ufw が有効' : /\b(chain|table)\b/.test(out(nft)) && /\bdrop\b|\breject\b/i.test(out(nft)) ? 'nftables に遮断の規則あり' : /policy (DROP|REJECT)/.test(out(ipt)) ? 'iptables の既定が遮断' : null;
  const sshd = step('linux.ssh', a => a[1] === '/etc/ssh/sshd_config'); if (sshd != null) { const v = (k) => lines(sshd).filter(l => !l.startsWith('#')).map(l => l.match(new RegExp(`^${k}\\s+(\\S+)`, 'i'))?.[1]).filter(Boolean)[0] || null; f.ssh = { permit_root: v('PermitRootLogin'), password_auth: v('PasswordAuthentication') }; }
  return f;
}

// 記録 (スナップショット) と対象の台帳から、評価基準ごとの目安を作る。mm = Mamoricho, probe = Probe
export function collectFacts(actor, mm, probe) {
  const op = { ...actor, role: ['viewer'].includes(actor.role) ? 'operator' : actor.role };
  const targets = probe ? probe.listTargets(op).filter(t => !t.revoked_at && !t.excluded) : [];
  const snaps = mm.snapshots(actor, { limit: 2000 }).filter(s => s.comparable);
  const outputOf = (rid) => mm.db().prepare('SELECT output FROM probe_runs WHERE id=?').get(rid)?.output || '';
  const per = []; const byCrit = {};
  const add = (cid, level, label, detail, target) => (byCrit[cid] ||= []).push({ level, label, detail, target: target ? { id: target.id, name: target.name } : null });
  for (const t of targets) {
    const sn = snaps.find(s => s.target_id === t.id); const row = { id: t.id, name: t.name, kind: t.kind, host: t.host, last_snapshot_at: sn?.at || null };
    if (!sn) { per.push(row); continue; }
    const pl = mm.snapshot(actor, sn.id);
    if (t.kind === 'ssh') {
      const f = sshFacts(pl.sections || [], outputOf); Object.assign(row, f);
      if (f.os) add('3-1-1-2', 'info', `${t.name}: ${f.os}`, 'OS の種類と版 (まとめて診断で読んだもの)', t);
      if (f.os) add('4-4-2-1', f.eol ? 'warn' : 'ok', f.eol ? `${t.name}: 標準のサポートが終わった OS (${f.eol})` : `${t.name}: サポート中の OS (${f.os})`, f.eol ? '延長サポートを契約していなければ、更改の計画と、リスクを下げる対策 (外からの切り離しなど) を' : '版から見た目安です', t);
      if (f.eol) add('4-4-4-1', 'warn', `${t.name}: 標準のサポートが終わった OS`, f.eol, t);
      if (f.upgradable != null) add('4-4-4-2', f.upgradable_security ? 'warn' : f.upgradable ? 'check' : 'ok', f.upgradable_security ? `${t.name}: セキュリティの更新が ${f.upgradable_security} 件、当たっていない` : f.upgradable ? `${t.name}: 当てていない更新が ${f.upgradable} 件 (セキュリティ以外)` : `${t.name}: 当てていない更新はない`, `最後の更新 ${f.last_update || '不明'}・自動更新 ${f.auto_updates == null ? '不明' : f.auto_updates ? 'あり' : 'なし'} (診断 ${new Date(sn.at).toLocaleDateString('ja-JP')})`, t);
      if (f.auto_updates != null) add('4-4-4-1', f.auto_updates ? 'ok' : 'check', `${t.name}: 自動更新 ${f.auto_updates ? 'あり' : 'なし'}`, '「可能であれば自動アップデート」の目安', t);
      if (f.upgradable != null) add('3-2-1-4', f.upgradable_security ? 'warn' : 'ok', `${t.name}: 残っている脆弱性の目安 (未適用のセキュリティ更新 ${f.upgradable_security})`, 'パッケージの更新から見た目安です', t);
      if (f.admins) add('4-1-2-5', 'info', `${t.name}: 管理者権限 (sudo/wheel) を持つ ID ${f.admins.length ? f.admins.join(', ') : 'なし'}`, '台帳「管理者 ID」と突き合わせてください', t);
      if (f.listen) add('4-4-1-4', f.listen.some(p => [21, 23, 111, 139, 445, 3389, 5900].includes(p)) ? 'warn' : 'info', `${t.name}: 外から受け付けているポート ${f.listen.join(', ') || 'なし'}`, '要らないサービスが開いていないか確かめてください (telnet・ftp・SMB・RDP・VNC などは特に)', t);
      if (f.firewall !== undefined) add('4-5-1-8', f.firewall ? 'ok' : 'check', `${t.name}: ソフトウェアのファイアウォール ${f.firewall || '有効と読めない'}`, 'ufw / nftables / iptables の状態から', t);
      if (f.ssh) add('4-4-1-5', /^yes$/i.test(f.ssh.permit_root || '') && !/^no$/i.test(f.ssh.password_auth || 'yes') ? 'warn' : /^yes$/i.test(f.ssh.permit_root || '') ? 'check' : 'ok', `${t.name}: root の SSH ログイン ${f.ssh.permit_root || '既定 (鍵のみ)'}・パスワード認証 ${f.ssh.password_auth || '既定 (有効)'}`, '最初からある管理者 (root) を使わない、またはパスワードでは入れないように', t);
    } else if (t.kind === 'network') {
      const sg = networkSigns(pl.sections || []); row.signs = sg.signs.map(s => ({ level: s.level, label: s.label }));
      const ver = (pl.sections || []).flatMap(s => (s.steps || []).filter(x => (x.argv || []).join(' ') === 'show version' && x.run_id)).map(x => lines(outputOf(x.run_id))[0]).find(Boolean); if (ver) row.version = ver.slice(0, 120);
      const pw = sg.signs.filter(s => /パスワード|telnet|SNMP/.test(s.label));
      add('4-5-1-1', pw.some(s => s.level === 'warn') ? 'warn' : 'info', pw.length ? `${t.name}: ${pw.map(s => s.label).join(' / ')}` : `${t.name}: 設定の写しから、平文のパスワード・telnet・既定の SNMP は見つからない`, '設定の写し (show) に対する目安です', t);
      add('4-5-1-3', pw.some(s => s.level === 'warn') ? 'warn' : 'info', `${t.name}: 管理のログインの設定 (診断 ${new Date(sn.at).toLocaleDateString('ja-JP')})`, pw.length ? pw.map(s => s.label).join(' / ') : '目立つ不備は見つからない', t);
      add('3-1-1-6', 'ok', `${t.name}: 設定の写しが記録にある`, 'まとめて診断のスナップショット (前回との差分つき)', t);
    }
    per.push(row);
  }
  if (snaps.length) add('3-1-1-6', 'info', `設定の写し: ${new Set(snaps.map(s => s.target_id)).size} 台分のスナップショット`, 'まとめて診断で、設定と状態の写しを前回との差分つきで残しています', null);
  return { at: new Date().toISOString(), targets: per, by_criterion: byCrit, note: '読んだ記録から機械的に拾った目安です。満たしているかどうかは、原文を読んで人が決めてください' };
}
export const factsOf = (facts, cid) => facts?.by_criterion?.[cid] || [];
