// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// root でしか読めないもの (root の鍵・sudo の設定・認証のログ・root の cron)。読み取り専用のユーザー mamoricho には見えないので、
// 登録時に「root の読み取りも許す」を選んだ対象だけ、ここに書いた **完全一致のコマンド** を sudo -n で動かせる (sudoers に 1 行ずつ書く)。
// 任意の cat や grep は許さない (箱が乗っ取られても、ここに無いものは読めない)。パスは Debian/Ubuntu の usrmerge 前提 (/usr/bin)。
export const ROOT_STEPS = {
  'linux.authkeys': [['/usr/bin/grep', '-rsH', '-e', 'ssh-', '-e', 'ecdsa-', '-e', 'sk-', '--include=authorized_keys', '/root', '/home', '/etc/ssh'], ['/usr/bin/find', '/root', '/home', '/etc/ssh', '-name', 'authorized_keys', '-type', 'f']],
  'linux.sudoers': [['/usr/bin/cat', '/etc/sudoers'], ['/usr/bin/ls', '-la', '/etc/sudoers.d'], ['/usr/bin/grep', '-rsH', '-e', 'ALL', '-e', 'NOPASSWD', '/etc/sudoers.d']],
  'linux.autostart': [['/usr/bin/crontab', '-l', '-u', 'root'], ['/usr/bin/ls', '-la', '--time-style=long-iso', '/var/spool/cron/crontabs']],
  'linux.logs_auth': [['/usr/bin/tail', '-n', '200', '/var/log/auth.log'], ['/usr/bin/lastb', '-n', '30'], ['/usr/bin/journalctl', '-u', 'ssh', '-n', '150', '--no-pager'], ['/usr/bin/journalctl', '-u', 'sshd', '-n', '150', '--no-pager']],
  'linux.integrity': [['/usr/bin/dpkg', '-V']],
  'linux.recent_etc': [['/usr/bin/find', '/etc', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/root', '-xdev', '-type', 'f', '-mtime', '-3']],
  // ディスクから消された実行ファイルで動いているプロセス (メモリだけで動く不正プログラムの手口。更新のあと再起動していないだけでも出る) と、ホームの隠しファイルの最近の変更 (.bashrc などへの仕込み)
  'linux.trojan': [['/usr/bin/find', '/proc', '-maxdepth', '2', '-name', 'exe', '-lname', '*deleted*'], ['/usr/bin/find', '/root', '/home', '-xdev', '-maxdepth', '3', '-type', 'f', '-name', '.*', '-mtime', '-7']],
};
// sudoers の引数では * ? [ ] が「何でも一致」になり、, : = ! \ も区切りの意味を持つ。完全一致にしたいので \ で守る
export const sudoersEscape = (arg) => String(arg).replace(/[\\*?\[\],:=!]/g, (c) => `\\${c}`);
// sudoers の行 (完全一致。引数まで含む)
export function sudoersLines(user = 'mamoricho', brand = 'まもり帳') {
  const cmds = Object.values(ROOT_STEPS).flat().map(a => a.map(sudoersEscape).join(' '));
  return [`# ${brand}: 読むだけの決まったコマンドを root で (完全一致。ここに無いものは動かない)。消すときは userdel -r ${user}`, `Defaults:${user} !requiretty`, ...cmds.map(c => `${user} ALL=(root) NOPASSWD: ${c}`)];
}
