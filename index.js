// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 genai-craft (生成AI工房). まもり帳 (Mamoricho) — https://genai-craft.com/
// まもり帳 — 基本の対策を対話で確かめて記録に残し、読むだけで診断し、管理者と API の権限を見張る (docs/MAMORICHO_DESIGN.md)。
//   このフォルダはひとまとまりのパッケージ (OSS にする部分)。外の世界には ports.js に書いたものだけで触る。
//   使い方: const { probe, mm, authz, inquiry, scs, ledgers, policies, notices } = createMamoricho(cfg, ports)。cfg は { probe: { decision_head } } 程度しか見ない。
//   SCS 評価制度の点検・台帳・規程・周知の経路は registerExtRoutes(route, mk) で組み込み先の経路に足す (routes.js)。
import { makePorts } from './ports.js';
import { ensureSchema } from './schema.js';
import { Probe } from './runner/probe.js';
import { ApiAuthz } from './runner/api-authz.js';
import { Mamoricho } from './core/mamoricho.js';
import { Inquiry } from './core/inquiry.js';
import { Scs } from './core/scs.js';
import { Ledgers } from './core/ledgers.js';
import { Policies } from './core/policies.js';
import { Notices } from './core/notices.js';

export { makePorts, DEFAULT_BRAND } from './ports.js';
export { ensureSchema } from './schema.js';
export { createLlm, PROVIDERS } from './llm/providers.js';
export { Probe, webScript, checkPublicUrl, isPrivateIp, redactText } from './runner/probe.js';
export { ApiAuthz } from './runner/api-authz.js';
export { Mamoricho, TEMPLATES, SETS, FULL_SET, COMPROMISE_SET, INCIDENT_SET, compromiseSigns, webSigns, networkSigns, webDigest, digestDiff, diffLines, splitCommonLines } from './core/mamoricho.js';
export { Inquiry } from './core/inquiry.js';
export { classifyCommand, llmJudge } from './core/classify.js';
export { ROOT_STEPS, sudoersLines, sudoersEscape } from './core/rootsteps.js';
export { ADMIN_RULES, ADMIN_NOTE, adminRules } from './core/admin-rules.js';
export { ITEMS, CATEGORIES, BASELINE, STATUSES } from './core/checklist.js';
export * as authzPolicy from './core/api-authz-policy.js';
export { Scs, SCS_CATEGORIES, hints as scsHints } from './core/scs.js';
export { SCS_CRITERIA, SCS_SOURCE } from './core/scs-criteria.js';
export { SCS_GUIDE, SCS_KINDS } from './core/scs-guide.js';
export { Ledgers, LEDGER_KINDS } from './core/ledgers.js';
export { Policies, paragraphs, keywordHits } from './core/policies.js';
export { POLICY_TEMPLATES } from './core/policy-templates.js';
export { Notices } from './core/notices.js';
export { docxText, mdToDocx } from './core/docx.js';
export { registerExtRoutes } from './routes.js';

export function createMamoricho(cfg, rawPorts) {
  const ports = makePorts(rawPorts); ensureSchema(ports.db());
  const probe = new Probe(cfg, ports); const mm = new Mamoricho(cfg, ports, { probe }); const authz = new ApiAuthz(cfg, ports, { probe, mm }); mm.authz = authz; const inquiry = new Inquiry(mm, ports, { probe });
  const ledgers = new Ledgers(ports, { mm, probe }); const notices = new Notices(ports, { mm }); const policies = new Policies(ports, { mm, notices }); const scs = new Scs(cfg, ports, { mm, probe, ledgers, policies, notices }); mm.scs = scs;
  return { ports, probe, mm, authz, inquiry, scs, ledgers, policies, notices };
}
