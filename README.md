# まもり帳 (Mamoricho)

中小企業の情報漏えい対策の「最低限」を、**対話で確かめて記録に残し、読むだけで診断し、管理者と API の権限を見張る**道具です。
安全を保証するものではありません。「基本を確かめ、いつ・誰が・何で確かめたかを記録に残した」と示すための道具です (利用者の言葉では「言い訳ツール」)。

- 基準: 個人情報保護委員会「大規模な漏えい等事案を踏まえた対応について (注意喚起)」(2026-10-07) と WARNING の 9 事例。中小規模事業者の手法の例示を「最低ライン」に。
- **点検**: ふつうの言葉の 42 の質問。文章で答えれば AI が状態を提案し、決めるのは人。
- **診断**: サーバー (SSH)・公開 HP (https)・ネットワーク機器に、**読むだけ**の決まった手順を使い捨てコンテナから流す。乗っ取り・トロイの木馬・改ざん・設定不備の兆候 (機械的な目安) と、前回との差分。
- **管理者の見張り**: ログイン履歴・認証ログ・監査ログを時刻順のイベントに直し、10 の規則 (管理者が増えた / 鍵が増えた / 多要素認証の直後の操作 / 権限を上げた直後のトークン …) を当てる。取れない材料は「確認できなかった」。
- **API の権限**: 自社の Web / API に、テスト用の主体 (未ログイン・一般・管理者) で「表どおりか」を GET/HEAD だけで確かめる。住所を固定・転送を追わない・毎秒 1 回・承認してから。
- **記録**: 1 件ごとに前の記録のハッシュを含めて署名した鎖。後から書き換えると分かる。
- **AI**: ローカル LLM (Ollama 標準。OpenAI 互換・Anthropic も選べる) は、聞き取り・まとめ・説明の役だけ。判定の基準と調査のコマンドは決定的な仕組み (許可リスト・署名・人の承認) で縛る。AI が止まっていても、規則と記録は動く。

## 動かし方 (単体版)

必要なもの: Node.js 22.13 以上、docker (調査用の使い捨てコンテナ)、任意で Ollama など (無ければ AI の機能だけ無効)。

```sh
git clone https://github.com/genai-craft/mamoricho && cd mamoricho
node standalone/cli.mjs init --user owner --password '********'   # 管理者 (owner) と鍵を作る。data/ ができる
node standalone/cli.mjs serve --port 7700                          # http://localhost:7700/
```

設定は `data/config.json`:

```json
{ "port": 7700, "llm": { "provider": "ollama", "base_url": "http://127.0.0.1:11434/v1", "model": "qwen3:8b" } }
```

`provider` は `ollama` (標準) / `openai-compatible` (llama.cpp・vLLM・LM Studio・OpenAI・Groq など、`base_url` は `/v1` まで、`api_key`) / `anthropic`。接続先が社内でなければ、画面の「安全の仕組み」に「データが外に出る」と出ます。

docker で動かすなら `standalone/Dockerfile` と `standalone/compose.yml` (docker のソケットをマウントします。調査は別のコンテナを 1 回ごとに起動して消すため)。

## 作り

```
core/      台本・調査の型・差分・兆候・コマンドの判定 (classify) と root の完全一致コマンド (rootsteps)・管理者監視・API 認可の純粋な計算・記録の鎖
runner/    使い捨てコンテナの実行器 (probe.js)・API 認可検査の実行 (api-authz.js)
llm/       LLM の口 (providers.js)
ui/        画面 (単体版の shell と、言箱 OS のデスクトップの両方に載る)
ports.js   外の世界に求めるもの (db / audit / requireRole / vault / approvals / signer …)。実装は standalone/ か、組み込み先が差し出す
standalone/ 単体版 (ローカルログイン・SQLite・署名つき監査・画面内承認・ローカル金庫・ed25519 鍵)
test/      パッケージ自身のテスト (`npm test`): 境界 (import が node: と中だけ) と、単体版の通し (ログイン → 画面の API → 記録の鎖 → 承認 → 金庫)
```

パッケージの中は node の標準モジュールとパッケージの中しか import しません (組み込み先の実装に依存しない)。これはテストで機械的に確かめ、GitHub Actions (.github/workflows/test.yml) で push ごとに走ります。

## 言箱 (Kotohako) との関係

まもり帳は、社内に置く AI 専用パソコン「言箱 (Kotohako)」のアプリとして生まれました。言箱では、金庫・承認・監査・署名鍵・ローカル LLM (Akigrid)・AI NAS が組み込みで差し出され、設定なしで動きます。このリポジトリは、その中身を**どこでも動く形**にしたものです。言箱としての提供 (製品への組み込み・商標・サポート) は genai-craft から株式会社フューチャースタンダードへの別途の許諾によります (NOTICE)。

## ライセンス

Apache License 2.0。著作権は genai-craft (生成AI工房) に帰属します。「まもり帳」「言箱」「Kotohako」の名称・ロゴの使用権は含みません。

---

**Mamoricho** is a small-business security "minimum baseline" assistant: an interview-style checklist with signed records, read-only diagnostics run from disposable containers, admin-account takeover heuristics (10 rules over normalized login/auth/audit events), and API authorization checks (GET/HEAD only, pinned host, approved plans). A local LLM (Ollama by default; OpenAI-compatible or Anthropic optional) only interviews, summarizes and explains — rules and commands are deterministic and allow-listed. Apache-2.0, © genai-craft.
