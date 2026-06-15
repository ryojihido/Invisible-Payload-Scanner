# Invisible Payload Scanner

**AIに作らせたコードや、ネットで拾ったプロジェクトを“動かす前”に、隠れた危ない入口がないかを一度だけ確認するための、Windows用ローカルツールです。**

外部に送信せず、あなたのPCの中だけで動きます。コマンド操作は不要。ダウンロードして展開し、`.cmd` をダブルクリックするだけで、ブラウザの画面から確認できます。

![Invisible Payload Scanner：v0.4.1 の起動画面](docs/preview.png)

英語版は [README.en.md](README.en.md)。安全設計と報告範囲は [SECURITY.ja.md](SECURITY.ja.md)（英語版 [SECURITY.md](SECURITY.md)）にまとめています。

---

## これは何？

- AIエージェント（Claude / Cursor など）に渡す前、`npm install` やビルドの前に、**プロジェクトのフォルダを1回スキャン**します。
- 結果は**3色の判定**で返します — 🔴 **止まれ** / 🟡 **確認して** / 🟢 **危ない入口は見つからず**。
- **100%ローカル**。スキャン内容を外部に送りません。ファイルは**読むだけ**で、実行しません。
- オープンソース（MITライセンス）。中身はあなた自身（や、あなたのAI）が読んで確かめられます。

## なぜ必要？

最近の攻撃の一部は「目に見えない」形で仕込まれます。

- ソースコードに、**見えない特殊文字**で命令を隠す（GlassWorm系の不可視Unicode）
- フォルダを開いた／インストールした**瞬間に自動で動く**設定（`postinstall`、エディタの `tasks.json` など）
- **AIエージェント向けの指示ファイル**（`CLAUDE.md` / `AGENTS.md` / `.cursor/rules`）に紛れ込ませる

面接課題、サンプルコード、知人から届いたリポジトリ、AIに生成させたプロジェクト——これらを**開いた瞬間**に動き出すものがあります。このツールは、その入口を**動かす前に**見るためのものです。

---

## 使い方（3ステップ）

1. **ダウンロードして展開** — GitHubのReleasesから最新の `InvisiblePayloadScanner-v0.4.1.zip` を入手して展開します。**まだ `npm install`・ビルド・起動はしないでください。**
2. **`Start-InvisiblePayloadScanner.cmd` をダブルクリック** — ローカルのWeb UIが起動し、ブラウザが開きます。
   - ⚠ **「WindowsによってPCが保護されました」**（SmartScreen）が出ることがあります。これは、同梱のローカルスクリプトを動かすための表示です。**「詳細情報」→「実行」** で進めてください。この扱いは、このツール同梱の `.ps1` だけに限ること。**出所不明の `.cmd` / `.ps1` に同じことをしないでください。**
3. **フォルダを選んでスキャン** — 確認したいプロジェクトフォルダのパスを貼り付けて `スキャン開始` を押します。フォルダの大きさに応じて数秒〜で**判定カード**が出ます。
   - パスは、エクスプローラーで対象フォルダを開き、上のアドレスバーの文字列をコピーして貼り付けるのが簡単です。Windowsの「パスのコピー」で `"C:\path\to\project"` のように引用符が付いても、そのまま貼り付けられます。

> スキャンの前に、画面上部に常にこう表示されます：「**このツールはファイルを読むだけで、実行・送信はしません。結果はこのPCの中だけに表示されます。**」

---

## 判定の見方（v0.4.1 Verdict-First）

スキャンが終わると、まず大きな**判定カード**が出ます。詳細の表より先に、「**で、このフォルダは触っていいの？**」に答えます。

- 🔴 **このプロジェクトは実行しないでください**
  既知の攻撃手口や、自動で動く危険な設定が見つかりました。次の一手：
  1. `npm install`・ビルド・起動を**しない**
  2. VS Code / Cursor で**開かない**（開くなら Restricted Mode）
  3. 結果JSONを保存して、詳しい人か AI に相談する
- 🟡 **実行する前に、確認したい点があります**
  気になる入口が見つかったか、または誤検知寄りの可能性があります。表示されたファイル名を確認してください。
- 🟢 **危ない入口は見つかりませんでした**
  目立つ危険は見つかりませんでした。ただし**完全な安全保証ではありません**（ウイルス対策ソフトやEDRと併用してください）。

> むずかしい言葉は、カードの中でやさしく言い換えます（例：「異体字セレクタ」→「**見えない特殊文字**」、「install lifecycle script」→「**インストール時に自動で動くスクリプト**」）。

スキャンを途中で止めたいときは、進捗ゲージ脇の **`スキャン中止`** を押せば数秒以内に止まります（サーバは動き続けるので、設定を変えてそのまま再実行できます）。`ツールを終了する` はローカルサーバごと閉じるためのボタンです。万一画面が応答しないときは、起動したPowerShellウィンドウを閉じても安全です。

---

## v0.4.1「Verdict-First UX」の新しいところ

v0.4.1は、v0.4.0の判定カード、スキャン中止、SHA-256確認、download-and-execute検出をそのまま引き継ぎ、巨大なモデルファイルを含むフォルダでもスキャンが途中停止しないよう修正した安定化版です。

- **巨大モデルファイルの安全なスキップ** — `.safetensors` や `.pt` などの数GB級ファイルが混ざっていても、最大ファイルサイズ判定で先にスキップし、候補ファイル列挙中のエラーを防ぎます。
- **不可視文字周辺の絵文字対応** — 不可視Unicodeの近くに絵文字などの補助面Unicodeがあっても、検出結果の抜粋生成で失敗しないようにしました。
- **エラー時の診断改善** — 予期しない例外が起きた場合、起動中のPowerShellウィンドウにマスク済み詳細を表示します。

### v0.4.0からの主な改善

- **判定ファースト表示** — 重要度の表より先に、🔴🟡🟢 の判定と「次の一手」を出します。
- **安全なスキャン中止** — スキャン中でも `スキャン中止` ボタンで止められます（以前は PowerShell ウィンドウを閉じるしかありませんでした）。
- **配布物の真贋確認（SHA-256）** — ダウンロードしたzipが本物か、1行で確認できます（下記）。
- **download-and-execute の検出を追加** — `curl … | bash`、`iwr … | iex`、`powershell -enc …`、`certutil` / `mshta` / `bitsadmin` / `rundll32` などの古典的な「取得して実行」を検出します（単独では低リスク、`postinstall` や `folderOpen` などと重なると格上げ）。

## ダウンロードしたzipが本物か確認する（任意・推奨）

展開する前に、PowerShellで次の1行を実行してください（ファイル名はダウンロードしたバージョンに合わせます）:

```powershell
Get-FileHash .\InvisiblePayloadScanner-v0.4.1.zip -Algorithm SHA256
```

表示された英数字が、GitHub Releaseページに記載された **zip用SHA-256** と同じなら本物です。違う場合は使わずに、Releaseページからダウンロードし直してください。

また、ツール起動時のPowerShellウィンドウには `Script SHA-256:` として、展開後に実行されている `Start-InvisiblePayloadScanner.ps1` 自身のハッシュが表示されます。これはzip全体のSHA-256とは別の値です。コード署名（Authenticode）は将来の検討課題で、現時点ではGitHub Releaseに記載されたSHA-256との照合が確認手段です。

---

## 何を見つけられる？（概要）

- **見えない特殊文字** — GlassWorm系の不可視Unicode、Trojan Source系の双方向制御文字、ゼロ幅スペースなど
- **インストール時に自動で動くスクリプト** — npmの `prepare` / `postinstall` など
- **エディタ／AIの自動実行** — VS Code・Cursor の `tasks.json`（`folderOpen`）、AIエージェントの hooks
- **AIエージェント向けの指示ファイル** — `CLAUDE.md` / `AGENTS.md` / `.cursor/rules` など
- **危険な「取得して実行」** — `curl|bash`、`iwr|iex`、`powershell -enc`、LOLBin（v0.4.0で追加）
- **CI／Git連携の危険コマンド候補** — GitHub Actions workflow、`.husky/` / `.githooks/`
- **既知のnpmサプライチェーンIoC** — 公開された攻撃の痕跡（例：2026年5月の TanStack 事案のIoC ほか）

## これは何ではないか（正直に）

- **感染判定器ではありません。** 「知らないものを動かす前に、一度止まる」ための検査補助です。
- **ウイルス対策ソフト・EDR・`npm audit`・専門的なサプライチェーン監査の代わりではありません。** ESETやWindows Defenderなどの常駐保護と併用してください。
- **検出ゼロ＝安全確定ではありません。** バイナリ埋め込み、インストール時に外部から取得されるコード、難読化された通常文字のローダーなどは、このツールだけでは網羅できません。

---

> ここから下は、詳しい仕様・運用・設計の詳細です（必要なときに参照してください）。

## スキャン範囲の目安

このツールは、GitHubなどから展開した「1つのプロジェクトフォルダ」を確認する想定です。

おすすめは、次のようなフォルダをそのまま指定することです。

- `package.json` が入っているプロジェクトのルートフォルダ
- `.vscode/` や `.cursor/` が入っているプロジェクトのルートフォルダ
- 面接課題やMVPレビューとして送られてきたフォルダ

反対に、次のような大きすぎる範囲は避けてください。

- `C:\Users\自分の名前` 全体
- `Downloads` 全体
- `Documents` 全体
- PC全体やドライブ全体

大きな親フォルダを指定すると、候補ファイルが多すぎて時間がかかったり、上限に達したりします。PC全体のウイルス検査は、ESETやWindows Defenderなどの常駐保護・フルスキャンに任せてください。

候補ファイルが多すぎる場合は、次のように絞ります。

- GitHubから展開した対象プロジェクトのフォルダだけを指定する
- 除外ディレクトリに `node_modules;AppData;Windows;Program Files` などを追加する
- まずは `node_modules 全体も詳しく確認する` をオフのまま使う
- 必要な時だけファイル名フィルタや最大ファイルサイズを調整する

## 結果JSONの使い方

`結果をJSON保存` は、検出結果をあとで確認したり、詳しい人へ相談したりするための控えです。

使い道の例:

- 検出が出た時に、該当ファイル、行番号、検出語、重要度を保存する
- GitHub issue、Security Advisory、npmの公式情報と照合する時のメモにする
- 詳しい人やチームメンバーへ相談する時に、スクリーンショットより正確な情報として渡す
- すでに実行してしまった場合に、どのプロジェクト・どの痕跡を見たか記録する

JSONにはローカルパス、ユーザー名、プロジェクト名が含まれることがあります。公開issueやSNSに貼る前に、不要なパスや名前が含まれていないか確認してください。

検出ログをAIに見せて「これは実行前に止めるべき検出か、誤検知寄りか、次に何を確認すべきか」を相談する使い方も有効です。ローカルLLMではない外部AIに渡す場合は、JSON内のローカルパス、ユーザー名、プロジェクト名、snippet、未マスクの秘密情報が含まれていないか確認し、必要なら該当箇所を削ってから共有してください。

## npm系プロジェクトでの追加防御

このスキャナで検出が出た場合や、知らないNode.jsプロジェクトを扱う場合は、実行前の追加防御として次のような設定も検討できます。

これはこのツールが自動で行う処理ではありません。既存プロジェクトのパッケージマネージャを変えると挙動が変わることがあるため、必要に応じて詳しい人やAIエージェントに内容を確認させてください。

pnpmを使う場合の例:

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 4320
minimumReleaseAgeStrict: true
blockExoticSubdeps: true
```

- `minimumReleaseAge` は、公開直後の新しいパッケージをすぐに入れないための待機時間です。`4320` は3日を意味します。
- `minimumReleaseAgeStrict: true` は、待機時間を満たす候補がない場合に解決を失敗させる設定です。
- `blockExoticSubdeps: true` は、推移的依存がgitや直接tarball URLなどからコードを取ってくるのを防ぐための設定です。
- install scriptを許可制にしたい場合は、pnpm 11系では `allowBuilds` や `pnpm approve-builds` を確認します。

AIエージェントに依頼する場合の例:

```text
このリポジトリの依存関係を安全側に見直してください。
可能ならpnpmに移行し、pnpm-workspace.yamlで minimumReleaseAge: 4320、minimumReleaseAgeStrict: true、blockExoticSubdeps: true を設定してください。
install/build/testで動作確認し、install scriptはallowBuildsまたはpnpm approve-buildsで必要なものだけ許可してください。
既存の挙動が変わる場合は、変更前に説明してください。
```

## 既定のGlassWorm系検出式

```powershell
([\uFE00-\uFE0F]|\uDB40[\uDD00-\uDDEF]){8,}
```

- `U+FE00` から `U+FE0F` は `\uFE00-\uFE0F` で検索します。
- `U+E0100` から `U+E01EF` は .NET/PowerShell の正規表現上ではサロゲートペアとして `\uDB40[\uDD00-\uDDEF]` で検索します。
- `{8,}` は「8個以上の連続」を意味します。
- 一次スクリーニングは `8` 以上、広いPC全体スキャンなら `16` 以上を推奨します。
- 数字を小さくすると感度が上がり、数字を大きくすると誤検知が減ります。

このツールが内部で使う検索式を、PowerShellだけで最小確認する場合は次の形になります。

```powershell
Get-ChildItem -LiteralPath "C:\path\to\project" -Recurse -File -ErrorAction SilentlyContinue |
  Select-String -Pattern '([\uFE00-\uFE0F]|\uDB40[\uDD00-\uDDEF]){8,}'
```

`-Filter ""` は空ではなく、指定しないか `-Filter *` にします。`-Filter` は基本的に1つのワイルドカード指定なので、複数拡張子を扱う場合はこのツールのWeb UI側のように `;` 区切りの独自フィルタを使う方が扱いやすいです。

## 既定の除外

既定では、よくある生成物やこのスキャナ自身のセルフテスト用フォルダを除外します。

```text
.git;dist;build;coverage;.cache;.next;.nuxt;out;.tmp;temp;_selftest;_compound_selftest;.edge-preview-profile
```

`_selftest` と `_compound_selftest` は、このツールの自己診断で作る検知確認用フォルダです。このスキャナの開発フォルダ自体を確認する時に、わざと危険に見えるテスト標本を通常のプロジェクト検出と混同しないため、既定では除外します。

また、次のファイルを除外します。

```text
README.md;*.md
```

Markdown内の絵文字やアクセシビリティ記号では `U+FE0F` が普通に使われることがあり、`README.md` などの説明文ファイルは通常実行されないためです。

ただし、READMEやMarkdownをビルド工程でコード生成に使う特殊なプロジェクトを確認したい場合は、除外ファイル名から `README.md;*.md` を外して再スキャンしてください。

## 進捗表示

スキャンは2段階です。

1. 候補ファイルを数える
2. 候補ファイル内の不可視文字や自動実行設定を確認する

Web UIのゲージは、1段階目では動作中表示、2段階目では候補ファイル数に対する検索済み割合を表示します。巨大フォルダでは候補ファイルの列挙にも時間がかかります。

## 拡張性

Web UIの `検索ルール` で `カスタム正規表現` を選ぶと、今後別のIoCや不可視文字にも対応できます。

組み込みルールとして、次の補助検出も選べます。

- GlassWorm系の可視デコーダ兆候: `codePointAt()`、`0xFE00` / `0xE0100`、`eval()` / `Buffer.from()` などが近い範囲に現れるコード
- Trojan Source系の双方向制御文字
- JavaScript識別子として悪用されることがあるHangul filler
- ゼロ幅スペースなどのゼロ幅制御文字

例:

```powershell
[\u200B-\u200F\u2060-\u2064\uFEFF]{1,}
```

これはゼロ幅スペース、方向制御、BOMなどの不可視制御文字を探すための例です。

## Supply Chain IOC Scan

Safety Pre-Scanでは、不可視Unicodeとは別に、既知のnpmサプライチェーン攻撃、install-time scripts、VS Code/Cursorの自動実行設定、AIエージェントhooks、GitHub Actions workflowの危険コマンド候補、Git hook候補に関係する痕跡を確認します。

確認対象の例:

- `package.json`
- `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`
- `.vscode/tasks.json`
- `.cursor/tasks.json`
- `.claude/settings.json`
- `AGENTS.md`, `CLAUDE.md`, `.cursor/rules/*`, `.windsurfrules`, `.github/copilot-instructions.md`
- `.github/workflows/*.yml`
- `.husky/*`, `.githooks/*`
- `.npmrc`, `.env*`
- `node_modules/**/package.json`

初期ルールは `rules/ioc-rules.json` に同梱しています。2026年5月のTanStack npm supply-chain compromiseで公開されたIoCを中心に、悪性git ref、`@tanstack/setup`、`router_init.js`、`tanstack_runner.js`、`filev2.getsession.org`、`seed*.getsession.org`、既知の影響バージョン候補を静的に照合します。

v0.3の追加ルールは、見分けが付きやすいように `rules/v0.3/` に分けています。

- `rules/v0.3/contagious-interview-rules.json`: 偽リクルーター/技術課題型リポジトリで見られる `folderOpen`、download-and-execute、短縮URL、Gist/Drive/Vercel系stager、install lifecycle、GitHub Actions workflowの危険コマンド候補、Git hook候補の静的ヒューリスティック
- `rules/v0.3/safe-patterns.json`: `husky install`、`lint-staged`、`npm run build` など、低リスク寄りに下げるためのローカルsafe-patterns

v0.4の追加ルールは `rules/v0.4/` にあります。

- `rules/v0.4/download-and-execute-rules.json`: `curl|wget … | sh/bash/node`、`iwr/irm … | iex`、`powershell -e/-enc <base64>`、および `certutil -urlcache/-decode`・`mshta https:`・`bitsadmin /transfer`・`rundll32 … javascript:` などのLOLBinを静的に照合します。単独一致はLow/Info、`folderOpen`・install lifecycle・Git hook・workflowなどと重なったときにHigh/Criticalへ格上げします。公式インストーラ系の1行（例: `curl -fsSL https://get.pnpm.io | sh`）はsafe-patternsに追加せず、未知リポジトリでは確認を促し、documentation文脈ではInfoに下げます。

safe-patternsは警告を完全に消すものではありません。危険なdownload-and-execute、shell、base64/encoded payload、credential harvestingらしい語が同時に見つかる場合は、safe-patternsより危険判定を優先します。

この機能は、パッケージ名だけで悪性と断定しません。`@tanstack/` のような名前空間一致は注意表示であり、危険度が上がるのは既知の悪性バージョン、既知IoC文字列、自動実行設定、install scriptの危険語などが重なった場合です。

v0.3では、単独の文字列一致よりも組み合わせを重視します。たとえば `.vscode/tasks.json` や `.cursor/tasks.json` の `runOn: folderOpen` が `npm install` / `npm i` / `pnpm i` / `yarn install` / `bun i` などを起動し、同じプロジェクトの `package.json` に `prepare` / `postinstall` などのinstall lifecycle scriptがある場合は、複合リスクとして追加表示します。

v0.3.1では、検出語そのものの危険度を `signalSeverity` として残しながら、実際の対応優先度を `severity` / `actionability` / `pathContext` で分けます。JSONの `summary` は表示上の対応優先度、`signalSummary` は元の検出シグナルの集計です。スキャン対象ルート直下の `.github/workflows/*.yml` は従来どおり強く扱います。一方、SDK、依存部品、上流コピーの内側にあるネストした `.github/workflows/*.yml` は、通常のローカル実行では動かないため、低めの対応優先度として表示します。検出を消すのではなく、CIを有効化する前の確認材料として残します。

`.env` や `.npmrc` は秘密情報を含む可能性があるため、検出結果では抜粋そのものを隠し、トークンらしい文字列もマスクします。JSON結果を公開する場合も、ローカルパス、ユーザー名、プロジェクト名が含まれていないか確認してください。

検出が出たときの簡易対策:

1. `Critical` がある場合は、そのプロジェクトを実行しないでください。
2. `npm install`、ビルド、起動、AIエージェントによる自動修正を止めます。
3. VS CodeやCursorで開く場合はRestricted Modeを使い、`.vscode/tasks.json` / `.cursor/tasks.json` を確認します。
4. `.claude/settings.json` などのhooksや、`AGENTS.md` / `CLAUDE.md` / `.cursor/rules/` などの指示ファイルがある場合は、AIエージェントで開く前に内容を確認します。
5. `.husky/` や `.githooks/` が検出された場合は、`git commit`、`git checkout`、`git merge` などで実行される可能性があるため、hookの内容を確認します。
6. package名だけの検出は悪性確定ではありません。バージョン、lockfile、公式アドバイザリを確認してください。
7. 既に実行済みでCritical/Highが出た場合は、GitHub token、npm token、APIキー、SSH鍵などのローテーションを検討してください。

## 精度と安全性の設計

このツールの検出精度は、次の構造で高めています。

- 既知情報に合わせ、異体字セレクタ `U+FE00` から `U+FE0F` と異体字セレクタ補助 `U+E0100` から `U+E01EF` を対象にします。
- PowerShell/.NETの正規表現で5桁コードポイントを誤指定しないよう、補助面は `\uDB40[\uDD00-\uDDEF]` のサロゲートペアで検索します。
- 連続個数をしきい値化し、単発の絵文字用 `U+FE0F` と長い不可視ペイロードを分けやすくしています。
- 最新の公開分析で重視されている「不可視文字列本体」と「それを復元する可視デコーダ兆候」は別ルールとして確認できます。
- 検出箇所は不可視文字を `[VS U+XXXX]` として可視化し、周辺文字列、行、列、コードポイントを表示します。
- バイナリ拡張子、巨大ファイル、指定除外ディレクトリ、指定除外ファイルをスキップできます。

Web UI自体の安全性は、次の構造で高めています。

- 外部サーバにデータを送信しません。
- `127.0.0.1` のローカルHTTPサーバとして動作します。
- 起動ごとにランダムなローカルAPIトークンを生成し、スキャンや停止APIに必要とします。
- Hostヘッダーを `127.0.0.1:<port>` / `localhost:<port>` に限定します。
- APIリクエストのOriginを確認し、OriginがないAPI呼び出しや別サイトからの単純なローカルAPI呼び出しを通しにくくしています。
- Content-Security-Policyなどのブラウザ向け安全ヘッダーを返します。
- 指定されたファイルは読み取りのみで、実行しません。
- 検出結果はブラウザ上に表示され、JSON保存はユーザー操作時のみ行います。
- 検索に使う正規表現はPowerShell/.NET上で実行し、各ファイルごとに正規表現タイムアウトを設定しています。
- シンボリックリンクやジャンクションなどの再解析ポイントは追跡しません。
- リクエストサイズ、正規表現長、対象ファイルサイズ、候補ファイル数に上限を設けています。

この設計でも、次のものは保証できません。

- 同じWindowsユーザー権限で既に悪意あるプロセスや危険なブラウザ拡張機能が動いている場合の保護
- バイナリに埋め込まれたマルウェア
- インストール時に外部から取得されるコード
- 難読化された通常文字ベースのローダー
- Solana、Google Calendar、WebRTC、HTTPエンドポイントなどのC2痕跡の網羅検知
- `.npmrc`、GitHub token、SSH鍵、ウォレットなどのcredential harvesting挙動の網羅検知
- 既知の悪性パッケージ名、拡張機能名、IP、ウォレットアドレスなどのIoC照合
- 依存パッケージ自体の正当性
- 検出文字列が本当に実行経路に乗るかどうか

## プライバシー

このスキャナはローカル実行を前提にしています。

- `127.0.0.1` にだけバインドします。
- スキャン対象ファイルの内容を外部へアップロードしません。
- 外部APIを呼び出しません。
- パッケージインストールやネットワーク接続を必要としません。
- JSONエクスポートは、ユーザーが保存ボタンを押した場合だけ作成します。

スクリーンショットを公開する場合は、ローカルパス、ユーザー名、公開したくないパッケージ名やプロジェクト名が写っていないことを確認してください。

## 検出後の対応

まず、検出されたファイルの種類で優先度を分けます。

高優先度:

- `.js`, `.ts`, `.mjs`, `.cjs`, `.jsx`, `.tsx`
- `.ps1`, `.cmd`, `.bat`, `.sh`
- `package.json`, npm scripts, GitHub Actions, CI設定
- ビルド時や起動時に読まれる設定ファイル

低優先度または誤検知寄り:

- `README.md`
- `CHANGELOG.md`
- `docs/` 配下のMarkdown
- `.vscode/extensions/` や `.antigravity/extensions/` など、エディタ/AIツールの拡張機能フォルダ内の既存script
- 絵文字、アクセシビリティ記号、バッジ、リンク周辺の `U+FE0F`
- `U+FE0F` が数個だけ連続している説明文

検出したら、次の順で確認します。

1. しきい値を `16` に上げて再スキャンします。
2. `README.md;*.md` を除外した状態で実行ファイル系だけ再スキャンします。
3. 実行されるファイルで長い不可視文字列が出た場合は、そのパッケージやリポジトリを使う作業を一旦止めます。
4. `npm install` やビルドをまだ実行していない場合は、実行しないまま入手元を確認します。
5. 既に実行済みの場合は、該当プロジェクトの依存関係、インストール時スクリプト、最近のコミット差分を確認します。
6. GitHubやnpmなどの公式ページ、issue、セキュリティアドバイザリで同名パッケージの報告がないか確認します。
7. 不審な場合はプロジェクトフォルダを削除する前に、検出結果JSON、該当ファイル、パッケージ名、バージョンを控えます。
8. 判断に迷う場合は、検出結果JSONを詳しい人やAIに見せて相談します。外部AIに渡す時は、ローカルパス、ユーザー名、プロジェクト名、snippet、秘密情報が含まれていないか先に確認してください。

誤検知の可能性が高い例:

```text
node_modules\focus-trap\README.md
U+FE0F U+FE0F U+FE0F U+FE0F
周辺表示: Accessibility や絵文字リンク
```

これはREADME内の絵文字・アクセシビリティ記号に反応している可能性が高く、感染確定ではありません。実行される `.js` や `.ts` に長い不可視文字列が出る場合とは扱いを分けてください。

エディタ拡張機能フォルダ内の `package.json` や `tasks.json` に反応することもあります。たとえば `.vscode/extensions/` や `.antigravity/extensions/` 配下は、正規の拡張機能がビルド用・開発用scriptを持っている場合があります。この場合は「危険確定」ではなく、拡張機能名、発行元、バージョン、意図して入れたものかを確認してください。身に覚えのない拡張機能、最近急に入った拡張機能、不審な発行元の場合は、無効化、削除、再インストール、公式マーケットプレイス情報の確認を検討してください。

---

## リリースの種類 / どれを使えばいい？

通常は最新の **v0.4.1 Verdict-First UX** を使ってください。Web UIでは、まず `両方まとめて確認（v0.4おすすめ）` のまま使い、不可視Unicodeだけ確認したい時にスキャン種別を切り替えます。

- **v0.4.1 Verdict-First UX（推奨）** — v0.4.0の機能に加え、数GB級モデルファイルを含むフォルダでのスキャン停止を修正。
- **v0.4.0 Verdict-First UX（推奨）** — 検出結果を 🔴🟡🟢 の判定と「次の一手」で表示。スキャン中止、SHA-256確認、download-and-execute検出を追加。
- **v0.3.1 Context-Aware Triage** — 検出シグナルと対応優先度を分けて表示。UIは日本語/英語を切り替え可能。
- **v0.3.0 Contagious Interview Pre-Scan** — `npm install`・エディタ・AIエージェント・Git hook 周辺の自動実行設定を確認。
- **v0.2.0 Safety Pre-Scan** — 不可視Unicodeに加え、npmサプライチェーンIoC・自動実行設定を確認。
- **v0.1.0 Classic** — 不可視Unicode（GlassWorm系・Trojan Source系）専用の軽量版。

既存の `v0.1.0` はそのまま残し、リリース済みzipは差し替えません。新しい確認範囲と巨大ファイル修正が必要な場合は `v0.4.1` 以降を使ってください。

---

- 英語版 README: [README.en.md](README.en.md)
- 安全設計と報告範囲: [SECURITY.ja.md](SECURITY.ja.md) ／ [SECURITY.md](SECURITY.md)
- ライセンス: MIT
