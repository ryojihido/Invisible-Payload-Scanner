# Invisible Payload Scanner v0.6.0

## 日本語

v0.6.0は「何が見つかったか」と「どこまで調べられたか」を分け、検出後に迷いにくくする更新です。

2026年11月5日の公開前更新として、TensorLake npm `0.5.144` の影響版照合・限定依存検査と、Cursor配布Claude Code拡張の `extension.js` 内の複合IOC検出を追加しました。Cursorの版番号だけは警告せず、公式の10月30日訂正版に基づく2指標の同時一致を確認します。拡張フォルダーは利用者が指定します。アーカイブ検査・PC全体のSSH設定や常駐状態の検査・駆除は含みません。追加ルールと出典は `rules/v0.6/october-2026-incidents.json`、使い方と限界はREADMEを参照してください。

- 読めないファイル、解析失敗、時間・件数・サイズ上限を未完了として表示。検出ゼロを全面的な安全とは扱いません。
- 関係する操作を実行したか、結果画面で任意に回答できます。未回答でも保存でき、回答だけで感染と判定しません。
- 対処手順をテキストで保存できます。結果と回答は自動送信せず、開いている画面や保存したテキストで手順を確認できます。
- 詳細設定と検出一覧を折りたたみ、最初の画面はフォルダー指定とスキャンを中心にしました。
- 依存ライブラリの開発・配布用設定や、条件を満たすローカル向けテストは参考情報として残します。外部コードの取得・実行、難読化、認証情報、既知IOC・影響版の警告は維持します。
- 同梱ルールが不足・破損している場合は明示的に停止します。中止・失敗したスキャンで、古い成功結果が復活しないようにしました。
- 起動時のスクリプトハッシュを.NETで直接計算し、`Get-FileHash` コマンドを利用できない起動環境でも同じSHA-256を表示します。計算に失敗した場合は開始しません。

利用方法：スキャナのZIPを新しいフォルダーに展開し、`Start-InvisiblePayloadScanner.cmd` をダブルクリックします。古い版とファイルを混ぜず、`www` と `rules` も一緒に保ってください。詳細は同梱READMEを参照してください。

JSONは `reportSchemaVersion: 2` です。従来のフィールドを保持し、`toolVersion`、検査範囲、案内根拠と本人の回答を追加しています。元の検出指標は `signalSeverity` に残ります。

これはローカルの静的スキャナです。感染確定、駆除、PC全体の検査、未知の攻撃の検出を保証しません。既存の複合検出などに誤検知が残る場合があります。通常のWindowsとブラウザの利用環境が必要で、追加の開発パッケージは不要です。

## English

v0.6.0 separates findings from scan completion and makes the next steps easier to follow.

The November 5, 2026 pre-release update adds affected-version and targeted dependency checks for TensorLake npm `0.5.144`, and combined IOC detection in the Cursor-distributed Claude Code extension's `extension.js`. Both markers from Cursor's October 30 corrected advisory must match; extension versions alone do not trigger warnings. Select the extension folder explicitly. Archive scanning, whole-host SSH/persistence inspection and removal are not included. Rules and sources are in `rules/v0.6/october-2026-incidents.json`; see README for usage and limits.

- Reports unreadable files, parse failures, timeouts and limits as incomplete checks.
- Adds optional, context-specific execution questions and offline-readable text export. Answers alone do not establish infection.
- Collapses advanced settings and the findings table so folder selection and scanning stay prominent.
- Retains narrowly defined dependency development and loopback-test findings as reference information. Download-and-execute, obfuscation, credential, known IOC and affected-version warnings remain.
- Fails explicitly on missing or invalid rule packs and prevents stale success results after cancellation or failure.
- Computes the startup script SHA-256 directly with .NET, without depending on `Get-FileHash` availability. A calculation failure prevents startup.

Extract the complete ZIP to a new folder and double-click `Start-InvisiblePayloadScanner.cmd`. Keep `www` and `rules` with the launcher and script; do not mix versions. See the bundled README for the three-step guide.

JSON uses `reportSchemaVersion: 2`, preserves existing fields and adds `toolVersion`, coverage and response context. Original signals remain in `signalSeverity`. This is a local static scanner, not a whole-PC infection assessment or malware-removal tool. False positives, including in existing compound detections, remain possible.

Archive: `InvisiblePayloadScanner-v0.6.0.zip`. Compare its SHA-256 with the separate checksum supplied alongside the archive or the hash in the published release notes. Matching a hash establishes file identity, not code safety.
