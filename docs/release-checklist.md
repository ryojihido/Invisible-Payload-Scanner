# リリースチェックリスト / Release Checklist

リリースzipごとに、配布物の真正性をユーザーが検証できるようにするための運用手順です。

## リリース前

1. `pwsh -NoProfile -Command "[void][scriptblock]::Create((Get-Content -Raw ./Start-InvisiblePayloadScanner.ps1))"` でパースエラーがないことを確認する。
2. `pwsh -NoProfile -File ./Start-InvisiblePayloadScanner.ps1 -SelfTest` が成功することを確認する。
3. `rules/` 配下のすべての `.json` が `ConvertFrom-Json` で読めることを確認する。
4. README.md / README.en.md / SECURITY.ja.md / SECURITY.md の記述が最新の挙動と一致していることを確認する。
5. zipに含めるファイルが前リリースと同じ構成（不要な内部文書・ローカルパスを含まない）であることを確認する。

### 検査範囲・対処案内の更新で追加する確認

- `pwsh -NoProfile -File tests/Test-OctoberIncidents.ps1` と `powershell.exe -NoProfile -File tests/Test-OctoberIncidents.ps1`。TensorLakeの確定版・限定依存検査、Cursorの複合IOCと正常同番号版、検査範囲、6番目の必須ルールの欠落・破損を確認する。合成データは `_drafts/incident-tests-*` に保持し、削除しない。ZIP展開版は `-ScannerRoot <展開したフォルダー>` で指定できる。
- 下記の既存テストには直接削除が含まれる。ごみ箱を経由しない削除を承認していない場合は原本をそのまま実行せず、隔離コピーで後始末を保持へ変更し、欠落ルールの試験はコピーの名前変更で行う。検証本体・期待値は変えず、その実行条件を記録する。

- `pwsh -NoProfile -File tests/Test-ScanCoverage.ps1` と `powershell.exe -NoProfile -File tests/Test-ScanCoverage.ps1`。専用の合成データだけを作り、終了時に削除する。5000件境界の検査には数分かかる。
- `node tests/Test-ResultUI.cjs`。Nodeは開発テスト用であり、利用者の起動には不要。DOM・通信の代用品はこの隔離テストだけに置き、本番へ同梱しない。
- `pwsh -NoProfile -File tests/Test-DependencyTriage.ps1` と `powershell.exe -NoProfile -File tests/Test-DependencyTriage.ps1`。依存ライブラリの参考情報化と、偽装ホスト・取得実行・認証情報・通常のinstall hook・既知影響版の警告維持を確認する。
- `pwsh -NoProfile -File tests/Test-ReparseBoundary.ps1` と `powershell.exe -NoProfile -File tests/Test-ReparseBoundary.ps1`。ジャンクション対応のWindows一時フォルダーに合成データを作り、リンクを追跡しないことを確認する。非対応の保存先では未実施として記録する。
- 通常画面のフォルダー入力→スキャンを、詳細設定や事前質問を開かずに完了できること。
- 「検出0＋一部未完了」「全て対象外」「旧形式」「中断→言語変更」で安全・成功と誤解させないこと。
- 実行状態の未回答・変更・取消、別環境・CI、根拠不足で不要な通信遮断や全パスワード変更を出さないこと。
- JSONとテキストを実ブラウザで保存して読み直す。テキストには日時、scan ID、案内根拠、回答と検査不足があること。サーバー停止後も表示済みの手順を保存できること。
- 初心者による操作観察、キーボード操作、狭い画面、日英切替、スクリーンリーダーを確認する。自動テストだけで初心者試験を完了扱いにしない。
- 公開前にREADMEの「開発中」表記と版番号を配布物に合わせる。新しい配布物の画像には実際のローカルパス、ユーザー名、結果JSONを混ぜない。

## zip作成とSHA-256

1. `dist/` にリリースzipを作成する（例: `InvisiblePayloadScanner-v0.6.0.zip`）。
2. SHA-256を算出する:

   ```powershell
   Get-FileHash .\dist\InvisiblePayloadScanner-v0.6.0.zip -Algorithm SHA256
   ```

3. 算出したzip用SHA-256を **GitHub Releaseノートに必ず記載する**。
4. リリース後、Releaseページからzipをダウンロードし直し、同じSHA-256になることを確認する。

## ユーザー向け検証手順（READMEにも記載）

ダウンロードしたzipが公開されたハッシュと一致するかは、次の1行で確認できます:

```powershell
Get-FileHash .\InvisiblePayloadScanner-v0.6.0.zip -Algorithm SHA256
```

表示された英数字がGitHub Releaseページに記載されたzip用SHA-256と一致することを確認します。この照合だけでコードの安全性を保証するものではありません。

また、ツール起動時のPowerShellウィンドウに `Script SHA-256:` として
`Start-InvisiblePayloadScanner.ps1` 自身のSHA-256が表示されます。
これはzip全体のSHA-256とは別の値です。スクリプト単体のハッシュを公開する場合は、
zip用SHA-256とは別項目としてリリースノートに記載してください。

## 将来課題

- コード署名（Authenticode）は将来の検討課題です。現時点ではSHA-256照合を一次手段とします。
