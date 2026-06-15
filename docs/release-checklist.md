# リリースチェックリスト / Release Checklist

リリースzipごとに、配布物の真正性をユーザーが検証できるようにするための運用手順です。

## リリース前

1. `pwsh -NoProfile -Command "[void][scriptblock]::Create((Get-Content -Raw ./Start-InvisiblePayloadScanner.ps1))"` でパースエラーがないことを確認する。
2. `pwsh -NoProfile -File ./Start-InvisiblePayloadScanner.ps1 -SelfTest` が成功することを確認する。
3. `rules/` 配下のすべての `.json` が `ConvertFrom-Json` で読めることを確認する。
4. README.md / README.en.md / SECURITY.ja.md / SECURITY.md の記述が最新の挙動と一致していることを確認する。
5. zipに含めるファイルが前リリースと同じ構成（不要な内部文書・ローカルパスを含まない）であることを確認する。

## zip作成とSHA-256

1. `dist/` にリリースzipを作成する（例: `InvisiblePayloadScanner-v0.4.1.zip`）。
2. SHA-256を算出する:

   ```powershell
   Get-FileHash .\dist\InvisiblePayloadScanner-v0.4.1.zip -Algorithm SHA256
   ```

3. 算出したzip用SHA-256を **GitHub Releaseノートに必ず記載する**。
4. リリース後、Releaseページからzipをダウンロードし直し、同じSHA-256になることを確認する。

## ユーザー向け検証手順（READMEにも記載）

ダウンロードしたzipが本物かどうかは、次の1行で確認できます:

```powershell
Get-FileHash .\InvisiblePayloadScanner-v0.4.1.zip -Algorithm SHA256
```

表示された英数字が、GitHub Releaseページに記載されたzip用SHA-256と同じなら本物です。

また、ツール起動時のPowerShellウィンドウに `Script SHA-256:` として
`Start-InvisiblePayloadScanner.ps1` 自身のSHA-256が表示されます。
これはzip全体のSHA-256とは別の値です。スクリプト単体のハッシュを公開する場合は、
zip用SHA-256とは別項目としてリリースノートに記載してください。

## 将来課題

- コード署名（Authenticode）は将来の検討課題です。現時点ではSHA-256照合を一次手段とします。
