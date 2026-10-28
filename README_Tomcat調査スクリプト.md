# Tomcat 2026年10月 脆弱性影響調査スクリプト

Apache Tomcat のローカル環境を読み取り専用で確認し、次の3件について、upstream版の影響範囲と設定上の手掛かりをJSON形式で出力します。

- CVE-2026-101296（JNDIRealm）
- CVE-2026-101356（HTTP/2）
- CVE-2026-103119（AJP、Tomcat 11のみ）

## 動作要件

- Python 3.9以上
- Python標準ライブラリのみ
- ネットワーク通信なし
- 設定変更、Tomcat起動・再起動なし

## 使い方

```bash
python3 tomcat_oct2026_audit.py --self-test
python3 tomcat_oct2026_audit.py --base /opt/tomcat
python3 tomcat_oct2026_audit.py --base /srv/tomcat/base --home /opt/tomcat/home --json-out /tmp/tomcat-audit.json
```

複数インスタンスを調べる場合は `--base` を複数回指定します。`CATALINA_HOME` と `CATALINA_BASE` が異なる場合は、対応する `--home` も指定してください。

## 注意事項

このスクリプトは初動調査用です。設定ファイルに現れない外部設定、アプリケーションの非同期処理、JNDIRealmが実際にネゴシエートするSASL機構、OSベンダーのバックポートは完全には判定できません。検出結果だけで脆弱性の有無を断定せず、Apache TomcatおよびOS・コンテナベンダーの最新アドバイザリと照合してください。

スクリプトはTomcat公式アドバイザリ記載のupstream版範囲を判定します。ディストリビューションのパッケージは、元の版番号が変わらないまま修正がバックポートされている場合があります。
