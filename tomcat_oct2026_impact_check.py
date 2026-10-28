#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tomcat 2026年10月の重要CVE 3件を確認する読み取り専用棚卸しスクリプト。

確認対象:
  CVE-2026-101296: JNDIRealm + non-GSSAPI SASL 機構
  CVE-2026-101356: HTTP/2 コネクタ
  CVE-2026-103119: AJP コネクタ（Tomcat 11 のみ）

CATALINA_HOME の RELEASE-NOTES または lib/catalina.jar の MANIFEST と、
CATALINA_BASE/conf/server.xml をローカルで読みます。設定変更、Tomcat起動・再起動、
外部通信、シェル実行は行いません。

例:
  python3 tomcat_oct2026_impact_check.py --base /opt/tomcat
  python3 tomcat_oct2026_impact_check.py --base /srv/tomcat/base --home /opt/tomcat/home
  python3 tomcat_oct2026_impact_check.py --base /opt/tomcat --json-out /tmp/tomcat.json
  python3 tomcat_oct2026_impact_check.py --self-test

終了コード: 0=影響範囲内の構成要素なし、1=要対応・要確認あり、2=判定不能/引数エラー。
ディストリビューションのバックポートはバージョン番号だけでは判定できません。
OSベンダーのセキュリティアドバイザリも併せて確認してください。
"""
import argparse
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

FIXED = {"9.0": "9.0.123", "10.1": "10.1.61", "11.0": "11.0.27"}
RULES = [
    {"cve": "CVE-2026-101296", "severity": "Important",
     "title": "JNDIRealm の non-GSSAPI SASL 認証で資格情報検証に失敗する問題",
     "feature": "jndi", "ranges": [("9.0.0.M1", "9.0.122"),
         ("10.1.0-M1", "10.1.60"), ("11.0.0-M1", "11.0.26")]},
    {"cve": "CVE-2026-101356", "severity": "Important",
     "title": "HTTP/2 非同期処理エラー後のリクエスト／レスポンス混線",
     "feature": "http2", "ranges": [("9.0.118", "9.0.122"),
         ("10.1.55", "10.1.60"), ("11.0.22", "11.0.26")]},
    {"cve": "CVE-2026-103119", "severity": "Important",
     "title": "AJP 応答混線（Tomcat 11 のみ）",
     "feature": "ajp", "ranges": [("11.0.0-M25", "11.0.26")]},
]


def version_key(text):
    """通常版・マイルストーン版のバージョン文字列を比較用に変換。"""
    match = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)(?:[.-]M(\d+))?", str(text or ""))
    if not match:
        return None
    major, minor, patch = map(int, match.group(1, 2, 3))
    return (major, minor, patch, 0, int(match.group(4))) if match.group(4) else (major, minor, patch, 1, 0)


def detect_version(home):
    """RELEASE-NOTES を先に確認し、なければ catalina.jar の MANIFEST を読む。"""
    notes = os.path.join(home, "RELEASE-NOTES")
    if os.path.isfile(notes):
        try:
            with open(notes, encoding="utf-8", errors="replace") as f:
                text = f.read(20000)
            found = re.search(r"Apache Tomcat Version\s+(\d+\.\d+\.\d+(?:[.-]M\d+)?)", text)
            if found:
                return found.group(1), "RELEASE-NOTES"
        except OSError:
            pass
    jar = os.path.join(home, "lib", "catalina.jar")
    if os.path.isfile(jar):
        try:
            with zipfile.ZipFile(jar) as archive:
                manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
            found = re.search(r"^Implementation-Version:\s*(\d+\.\d+\.\d+(?:[.-]M\d+)?)",
                              manifest, re.MULTILINE)
            if found:
                return found.group(1), "lib/catalina.jar MANIFEST"
        except (OSError, KeyError, zipfile.BadZipFile):
            pass
    return None, None


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_server_xml(path):
    """AJP / HTTP/2 コネクタと JNDIRealm の設定上の手がかりを抽出。"""
    root = ET.parse(path).getroot()
    result = {"ajp_connectors": [], "http2_connectors": [], "jndi_realms": []}
    for node in root.iter():
        if local_name(node.tag) != "Connector":
            continue
        protocol = (node.get("protocol") or "").strip()
        port = (node.get("port") or "").strip()
        if protocol.upper().startswith("AJP") or port == "8009":
            result["ajp_connectors"].append({"port": port or "(未指定)",
                "protocol": protocol or "(未指定)", "address": node.get("address") or "(未指定)",
                "secretRequired": node.get("secretRequired") or "(Tomcat既定値)",
                "secret_configured": bool((node.get("secret") or "").strip())})
        upgrades = [child.get("className", "") for child in list(node)
                    if local_name(child.tag) == "UpgradeProtocol"]
        if any("Http2Protocol" in item for item in upgrades) or protocol.lower() in ("h2", "h2c"):
            result["http2_connectors"].append({"port": port or "(未指定)",
                "protocol": protocol or "(未指定)"})
    for node in root.iter():
        if local_name(node.tag) == "Realm" and "JNDIRealm" in (node.get("className") or ""):
            result["jndi_realms"].append({"className": node.get("className"),
                "authentication": node.get("authentication") or "(未指定)",
                "saslMechanism": node.get("saslMechanism") or "(未指定)"})
    return result


def matching_cves(version):
    current = version_key(version)
    if current is None:
        return []
    hits = []
    for rule in RULES:
        for low, high in rule["ranges"]:
            lo, hi = version_key(low), version_key(high)
            if lo[:2] == current[:2] and lo <= current <= hi:
                hits.append(rule)
                break
    return hits


def inspect(base, home=None):
    base = os.path.abspath(base)
    home = os.path.abspath(home or base)
    version, source = detect_version(home)
    server_xml = os.path.join(base, "conf", "server.xml")
    row = {"catalina_base": base, "catalina_home": home,
           "server_xml": server_xml, "version": version,
           "version_source": source, "fixed_version": None,
           "configuration_hints": None, "findings": [], "error": None}
    if not version:
        row["error"] = "バージョンを判定できません。RELEASE-NOTES または catalina.jar を確認してください。"
        return row
    row["fixed_version"] = FIXED.get(".".join(version.split(".")[:2]))
    if not os.path.isfile(server_xml):
        row["error"] = "CATALINA_BASE/conf/server.xml が見つかりません。"
        return row
    try:
        cfg = parse_server_xml(server_xml)
    except (OSError, ET.ParseError) as exc:
        row["error"] = "server.xml を読み取れません: %s" % exc
        return row
    row["configuration_hints"] = cfg
    for rule in matching_cves(version):
        feature = rule["feature"]
        if feature == "ajp":
            evidence = cfg["ajp_connectors"]
            status = "要対応候補" if evidence else "バージョン範囲内・設定記述なし"
            note = "Tomcat 11 の AJP コネクタが対象です。AJP利用が確認できれば修正版へ更新してください。"
        elif feature == "http2":
            evidence = cfg["http2_connectors"]
            status = "要対応候補" if evidence else "バージョン範囲内・設定記述なし"
            note = "HTTP/2コネクタの有効状態を確認してください。別ファイルや外部設定での構成は手動確認が必要です。"
        else:
            evidence = cfg["jndi_realms"]
            status = "要確認" if evidence else "バージョン範囲内・JNDIRealm記述なし"
            note = ("JNDIRealm が使われている場合、non-GSSAPI SASL 認証の構成かを確認してください。"
                    "XMLからSASLプロバイダの実際の動作までは確定できないため、自動的に影響ありとは断定しません。")
        row["findings"].append({"cve": rule["cve"], "severity": rule["severity"],
            "title": rule["title"], "affected_versions": ["%s ～ %s" % pair for pair in rule["ranges"]],
            "configuration_hint": evidence, "status": status, "note": note})
    if not row["findings"]:
        row["findings"].append({"status": "対象3件のupstream影響範囲外"})
    return row


def self_test():
    # 版の境界確認
    assert {x["cve"] for x in matching_cves("11.0.26")} == {"CVE-2026-101296", "CVE-2026-101356", "CVE-2026-103119"}
    assert {x["cve"] for x in matching_cves("10.1.60")} == {"CVE-2026-101296", "CVE-2026-101356"}
    assert {x["cve"] for x in matching_cves("9.0.122")} == {"CVE-2026-101296", "CVE-2026-101356"}
    assert matching_cves("11.0.27") == [] and matching_cves("10.1.61") == [] and matching_cves("9.0.123") == []
    assert "CVE-2026-103119" not in {x["cve"] for x in matching_cves("10.1.60")}
    assert "CVE-2026-103119" not in {x["cve"] for x in matching_cves("9.0.122")}
    assert "CVE-2026-103119" not in {x["cve"] for x in matching_cves("11.0.0-M24")}
    assert "CVE-2026-103119" in {x["cve"] for x in matching_cves("11.0.0-M25")}
    assert version_key("9.0.0.M1") < version_key("9.0.0")

    xml = """<Server><Service>
      <Connector port="8009" protocol="AJP/1.3" address="127.0.0.1" secretRequired="true" secret="x"/>
      <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol">
        <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol"/>
      </Connector>
      <Engine><Realm className="org.apache.catalina.realm.JNDIRealm" authentication="DIGEST-MD5"/></Engine>
    </Service></Server>"""
    import tempfile
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".xml") as handle:
        handle.write(xml); handle.flush(); hints = parse_server_xml(handle.name)
    assert len(hints["ajp_connectors"]) == 1
    assert len(hints["http2_connectors"]) == 1
    assert len(hints["jndi_realms"]) == 1
    assert hints["ajp_connectors"][0]["secret_configured"] is True

    print("自己テスト成功：Tomcat 9/10/11 の境界・CVE判定と設定抽出を確認しました。")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Tomcat 2026年10月の重要CVEを読み取り専用で棚卸し")
    parser.add_argument("--base", action="append", default=[], help="CATALINA_BASE（複数指定可）")
    parser.add_argument("--home", action="append", default=[], help="CATALINA_HOME（複数指定可）")
    parser.add_argument("--json-out", help="結果JSONの保存先。省略時は標準出力")
    parser.add_argument("--self-test", action="store_true", help="自己テストを実行")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.base:
        parser.error("--base で CATALINA_BASE を1つ以上指定してください")
    if args.home and len(args.home) not in (1, len(args.base)):
        parser.error("--home は1つ、または --base と同じ個数を指定してください")
    homes = args.home or [None] * len(args.base)
    if len(homes) == 1 and len(args.base) > 1:
        homes = homes * len(args.base)
    targets = [inspect(base, home) for base, home in zip(args.base, homes)]
    report = {"generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "script": "tomcat_oct2026_impact_check.py",
        "scope": [r["cve"] for r in RULES], "fixed_versions": FIXED, "targets": targets}
    output = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                f.write(output + "\n")
        except OSError as exc:
            print("JSONを書き出せません: %s" % exc, file=sys.stderr)
            return 2
        print("結果を保存しました: " + args.json_out)
    else:
        print(output)
    if any(t["error"] for t in targets):
        return 2
    if any(f.get("status") in ("要対応候補", "要確認") for t in targets for f in t["findings"]):
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
