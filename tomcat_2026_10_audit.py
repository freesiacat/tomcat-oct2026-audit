#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Tomcat 2026年10月公表分の影響調査（ローカル・読み取り専用）。

2026-10-12 に修正され、2026-10-20 に公開された Tomcat 9.0.123 / 10.1.61 /
11.0.27 の全 CVE を対象に、次の2点を突き合わせて影響有無を判定します。

  1) CATALINA_HOME の RELEASE-NOTES または lib/catalina.jar の MANIFEST から
     判定した Tomcat のバージョンが、CVE ごとの影響範囲に入っているか
  2) CATALINA_BASE の conf/server.xml に、その CVE が成立する構成
     （AJPコネクタ / HTTP/2 / JNDIRealm の SASL / FIPS / Unix Domain Socket）
     が書かれているか

行わないこと: ファイルの変更、Tomcat の起動・再起動、シェルコマンドの実行、
外部ネットワークへの通信。読み取り権限だけで動作するため、本番機でも実行できます。

使い方:
  python3 tomcat_2026_10_audit.py --base /opt/tomcat
  python3 tomcat_2026_10_audit.py --base /opt/tomcat/base --home /opt/tomcat/home
  python3 tomcat_2026_10_audit.py --base /opt/tomcat --json-out /tmp/tomcat_audit.json
  python3 tomcat_2026_10_audit.py --self-test

終了コード:
  0 : 影響範囲外、または影響し得る構成を検出しなかった
  1 : 影響範囲内、または影響し得る構成を検出した（要更新・要確認）
  2 : 引数エラー、または読み取れず判定できなかった

注意: ディストリビューションが upstream の版番号を維持したまま修正を
バックポートしている場合があります。OSベンダーのアドバイザリも必ず確認してください。
"""

import argparse
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# 2026-10-12 に修正された各系列の版
FIXED = {"9.0": "9.0.123", "10.1": "10.1.61", "11.0": "11.0.27"}

# 影響範囲は tomcat.apache.org/security-9.html / -10.html / -11.html の
# "Affects:" 表記に一致させている（公開日 2026-10-20）。
CVE_TABLE = [
    {
        "cve": "CVE-2026-101296",
        "severity": "Important",
        "title": "JNDIRealm を非GSSAPIのSASL機構で構成している場合に、"
                 "誤ったパスワードでも認証が成立する",
        "feature": "jndi_sasl",
        "ranges": [("9.0.0.M1", "9.0.122"), ("10.1.0-M1", "10.1.60"),
                   ("11.0.0-M1", "11.0.26")],
        "fixed_by": {"9.0": "9.0.123", "10.1": "10.1.61", "11.0": "11.0.27"},
    },
    {
        "cve": "CVE-2026-101356",
        "severity": "Important",
        "title": "非同期サーブレットのHTTP/2処理におけるオブジェクト再利用の不備で、"
                 "利用者間でリクエスト・レスポンスが混線する",
        "feature": "http2",
        "ranges": [("9.0.118", "9.0.122"), ("10.1.55", "10.1.60"),
                   ("11.0.22", "11.0.26")],
        "fixed_by": {"9.0": "9.0.123", "10.1": "10.1.61", "11.0": "11.0.27"},
    },
    {
        "cve": "CVE-2026-103119",
        "severity": "Important",
        "title": "AJPで大きな非ブロッキング書き込みを行うと、応答本文が次のリクエストへ"
                 "分割され、1つ目の応答の内容が2つ目に漏れ得る",
        "feature": "ajp",
        "ranges": [("11.0.0-M25", "11.0.26")],
        "fixed_by": {"11.0": "11.0.27"},
    },
    {
        "cve": "CVE-2026-93446",
        "severity": "Low",
        "title": "後始末の不備により、TLS 1.3の接続が断続的に失敗する",
        "feature": "always",
        "ranges": [("9.0.90", "9.0.122"), ("10.1.25", "10.1.60"),
                   ("11.0.0-M21", "11.0.26")],
        "fixed_by": {"9.0": "9.0.123", "10.1": "10.1.61", "11.0": "11.0.27"},
    },
    {
        "cve": "CVE-2026-88041",
        "severity": "Low",
        "title": "HTTP/2のトレーラ情報が、後続のリクエストへ混入する",
        "feature": "http2",
        "ranges": [("9.0.92", "9.0.122"), ("10.1.27", "10.1.60"),
                   ("11.0.0-M23", "11.0.26")],
        "fixed_by": {"9.0": "9.0.123", "10.1": "10.1.61", "11.0": "11.0.27"},
    },
    {
        "cve": "CVE-2026-74049",
        "severity": "Low",
        "title": "JSTLのc:redirectの置き換え実装がページ処理を即座に終了せず、"
                 "リダイレクト後も残りのページが処理される",
        "feature": "jsp",
        "ranges": [("9.0.0.M1", "9.0.122"), ("10.1.0-M1", "10.1.60"),
                   ("11.0.0-M1", "11.0.26")],
        "fixed_by": {"9.0": "9.0.123", "10.1": "10.1.61", "11.0": "11.0.27"},
    },
    {
        "cve": "CVE-2026-74048",
        "severity": "Low",
        "title": "OpenSSLLifecycleListenerでFIPSモードを指定しても、FIPS有効化に"
                 "失敗すると非FIPSモードのまま起動を継続する",
        "feature": "fips",
        "ranges": [("9.0.92", "9.0.122"), ("10.1.22", "10.1.60"),
                   ("11.0.0-M14", "11.0.26")],
        "fixed_by": {"9.0": "9.0.123", "10.1": "10.1.61", "11.0": "11.0.27"},
    },
    {
        "cve": "CVE-2026-80353",
        "severity": "Low",
        "title": "APRコネクタのUnix Domain Socket作成時の競合状態により、"
                 "権限のないローカル利用者がソケットへアクセスできる",
        "feature": "apr_uds",
        "ranges": [("9.0.47", "9.0.122")],
        "fixed_by": {"9.0": "9.0.123"},
    },
]

SEVERITY_ORDER = {"Important": 0, "Moderate": 1, "Low": 2}

CONDITION_LABEL = {
    "ajp": "AJPコネクタが有効",
    "http2": "HTTP/2コネクタが有効",
    "jndi_sasl": "JNDIRealmが非GSSAPIのSASL機構で構成",
    "fips": "OpenSSLのFIPSモードを有効化",
    "apr_uds": "APRコネクタでUnix Domain Socketを使用",
    "jsp": "JSP / JSTLを配備（server.xmlだけでは判定できない）",
    "always": "構成を問わず該当し得る",
}


def version_key(value):
    """'11.0.0-M25' や '9.0.0.M1' を比較できるタプルへ変換する。

    マイルストーン版は、同じ番号の正式版より前として扱う。
    """
    if not value:
        return None
    match = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)(?:[.-]M(\d+))?", str(value))
    if not match:
        return None
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    if match.group(4) is None:
        return (major, minor, patch, 1, 0)
    return (major, minor, patch, 0, int(match.group(4)))


def detect_version(home):
    """RELEASE-NOTES を優先し、無ければ lib/catalina.jar の MANIFEST を読む。"""
    notes = os.path.join(home, "RELEASE-NOTES")
    if os.path.isfile(notes):
        try:
            with open(notes, "r", encoding="utf-8", errors="replace") as handle:
                head = handle.read(16384)
            match = re.search(r"Apache Tomcat Version\s+(\d+\.\d+\.\d+(?:[.-]M\d+)?)", head)
            if match:
                return match.group(1), "RELEASE-NOTES"
        except OSError:
            pass

    jar = os.path.join(home, "lib", "catalina.jar")
    if os.path.isfile(jar):
        try:
            with zipfile.ZipFile(jar) as archive:
                manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
            match = re.search(r"^Implementation-Version:\s*(\d+\.\d+\.\d+(?:[.-]M\d+)?)",
                              manifest, re.MULTILINE)
            if match:
                return match.group(1), "lib/catalina.jar (MANIFEST)"
        except (OSError, KeyError, zipfile.BadZipFile):
            pass
    return None, None


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def classify_jndi_auth(authentication):
    """JNDIRealm の authentication 属性から、SASL の利用状況を分類する。

    Tomcat の JNDIRealm は authentication に none / simple / strong /
    プロバイダ固有の機構名（GSSAPI、DIGEST-MD5 など）を指定できる。
    このCVEは「GSSAPI 以外の SASL 機構を使っている」構成で成立するため、
    none・simple は対象外、strong は機構がプロバイダ依存のため要確認とする。
    """
    value = (authentication or "").strip().lower()
    if not value or value in ("none", "simple"):
        return {"sasl_in_use": False, "non_gssapi_sasl": False, "needs_review": False}
    if value == "gssapi":
        return {"sasl_in_use": True, "non_gssapi_sasl": False, "needs_review": False}
    if value == "strong":
        return {"sasl_in_use": True, "non_gssapi_sasl": False, "needs_review": True}
    return {"sasl_in_use": True, "non_gssapi_sasl": True, "needs_review": False}


def read_server_config(path):
    """conf/server.xml から、影響判定に必要な要素だけを読み取る。"""
    root = ET.parse(path).getroot()
    config = {
        "ajp_connectors": [],
        "http2_connectors": [],
        "jndi_realms": [],
        "apr_listener": False,
        "uds_connectors": [],
        "fips_listener": False,
        "ssl_implementation": [],
    }

    for node in root.iter():
        tag = local_name(node.tag)

        if tag == "Listener":
            class_name = node.get("className") or ""
            if "AprLifecycleListener" in class_name:
                config["apr_listener"] = True
            if "OpenSSLLifecycleListener" in class_name:
                fips_mode = (node.get("FIPSMode") or "").strip().lower()
                if fips_mode in ("on", "require", "true"):
                    config["fips_listener"] = True
            continue

        if tag != "Connector":
            continue

        protocol = (node.get("protocol") or "").strip()
        port = (node.get("port") or "").strip()
        address = (node.get("address") or "").strip()

        ssl_impl = (node.get("sslImplementationName") or "").strip()
        if ssl_impl:
            config["ssl_implementation"].append(ssl_impl)

        socket_path = (node.get("socketPath") or "").strip()
        if socket_path:
            config["uds_connectors"].append({
                "port": port or "(未指定)",
                "protocol": protocol or "(未指定)",
                "socketPath": socket_path,
            })

        if protocol.upper().startswith("AJP") or port == "8009":
            config["ajp_connectors"].append({
                "port": port or "(未指定)",
                "protocol": protocol or "(未指定)",
                "address": address or "(未指定: 全インタフェース)",
                "bound_to_all_interfaces": address in ("", "0.0.0.0", "::"),
                "secretRequired": (node.get("secretRequired") or "(未指定)").strip(),
                "secret_configured": bool((node.get("secret") or "").strip()),
            })

        upgrade_classes = [child.get("className") or "" for child in list(node)
                           if local_name(child.tag) == "UpgradeProtocol"]
        if any("Http2Protocol" in name for name in upgrade_classes) or \
                protocol.lower().split("/")[0] in ("h2", "h2c"):
            config["http2_connectors"].append({
                "port": port or "(未指定)",
                "protocol": protocol or "(未指定)",
            })

    for node in root.iter():
        if local_name(node.tag) != "Realm":
            continue
        class_name = node.get("className") or ""
        if "JNDIRealm" not in class_name:
            continue
        authentication = (node.get("authentication") or "").strip()
        classification = classify_jndi_auth(authentication)
        config["jndi_realms"].append({
            "className": class_name,
            "authentication": authentication or "(未指定: プロバイダ既定)",
            "sasl_in_use": classification["sasl_in_use"],
            "non_gssapi_sasl": classification["non_gssapi_sasl"],
            "needs_review": classification["needs_review"],
        })

    return config


def affected_cves(version):
    """バージョンが影響範囲に入るCVEを、深刻度順に返す。"""
    parsed = version_key(version)
    if parsed is None:
        return []
    hits = []
    for entry in CVE_TABLE:
        for low, high in entry["ranges"]:
            low_key, high_key = version_key(low), version_key(high)
            if low_key is None or high_key is None:
                continue
            if low_key[:2] == parsed[:2] and low_key <= parsed <= high_key:
                hits.append({
                    "cve": entry["cve"],
                    "severity": entry["severity"],
                    "title": entry["title"],
                    "feature": entry["feature"],
                    "affects": "%s 〜 %s" % (low, high),
                })
                break
    hits.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["cve"]))
    return hits


def condition_met(feature, config):
    """CVEが成立する前提（設定・機能）が有効かを返す。"""
    if feature == "ajp":
        return bool(config["ajp_connectors"])
    if feature == "http2":
        return bool(config["http2_connectors"])
    if feature == "jndi_sasl":
        return any(realm["non_gssapi_sasl"] or realm["needs_review"]
                   for realm in config["jndi_realms"])
    if feature == "fips":
        return bool(config["fips_listener"])
    if feature == "apr_uds":
        return bool(config["uds_connectors"])
    return True  # jsp / always は server.xml だけでは絞り込めないため確認対象に残す


def inspect(base, home=None):
    """1つのCATALINA_BASEを調べ、判定結果を返す。"""
    base = os.path.abspath(base)
    home = os.path.abspath(home or base)
    server_xml = os.path.join(base, "conf", "server.xml")
    record = {
        "catalina_base": base,
        "catalina_home": home,
        "version": None,
        "version_source": None,
        "fixed_version": None,
        "config_file": server_xml,
        "configuration": None,
        "findings": [],
        "needs_action": False,
        "error": None,
    }

    version, source = detect_version(home)
    record["version"], record["version_source"] = version, source
    if not version:
        record["error"] = ("バージョンを判定できませんでした。"
                           "RELEASE-NOTES または lib/catalina.jar を確認してください。")
        return record

    record["fixed_version"] = FIXED.get(".".join(version.split(".")[:2]))

    if not os.path.isfile(server_xml):
        record["error"] = "conf/server.xml が見つかりません。CATALINA_BASE を確認してください。"
        return record
    try:
        config = read_server_config(server_xml)
    except (OSError, ET.ParseError) as exc:
        record["error"] = "server.xml を読み取れませんでした: %s" % exc
        return record
    record["configuration"] = config

    for hit in affected_cves(version):
        met = condition_met(hit["feature"], config)
        feature = hit["feature"]
        finding = dict(hit)
        finding.pop("feature", None)
        finding["condition_label"] = CONDITION_LABEL[feature]
        finding["condition_met"] = met
        finding["status"] = "影響条件あり" if met else "バージョン該当・構成条件なし"
        if feature == "ajp":
            finding["evidence"] = config["ajp_connectors"]
        elif feature == "http2":
            finding["evidence"] = config["http2_connectors"]
        elif feature == "jndi_sasl":
            finding["evidence"] = config["jndi_realms"]
        elif feature == "apr_uds":
            finding["evidence"] = config["uds_connectors"]
        elif feature == "fips":
            finding["evidence"] = {"fips_listener": config["fips_listener"],
                                   "ssl_implementation": config["ssl_implementation"]}
        else:
            finding["evidence"] = None
        record["findings"].append(finding)
        if met:
            record["needs_action"] = True

    if not record["findings"]:
        record["findings"].append({
            "cve": None,
            "severity": None,
            "status": "影響範囲外",
            "detail": "2026年10月12日修正分のいずれの影響範囲にも該当しません。",
        })
    return record


def self_test():
    """判定ロジックの自己テスト。"""
    def hits(version):
        return {hit["cve"] for hit in affected_cves(version)}

    # 表そのものから境界を検算する（表を直せばテストも追随する）
    for entry in CVE_TABLE:
        cve = entry["cve"]
        for low, high in entry["ranges"]:
            assert cve in hits(high), (cve, high, "影響範囲の上限は該当するはず")
            for branch, fixed in entry["fixed_by"].items():
                if branch == ".".join(high.split(".")[:2]):
                    assert cve not in hits(fixed), (cve, fixed, "修正版は影響範囲外のはず")
            low_key = version_key(low)
            below = "%d.%d.%d" % (low_key[0], low_key[1], max(low_key[2] - 1, 0))
            if low_key[2] > 0:
                assert cve not in hits(below), (cve, below, "下限の1つ前は該当しないはず")

    # 修正版では該当なし
    assert hits("11.0.27") == set()
    assert hits("10.1.61") == set()
    assert hits("9.0.123") == set()

    # 主要3件は最新の影響版すべてで揃う
    assert {"CVE-2026-101296", "CVE-2026-101356", "CVE-2026-103119"} <= hits("11.0.26")
    assert {"CVE-2026-101296", "CVE-2026-101356"} <= hits("10.1.60")
    assert {"CVE-2026-101296", "CVE-2026-101356"} <= hits("9.0.122")

    # AJP 応答混線は 11 系の 11.0.0-M25 以降のみ
    assert "CVE-2026-103119" in hits("11.0.0-M25")
    assert "CVE-2026-103119" not in hits("11.0.0-M24")
    assert "CVE-2026-103119" not in hits("10.1.60")
    assert "CVE-2026-103119" not in hits("9.0.122")

    # APR コネクタの Unix Domain Socket は 9 系のみ
    assert "CVE-2026-80353" in hits("9.0.122")
    assert "CVE-2026-80353" not in hits("9.0.46")
    assert "CVE-2026-80353" not in hits("10.1.60")

    # マイルストーン版の順序
    assert version_key("9.0.0.M1") < version_key("9.0.0")
    assert version_key("11.0.0-M24") < version_key("11.0.0-M25")
    assert version_key("11.0.0-M25") < version_key("11.0.26")
    assert version_key("11.0.26") < version_key("11.0.27")
    assert version_key("not-a-version") is None

    # JNDIRealm の authentication 分類
    assert classify_jndi_auth("simple")["sasl_in_use"] is False
    assert classify_jndi_auth("none")["sasl_in_use"] is False
    assert classify_jndi_auth("")["sasl_in_use"] is False
    assert classify_jndi_auth("GSSAPI")["non_gssapi_sasl"] is False
    assert classify_jndi_auth("GSSAPI")["needs_review"] is False
    assert classify_jndi_auth("strong")["needs_review"] is True
    assert classify_jndi_auth("DIGEST-MD5")["non_gssapi_sasl"] is True

    sample = """<?xml version="1.0" encoding="UTF-8"?>
<Server port="8005">
  <Listener className="org.apache.catalina.core.AprLifecycleListener"/>
  <Listener className="org.apache.catalina.core.OpenSSLLifecycleListener" FIPSMode="on"/>
  <Service name="Catalina">
    <Connector port="8009" protocol="AJP/1.3" address="0.0.0.0" secretRequired="false"/>
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol">
      <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol"/>
    </Connector>
    <Connector port="8080" protocol="org.apache.coyote.http11.Http11AprProtocol"
               socketPath="/run/tomcat.sock"/>
    <Engine name="Catalina" defaultHost="localhost">
      <Realm className="org.apache.catalina.realm.JNDIRealm" authentication="DIGEST-MD5"/>
    </Engine>
  </Service>
</Server>
"""
    import tempfile
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".xml") as handle:
        handle.write(sample)
        handle.flush()
        config = read_server_config(handle.name)

    assert len(config["ajp_connectors"]) == 1
    assert config["ajp_connectors"][0]["bound_to_all_interfaces"] is True
    assert config["ajp_connectors"][0]["secretRequired"] == "false"
    assert config["ajp_connectors"][0]["secret_configured"] is False
    assert len(config["http2_connectors"]) == 1
    assert len(config["jndi_realms"]) == 1
    assert config["jndi_realms"][0]["non_gssapi_sasl"] is True
    assert config["apr_listener"] is True
    assert config["fips_listener"] is True
    assert len(config["uds_connectors"]) == 1

    for feature in ("ajp", "http2", "jndi_sasl", "fips", "apr_uds"):
        assert condition_met(feature, config) is True, feature

    clean = """<Server><Service>
      <Connector port="8080" protocol="HTTP/1.1"/>
    </Service></Server>"""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".xml") as handle:
        handle.write(clean)
        handle.flush()
        clean_config = read_server_config(handle.name)
    for feature in ("ajp", "http2", "jndi_sasl", "fips", "apr_uds"):
        assert condition_met(feature, clean_config) is False, feature
    assert condition_met("always", clean_config) is True

    print("自己テスト成功: 版の境界判定、JNDIRealmの分類、XML解析、構成条件の判定を検証しました。")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Apache Tomcat 2026年10月公表分の影響をローカルで棚卸しします（読み取り専用）。")
    parser.add_argument("--base", action="append", default=[],
                        help="CATALINA_BASE。複数インスタンスを調べる場合は繰り返し指定します。")
    parser.add_argument("--home", action="append", default=[],
                        help="対応するCATALINA_HOME。省略時は--baseと同じ場所を参照します。")
    parser.add_argument("--json-out", default=None,
                        help="結果JSONの書き出し先。省略時は標準出力へ出します。")
    parser.add_argument("--self-test", action="store_true",
                        help="判定ロジックの自己テストを実行します。")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.base:
        parser.error("--base で CATALINA_BASE を1つ以上指定してください。")
    if args.home and len(args.home) not in (1, len(args.base)):
        parser.error("--home は1つ、または --base と同じ個数を指定してください。")

    homes = list(args.home) if args.home else [None] * len(args.base)
    if len(homes) == 1 and len(args.base) > 1:
        homes = homes * len(args.base)

    targets = [inspect(base, home) for base, home in zip(args.base, homes)]
    report = {
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "script": "tomcat_2026_10_audit.py",
        "scope": [entry["cve"] for entry in CVE_TABLE],
        "fixed_versions": FIXED,
        "targets": targets,
    }

    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except OSError as exc:
            print("JSONを書き出せませんでした: %s" % exc, file=sys.stderr)
            return 2
        print("結果を書き出しました: %s" % args.json_out)
    else:
        print(text)

    if any(target["error"] for target in targets):
        return 2
    if any(target["needs_action"] for target in targets):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
