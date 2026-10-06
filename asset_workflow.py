#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
资产收集分级自动化工作流 v1.0
配套文档：资产收集分级工作流.md
合规红线：主动探测仅限已书面授权范围内的目标；本工具全程留痕（audit.log）

用法：
    交互式向导：  python asset_workflow.py
    命令行模式：  python asset_workflow.py --domain example.com --level general --authorized
    仅被动收集：  加 --passive-only
    高敏感特批：  加 --approve-active（模拟"单独审批"留痕）
"""

import argparse
import base64
import csv
import json
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

OUTDIR = Path(__file__).resolve().parent
AUDIT_LOG = OUTDIR / "audit.log"

# ---------------- 分级管控矩阵（对应文档第 2 节） ----------------
# resolve: DNS 解析验证；http: Web 存活探测；rate: 请求间隔秒数
MATRIX = {
    "high":    {"label": "高敏感",   "resolve": "approve", "http": "approve", "rate": 2.0},
    "special": {"label": "特殊敏感", "resolve": "yes",     "http": "yes",     "rate": 1.0},
    "general": {"label": "一般对象", "resolve": "yes",     "http": "yes",     "rate": 0.2},
    "custom":  {"label": "自定义",   "resolve": "yes",     "http": "yes",     "rate": 2.0},
}
LEVEL_ORDER = {"high": 3, "special": 2, "general": 1, "custom": 0}

UA = "asset-workflow/1.0 (authorized security assessment)"

# 中国常见二级后缀，用于从 FQDN 归并主域名（www.example.edu.cn -> example.edu.cn）
CN_SECOND_LEVEL = ("edu.cn", "com.cn", "gov.cn", "org.cn", "net.cn", "ac.cn",
                   "mil.cn", "com.hk", "edu.hk", "gov.hk", "org.hk")


def root_domain(domain):
    """从输入提取主域名；输入 www 子域名也能正确归并"""
    d = domain.strip().lower()
    parts = [p for p in d.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in CN_SECOND_LEVEL:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return d


def audit(action, detail=""):
    """全程留痕：JSON 行写入 audit.log"""
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "action": action, "detail": detail}
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


_log_local = threading.local()


def log(msg):
    fn = getattr(_log_local, "fn", None)
    if fn:
        fn(str(msg))            # Web 任务线程：写入自己的 job 日志
    else:
        print(msg, flush=True)  # CLI / 其他线程：照常打印


# ---------------- P0 立项与授权 ----------------
def check_authorization(auto=False, domain=""):
    checklist = [
        "书面授权在手（授权书/合同/SRC 范围公告）",
        "测试范围已书面确认",
        "禁止项清单已知悉（禁测系统、禁测时段）",
        "应急联系人双向可达",
        "数据保留与销毁要求已明确",
    ]
    if auto:
        audit("P0_authorization", f"CLI --authorized 确认，domain={domain}")
        log("[P0] 已通过 --authorized 声明授权，留痕完成")
        return True
    log("\n=== P0 立项与授权（逐项确认，任一不满足即中止） ===")
    for item in checklist:
        ans = input(f"  [ ] {item} —— 已满足？(y/n): ").strip().lower()
        if ans != "y":
            log("授权检查未通过，流程中止。")
            audit("P0_failed", item)
            return False
    audit("P0_authorization", "交互式逐项确认通过")
    return True


# ---------------- P1 对象定级 ----------------
def questionnaire():
    """自定义对象风险问卷（文档 1.3 节），返回总分"""
    questions = [
        ("行业监管强度", ["无特殊监管", "一般行业规范", "强监管（金融/医疗/政务）"]),
        ("数据敏感度", ["公开数据为主", "含普通个人信息", "敏感个人信息/未成年人/金融数据"]),
        ("等保定级", ["未定级或一级", "二级", "三级及以上"]),
        ("业务中断容忍度", ["可接受短暂中断", "低峰期可操作", "7x24 不可中断"]),
        ("资产边界清晰度", ["边界清晰", "部分模糊", "大量影子资产/归属不明"]),
        ("授权完备性", ["书面授权齐全", "授权待补", "无正式授权"]),
    ]
    total = 0
    log("\n--- 自定义对象风险问卷（每项 0-2 分） ---")
    for i, (q, opts) in enumerate(questions, 1):
        log(f"  Q{i} {q}:")
        for s, o in enumerate(opts):
            log(f"      {s} = {o}")
        while True:
            v = input("    评分(0/1/2): ").strip()
            if v in ("0", "1", "2"):
                total += int(v)
                break
    return total


def classify_interactive():
    log("\n=== P1 对象定级（决策树，命中即停） ===")
    q1 = input("  目标属于 政府军工/金融/运营商/能源/医疗/关基？(y/n): ").strip().lower()
    if q1 == "y":
        return "high"
    q2 = input("  目标属于 教育/大型互联网/国企集团？(y/n): ").strip().lower()
    if q2 == "y":
        return "special"
    q3 = input("  目标属于 中小企业/个人站点？(y/n): ").strip().lower()
    if q3 == "y":
        return "general"
    score = questionnaire()
    audit("P1_questionnaire", f"score={score}")
    if score >= 8:
        mapped = "high"
    elif score >= 4:
        mapped = "special"
    else:
        mapped = "general"
    log(f"  问卷总分 {score}，映射等级：{MATRIX[mapped]['label']}")
    return mapped


# ---------------- P2 被动收集：crt.sh 证书透明度 + HackerTarget 被动DNS ----------------
def _passive_crtsh(root):
    subs = set()
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + root) + "&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        for item in data:
            for name in item.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(root):
                    subs.add(name)
        return subs, None
    except Exception as e:
        return subs, str(e)


def _passive_hackertarget(root):
    subs = set()
    url = "https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(root)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8", "ignore")
        for line in text.splitlines():
            host = line.split(",")[0].strip().lower()
            if host.endswith(root):
                subs.add(host)
        return subs, None
    except Exception as e:
        return subs, str(e)


def _passive_hunter(root, key):
    """Hunter 鹰图测绘平台查询（消耗账号积分，免费账号每日 500 条额度）"""
    subs = set()
    q = 'domain="' + root + '"'
    b64 = base64.urlsafe_b64encode(q.encode("utf-8")).decode("ascii")
    url = ("https://hunter.qianxin.com/openApi/search?api-key=" + key +
           "&search=" + b64 + "&page=1&page_size=100&is_web=3&port_filter=false")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        if data.get("code") != 200:
            return subs, "API 返回异常: " + str(data.get("message") or data.get("code"))
        for item in (data.get("data") or {}).get("arr") or []:
            for field in ("domain", "url"):
                v = (item.get(field) or "").strip().lower()
                if not v:
                    continue
                host = urllib.parse.urlparse(v if "://" in v else "//" + v).hostname or v
                if host and host.endswith(root):
                    subs.add(host)
        return subs, None
    except Exception as e:
        return subs, str(e)


def _passive_fofa(root, email, key):
    """FOFA 测绘平台查询（免费账号可用 API，额度有限）"""
    subs = set()
    q = 'domain="' + root + '"'
    b64 = base64.b64encode(q.encode("utf-8")).decode("ascii")
    url = ("https://fofa.info/api/v1/search/all?email=" + urllib.parse.quote(email) +
           "&key=" + key + "&qbase64=" + urllib.parse.quote(b64) +
           "&size=500&fields=host,domain")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        if data.get("error"):
            return subs, "API 返回异常: " + str(data.get("errmsg"))
        for row in data.get("results") or []:
            for v in row:
                v = (v or "").strip().lower()
                if not v:
                    continue
                host = urllib.parse.urlparse(v if "://" in v else "//" + v).hostname or v
                if host and host.endswith(root):
                    subs.add(host)
        return subs, None
    except Exception as e:
        return subs, str(e)


def parse_import_csv(text, root):
    """解析测绘平台（Hunter/FOFA）网页导出的 CSV 文本，格式无关：
    直接全文匹配以主域名结尾的主机名，兼容任意列结构"""
    subs = set()
    pattern = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+" + re.escape(root) + r")\b")
    for m in pattern.finditer(text.lower()):
        subs.add(m.group(1))
    return subs


def passive_collect(domain, hunter_key="", fofa_email="", fofa_key=""):
    root = root_domain(domain)
    if root != domain:
        log(f"\n[P2] 输入 {domain} 已归并到主域名 {root}")
    log(f"\n=== P2 被动收集（零接触目标） 主域名: {root} ===")
    subs = {root, domain.strip().lower()}

    found, err = _passive_crtsh(root)
    if err:
        log(f"  [警告] crt.sh 查询失败: {err}（检查网络后重试）")
    else:
        log(f"  crt.sh 证书透明度: {len(found)} 个")
    subs |= found

    found2, err2 = _passive_hackertarget(root)
    if err2:
        log(f"  [警告] HackerTarget 被动DNS查询失败: {err2}")
    else:
        log(f"  HackerTarget 被动DNS: {len(found2)} 个")
    subs |= found2

    if hunter_key:
        found3, err3 = _passive_hunter(root, hunter_key)
        if err3:
            log(f"  [警告] Hunter 测绘查询失败: {err3}")
        else:
            log(f"  Hunter 鹰图测绘: {len(found3)} 个（消耗账号积分）")
        subs |= found3
    else:
        log("  Hunter 测绘: 未启用（界面勾选并填 Key 后使用）")

    if fofa_email and fofa_key:
        found4, err4 = _passive_fofa(root, fofa_email, fofa_key)
        if err4:
            log(f"  [警告] FOFA 测绘查询失败: {err4}")
        else:
            log(f"  FOFA 测绘: {len(found4)} 个（消耗账号额度）")
        subs |= found4
    else:
        log("  FOFA 测绘: 未启用（界面勾选并填邮箱+Key 后使用）")

    log(f"  合计唯一（子）域名: {len(subs)} 个")
    audit("P2_passive", f"input={domain}, root={root}, subdomains={len(subs)}")
    return sorted(subs)


# ---------------- P3 主动探测（分级管控） ----------------
def resolve_host(name):
    try:
        socket.setdefaulttimeout(5)
        return socket.gethostbyname(name)
    except Exception:
        return ""


def _decode_body(body, headers):
    """按响应头/meta 声明的编码解码，兼容 GBK 中文站点（如高校官网）"""
    enc = None
    m = re.search(r"charset=([\w-]+)", headers.get("Content-Type", ""), re.I)
    if m:
        enc = m.group(1)
    if not enc:
        m = re.search(r"charset=[\"']?([\w-]+)", body[:2048].decode("ascii", "ignore"), re.I)
        if m:
            enc = m.group(1)
    for e in ([enc] if enc else []) + ["utf-8", "gb18030"]:
        try:
            return body.decode(e)
        except Exception:
            continue
    return body.decode("utf-8", "ignore")


def http_probe(host, rate, breaker=None):
    """HTTPS 优先，记录状态码 / Server 头 / 页面标题；传入 breaker 时喂熔断信号"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme, port in (("https", 443), ("http", 80)):
        url = f"{scheme}://{host}/"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                body = _decode_body(r.read(16384), r.headers)
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""
                time.sleep(rate)
                if breaker:
                    breaker.ok()
                return {"ip": resolve_host(host), "port": port, "status": r.status,
                        "server": r.headers.get("Server", ""), "title": title,
                        "powered_by": r.headers.get("X-Powered-By", "")}
        except urllib.error.HTTPError as e:
            if breaker:
                if e.code in (403, 429):
                    breaker.fail(str(e.code))
                else:
                    breaker.ok()  # 服务器有响应（404/500 等），连接层面正常
            continue
        except Exception as e:
            if breaker:
                breaker.fail(_classify_net_error(e))
            continue
    return None


def active_probe(subs, level, approve_active):
    rule = MATRIX[level]
    if rule["http"] == "approve" and not approve_active:
        log(f"\n[P3] {rule['label']}对象的主动探测需单独审批：未加 --approve-active，跳过。")
        log("     仅使用被动数据 + DNS 解析（已获批情况下）。")
        audit("P3_skipped", "active probing not approved")
        do_http = False
    else:
        if rule["http"] == "approve":
            audit("P3_approved", "active probing approved via --approve-active")
            log("\n[P3] 已记录主动探测特批（--approve-active）")
        do_http = True
    do_resolve = rule["resolve"] == "yes" or (rule["resolve"] == "approve" and approve_active)

    log(f"\n=== P3 主动探测 速率间隔 {rule['rate']}s/请求 ===")
    results = []
    for i, name in enumerate(subs, 1):
        ip = resolve_host(name) if do_resolve else ""
        row = {"name": name, "ip": ip, "port": "", "status": "", "server": "", "title": "",
               "source": "被动(crt.sh)"}
        if do_http and ip:
            probe = http_probe(name, rule["rate"])
            if probe:
                row.update({"ip": probe["ip"], "port": probe["port"], "status": probe["status"],
                            "server": probe["server"], "title": probe["title"]})
                row["source"] += "+主动探测"
        results.append(row)
        log(f"  [{i}/{len(subs)}] {name}  {ip or '-'}  {row['status'] or ''}")
    audit("P3_active", f"probed={len(results)}, http={'on' if do_http else 'off'}")
    return results


def title_probe(subs, level, approve_active=False):
    """标题补全：轻量主动探测，每站仅访问首页一次，速率按等级限制。
    属于主动探测，高敏感对象仍需 --approve-active 特批。"""
    rule = MATRIX[level]
    if rule["http"] == "approve" and not approve_active:
        log(f"\n[标题补全] {rule['label']}对象的主动探测需单独审批：未加 --approve-active，跳过。")
        audit("P3_title_skipped", "title probing not approved")
        return [{"name": s, "ip": "", "port": "", "status": "", "server": "", "title": "",
                 "source": "被动(crt.sh)"} for s in subs]
    if rule["http"] == "approve":
        audit("P3_title_approved", "title probing approved via --approve-active")
        log("\n[标题补全] 已记录轻量探测特批（--approve-active）")
    log(f"\n=== 标题补全（每站仅访问首页一次，间隔 {rule['rate']}s）===")
    results = []
    for i, name in enumerate(subs, 1):
        ip = resolve_host(name)
        row = {"name": name, "ip": ip, "port": "", "status": "", "server": "", "title": "",
               "source": "被动+标题探测"}
        if ip:
            probe = http_probe(name, rule["rate"])
            if probe:
                row.update({"ip": probe["ip"], "port": probe["port"], "status": probe["status"],
                            "server": probe["server"], "title": probe["title"]})
        results.append(row)
        log(f"  [{i}/{len(subs)}] {name}  {row['status'] or '-'}  {row['title'][:40]}")
    audit("P3_title", f"titled={sum(1 for r in results if r['title'])}/{len(results)}")
    return results


# ---------------- 熔断器：连续异常立即停止主动探测（只停不绕） ----------------
class CircuitBreaker:
    """主动探测熔断器。连续超时/被重置（默认 5 次）或连续 403/429（默认 3 次）触发，
    触发后全部主动探测立即停止，已收集结果照常导出。
    设计红线：只停不绕——不做自动重试/降速/换 IP，触发后由人工判断。"""

    def __init__(self, max_fails=5, max_blocks=3, baseline_host=None):
        self.max_fails = max_fails
        self.max_blocks = max_blocks
        self.baseline_host = baseline_host  # 基线主机（一般是主站），用于封禁强确认
        self.fails = 0
        self.blocks = 0
        self.count = 0
        self.tripped = False
        self.reason = ""

    def ok(self):
        self.fails = 0
        self.blocks = 0
        self._tick()

    def fail(self, kind):
        if kind in ("timeout", "reset"):
            self.fails += 1
        elif kind in ("403", "429"):
            self.blocks += 1
        else:
            return  # DNS 失败、连接被拒绝（主机在线但无服务）等正常噪音，不计入
        if self.blocks >= self.max_blocks:
            self.tripped = True
            self.reason = f"连续 {self.blocks} 次收到 HTTP {kind}，疑似被目标 WAF/安全设备拦截"
        elif self.fails >= self.max_fails:
            self.tripped = True
            self.reason = f"连续 {self.fails} 次连接超时/被重置，疑似 IP 被目标安全设备封禁"
        self._tick()

    def _tick(self):
        """每 10 个请求且正处于连续异常中时，回探基线主机；基线失联 = 封禁强确认"""
        self.count += 1
        if (self.baseline_host and not self.tripped and self.count % 10 == 0
                and (self.fails >= 2 or self.blocks >= 2)
                and http_probe(self.baseline_host, 0) is None):
            self.tripped = True
            self.reason = (f"基线主机 {self.baseline_host} 失联且连续探测异常，"
                           "高度疑似本机 IP 已被封禁")


def _classify_net_error(e):
    """把网络异常分类为熔断信号：timeout/reset 计入；refused 证明主机在线，不计入"""
    reason = str(getattr(e, "reason", e)).lower()
    if "timed out" in reason or "timeout" in reason:
        return "timeout"
    if "reset" in reason:
        return "reset"
    return "other"


# ---------------- 自定义探测操作（Web 勾选触发，全部低速，仅授权范围内使用） ----------------
SUB_WORDS = ("www", "mail", "webmail", "oa", "vpn", "portal", "sso", "cas", "api",
             "dev", "test", "cms", "blog", "bbs", "wiki", "lib", "mirror", "git",
             "file", "files", "upload", "download", "static", "img", "media", "video",
             "news", "app", "apps", "m", "wap", "admin", "manage", "console", "monitor",
             "status", "backup", "bak", "old", "data", "db", "ns1", "ns2", "dns",
             "ftp", "smtp", "jw", "jwc", "xg")
PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
         1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9090)
DIR_PATHS = ("/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.svn/entries",
             "/WEB-INF/web.xml", "/readme.txt", "/admin/", "/phpmyadmin/")


def brute_subdomains(root, rate=2.0, breaker=None):
    """子域名爆破：内置小字典做主动 DNS 查询（低速）。
    DNS 查询打的是公共解析器、不接触目标服务器，按设计不喂熔断信号，只响应熔断停止。"""
    found = set()
    log(f"\n[子域名爆破] 内置字典 {len(SUB_WORDS)} 条，间隔 {rate}s/查询")
    for i, w in enumerate(SUB_WORDS, 1):
        if breaker and breaker.tripped:
            log(f"  [熔断] {breaker.reason}，本项探测提前停止")
            break
        host = f"{w}.{root}"
        if resolve_host(host):
            found.add(host)
            log(f"  [{i}/{len(SUB_WORDS)}] {host}  ✓ 命中")
        time.sleep(rate)
    audit("P3_brute", f"root={root}, found={len(found)}")
    log(f"  爆破命中: {len(found)} 个")
    return found


def port_scan(rows, rate=2.0, timeout=1.5, max_hosts=30, breaker=None):
    """存活探测/端口扫描：对主机 TCP connect 常见端口（低速，主机间限速）。
    熔断信号：曾有响应主机后，当前主机 20 端口全部无响应记 1 次异常
    （有开放端口或收到 RST 拒绝 = 主机在线，属正常，不计入）。"""
    log(f"\n[存活探测/端口扫描] 常见端口 {len(PORTS)} 个，主机间隔 {rate}s，最多 {max_hosts} 台")
    scanned = 0
    seen_alive = False
    for row in rows:
        if breaker and breaker.tripped:
            log(f"  [熔断] {breaker.reason}，本项探测提前停止")
            break
        if scanned >= max_hosts:
            log(f"  已达上限 {max_hosts} 台，其余跳过")
            break
        ip = row.get("ip") or resolve_host(row["name"])
        if not ip:
            log(f"  {row['name']} 解析失败，跳过")
            continue
        row["ip"] = ip
        open_ports = []
        refused_seen = False
        for p in PORTS:
            if breaker and breaker.tripped:
                break
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                rc = s.connect_ex((ip, p))
                if rc == 0:
                    open_ports.append(p)
                elif rc in (10061, 111):  # 拒绝 = 收到 RST = 主机在线（Windows/Linux）
                    refused_seen = True
            except Exception:
                pass
            finally:
                s.close()
        if open_ports:
            row["port"] = ",".join(str(p) for p in open_ports)
        if breaker:
            if open_ports or refused_seen:
                seen_alive = True
                breaker.ok()
            elif seen_alive:
                breaker.fail("timeout")
        log(f"  {row['name']} ({ip}) 开放端口: {row['port'] or '无'}")
        scanned += 1
        time.sleep(rate)
    audit("P3_portscan", f"hosts={scanned}")


def fingerprint_probe(rows, rate=2.0, max_hosts=60, breaker=None):
    """Web 指纹识别：状态码 + Server 头 + X-Powered-By + 页面标题（低速）。
    解析失败属正常噪音不喂熔断信号；HTTP 层信号由 http_probe 自动上报。"""
    targets = rows[:max_hosts]
    log(f"\n[Web 指纹识别] {len(targets)} 个目标，间隔 {rate}s/请求")
    for i, row in enumerate(targets, 1):
        if breaker and breaker.tripped:
            log(f"  [熔断] {breaker.reason}，本项探测提前停止")
            break
        ip = row.get("ip") or resolve_host(row["name"])
        if not ip:
            log(f"  [{i}/{len(targets)}] {row['name']} 解析失败，跳过")
            continue
        row["ip"] = ip
        probe = http_probe(row["name"], rate, breaker=breaker)
        if not probe:
            log(f"  [{i}/{len(targets)}] {row['name']} 无 Web 服务")
            continue
        row.update({"ip": probe["ip"], "status": probe["status"],
                    "server": probe["server"], "title": probe["title"]})
        if probe.get("powered_by"):
            row["server"] = (row["server"] + " | X-Powered-By: " + probe["powered_by"]).strip(" |")
        ports = [x for x in str(row.get("port", "")).split(",") if x]
        if str(probe["port"]) not in ports:
            ports.append(str(probe["port"]))
        row["port"] = ",".join(ports)
        row["source"] += "+指纹"
        log(f"  [{i}/{len(targets)}] {row['name']}  {probe['status']}  {row['server'][:40]}")
    audit("P3_fingerprint", f"probed={len(targets)}")


def _fetch_status(host, path, ctx, breaker=None):
    """请求单个路径，返回 HTTP 状态码；HTTPS 优先、HTTP 回退；无响应返回 None。
    传入 breaker 时喂熔断信号（403/429 计入拦截，超时/重置计入失败）。"""
    for scheme in ("https", "http"):
        req = urllib.request.Request(f"{scheme}://{host}{path}", headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
                r.read(1024)
                if breaker:
                    breaker.ok()
                return r.status
        except urllib.error.HTTPError as e:
            if breaker:
                if e.code in (403, 429):
                    breaker.fail(str(e.code))
                else:
                    breaker.ok()  # 404 等说明服务器在线，连接层面正常
            return e.code
        except Exception as e:
            if breaker:
                breaker.fail(_classify_net_error(e))
            continue
    return None


def dir_scan(rows, rate=2.0, max_hosts=8, breaker=None):
    """目录扫描/爬虫：对可解析主机请求少量常见敏感路径（低速，发现写入 row['note']）"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    hosts = []
    for r in rows:
        ip = r.get("ip") or resolve_host(r["name"])
        if ip:
            r["ip"] = ip
            hosts.append(r)
        if len(hosts) >= max_hosts:
            break
    log(f"\n[目录扫描/爬虫] 路径 {len(DIR_PATHS)} 条 × 主机 {len(hosts)} 台，间隔 {rate}s/请求")
    for row in hosts:
        if breaker and breaker.tripped:
            log(f"  [熔断] {breaker.reason}，本项探测提前停止")
            break
        hits = []
        for path in DIR_PATHS:
            if breaker and breaker.tripped:
                break
            code = _fetch_status(row["name"], path, ctx, breaker=breaker)
            if code in (200, 401, 403):
                hits.append(f"{path}({code})")
            time.sleep(rate)
        if hits:
            row["note"] = (row.get("note", "") + " 路径发现: " + " ".join(hits)).strip()
        log(f"  {row['name']}: {' '.join(hits) if hits else '无发现'}")
    audit("P3_dirscan", f"hosts={len(hosts)}")


# ---------------- P4-P6 梳理 + 输出 ----------------
def build_rows(raw, level):
    rows = []
    for i, r in enumerate(raw, 1):
        is_web = bool(r.get("status"))
        rows.append({
            "序号": i,
            "资产类型": "Web应用" if is_web else "域名/主机(待确认)",
            "域名": r["name"],
            "IP": r.get("ip", ""),
            "端口": r.get("port", ""),
            "服务及版本": r.get("server", ""),
            "指纹信息": r.get("title", ""),
            "归属部门/责任人": "(P5 阶段由客户确认)",
            "重要性": "待分级",
            "是否在授权范围": "待P5确认",
            "数据来源": r.get("source", "被动"),
            "备注": r.get("note", ""),
        })
    return rows


def export(domain, level, rows):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = OUTDIR / f"assets_{domain}_{ts}.csv"
    md_path = OUTDIR / f"assets_{domain}_{ts}.md"
    fields = ["序号", "资产类型", "域名", "IP", "端口", "服务及版本", "指纹信息",
              "归属部门/责任人", "重要性", "是否在授权范围", "数据来源", "备注"]
    def _safe(v):
        s = str(v)
        return ("'" + s) if s[:1] in ("=", "+", "-", "@") else s
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows({k: _safe(r[k]) for k in fields} for r in rows)

    web_n = sum(1 for r in rows if r["资产类型"] == "Web应用")
    lines = [
        f"# 资产收集清单：{domain}",
        "",
        f"- 生成时间：{datetime.now().isoformat(timespec='seconds')}",
        f"- 对象定级：**{MATRIX[level]['label']}**",
        f"- 资产总数：{len(rows)}（Web 应用 {web_n}）",
        f"- 数据来源：被动收集（crt.sh 证书透明度）+ 分级管控的主动探测",
        "",
        "| " + " | ".join(fields[:7]) + " |",
        "|" + "---|" * 7,
    ]
    for r in rows:
        lines.append("| " + " | ".join(str(r[k]) for k in fields[:7]) + " |")
    lines += [
        "",
        "---",
        "## 下一步（P5 范围确认，红线步骤）",
        "1. 本清单提交客户/按 SRC 范围公告核对；",
        "2. 书面圈定可测资产（签字/邮件留痕）；",
        "3. 范围外资产仅报告，禁止任何测试。",
        "",
        "六条红线：不越权、不拖库、不破坏、不扩散、不留后门、按约销毁。",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    audit("P6_export", f"csv={csv_path.name}, md={md_path.name}")
    return csv_path, md_path


def main():
    ap = argparse.ArgumentParser(description="资产收集分级自动化工作流")
    ap.add_argument("--domain", help="目标主域名，如 example.com")
    ap.add_argument("--level", choices=["high", "special", "general", "custom"], help="对象等级")
    ap.add_argument("--authorized", action="store_true", help="声明已完成 P0 授权检查（留痕）")
    ap.add_argument("--passive-only", action="store_true", help="仅被动收集，跳过 P3 主动探测")
    ap.add_argument("--titles", action="store_true", help="被动收集后补全网站标题（轻量探测，每站访问首页一次）")
    ap.add_argument("--approve-active", action="store_true", help="高敏感对象主动探测特批（留痕）")
    ap.add_argument("--hunter-key", default="", help="Hunter API-KEY（随用随填，不落盘）")
    ap.add_argument("--fofa-email", default="", help="FOFA 登录邮箱（随用随填，不落盘）")
    ap.add_argument("--fofa-key", default="", help="FOFA API Key（随用随填，不落盘）")
    args = ap.parse_args()

    log("=" * 56)
    log("  资产收集分级自动化工作流 v1.0")
    log("  合规红线：主动探测仅限已书面授权范围内的目标")
    log("=" * 56)

    interactive = not args.domain
    if interactive:
        args.domain = input("\n请输入目标主域名（如 example.com）: ").strip().lower()
    if not args.domain:
        sys.exit("未提供域名，退出。")

    # P0
    if not check_authorization(auto=args.authorized, domain=args.domain):
        sys.exit(1)

    # P1
    level = args.level or classify_interactive()
    log(f"\n[P1] 定级结果：{MATRIX[level]['label']}")
    audit("P1_classify", f"domain={args.domain}, level={level}")

    # P2
    subs = passive_collect(args.domain, hunter_key=args.hunter_key,
                           fofa_email=args.fofa_email, fofa_key=args.fofa_key)

    # P3
    if args.passive_only:
        if args.titles:
            raw = title_probe(subs, level, args.approve_active)
        else:
            log("\n[P3] --passive-only：跳过主动探测")
            raw = [{"name": s, "ip": "", "port": "", "status": "", "server": "", "title": "",
                    "source": "被动(crt.sh)"} for s in subs]
    else:
        raw = active_probe(subs, level, args.approve_active)

    # P4-P6
    rows = build_rows(raw, level)
    csv_path, md_path = export(args.domain, level, rows)
    log("\n=== P4-P6 完成 ===")
    log(f"  资产清单 CSV: {csv_path}")
    log(f"  资产清单 MD : {md_path}")
    log(f"  审计留痕    : {AUDIT_LOG}")
    log("\n[提醒] 下一步是 P5 范围确认：清单交客户书面圈定后，才可进入漏洞扫描/测试。")


if __name__ == "__main__":
    main()
