#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
资产收集分级工作流 · Web 版 v1.0
启动：python asset_web.py  然后浏览器打开 http://localhost:8000
后端复用 asset_workflow.py 的收集引擎与审计留痕。
仅监听 127.0.0.1，不对外暴露。
"""

import argparse
import json
import re
import threading
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import asset_workflow as aw

OUTDIR = Path(__file__).resolve().parent
JOBS = {}
MAX_PROBE = 60  # 单次最多主动探测的域名数，防止大型目标跑太久

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>资产收集分级工作流</title>
<style>
  * { box-sizing: border-box; margin: 0; }
  body { font-family: "Microsoft YaHei", "PingFang SC", sans-serif; background: #f7f6f3; color: #2c2c2a; line-height: 1.6; }
  .wrap { max-width: 880px; margin: 0 auto; padding: 24px 16px 64px; }
  header.top { padding: 20px 0 8px; }
  header.top h1 { font-size: 20px; font-weight: 500; }
  header.top p { font-size: 13px; color: #888780; margin-top: 4px; }
  .steps { display: flex; gap: 8px; margin: 16px 0 20px; flex-wrap: wrap; }
  .step-tab { font-size: 12px; padding: 4px 12px; border-radius: 99px; background: #f1efe8; color: #888780; border: 1px solid #e3e1d8; }
  .step-tab.on { background: #185FA5; color: #fff; border-color: #185FA5; }
  .card { background: #fff; border: 1px solid #e8e6df; border-radius: 12px; padding: 20px; margin-bottom: 16px; }
  .card h2 { font-size: 15px; font-weight: 500; margin-bottom: 12px; }
  .card h2 .num { display: inline-block; width: 22px; height: 22px; line-height: 22px; text-align: center; border-radius: 50%; background: #185FA5; color: #fff; font-size: 12px; margin-right: 8px; }
  label.chk { display: flex; gap: 8px; align-items: flex-start; font-size: 13px; padding: 6px 0; cursor: pointer; }
  label.chk input { margin-top: 4px; }
  .q-row { font-size: 13px; padding: 10px 12px; background: #faf9f6; border-radius: 8px; margin-bottom: 8px; }
  .q-row .opts { margin-top: 6px; display: flex; gap: 14px; flex-wrap: wrap; }
  .q-row label { font-size: 13px; cursor: pointer; }
  input[type=text] { width: 100%; padding: 9px 12px; font-size: 14px; border: 1px solid #d3d1c7; border-radius: 8px; outline: none; }
  input[type=text]:focus { border-color: #185FA5; }
  .btn { display: inline-block; padding: 9px 22px; font-size: 14px; border: none; border-radius: 8px; cursor: pointer; background: #185FA5; color: #fff; }
  .btn:disabled { background: #b4b2a9; cursor: not-allowed; }
  .btn.ghost { background: #fff; color: #185FA5; border: 1px solid #85B7EB; }
  .badge { display: inline-block; font-size: 12px; padding: 3px 12px; border-radius: 99px; margin-left: 8px; }
  .b-high { background: #FCEBEB; color: #A32D2D; }
  .b-special { background: #FAEEDA; color: #854F0B; }
  .b-general { background: #EAF3DE; color: #3B6D11; }
  .b-custom { background: #EEEDFE; color: #3C3489; }
  .warn { background: #FCEBEB; border: 1px solid #F09595; border-radius: 8px; padding: 10px 14px; font-size: 13px; color: #791F1F; margin-top: 12px; }
  .note { font-size: 12px; color: #888780; margin-top: 8px; }
  pre.logbox { background: #2c2c2a; color: #d6f5d6; font-size: 12px; padding: 14px; border-radius: 8px; max-height: 300px; overflow: auto; white-space: pre-wrap; font-family: Consolas, monospace; }
  table.res { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }
  table.res th, table.res td { border: 1px solid #e8e6df; padding: 6px 8px; text-align: left; word-break: break-all; }
  table.res th { background: #f1efe8; font-weight: 500; }
  .hidden { display: none !important; }
  footer.redline { margin-top: 24px; font-size: 12px; color: #A32D2D; background: #FCEBEB; border-radius: 8px; padding: 10px 14px; }
  a.dl { font-size: 13px; color: #185FA5; margin-right: 16px; }
  .row-flex { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-top: 12px; }
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1>资产收集分级工作流 · Web 版</h1>
    <p>合规优先 · 最小必要 · 全程留痕 · 分级管控（审计日志写入服务端 audit.log）</p>
  </header>

  <div class="steps">
    <span class="step-tab on" id="tab1">1 授权确认</span>
    <span class="step-tab" id="tab2">2 对象定级</span>
    <span class="step-tab" id="tab3">3 执行收集</span>
    <span class="step-tab" id="tab4">4 资产清单</span>
  </div>

  <div class="card" id="card1">
    <h2><span class="num">1</span>P0 立项与授权（逐项确认）</h2>
    <div id="authList"></div>
    <div class="warn hidden" id="authWarn">授权检查未全部通过，无法继续。六条红线：不越权、不拖库、不破坏、不扩散、不留后门、按约销毁。</div>
  </div>

  <div class="card hidden" id="card2">
    <h2><span class="num">2</span>P1 对象定级（决策树）</h2>
    <div class="q-row">目标属于 政府军工 / 金融 / 运营商 / 能源 / 医疗 / 关基？
      <div class="opts"><label><input type="radio" name="q1" value="y"> 是</label><label><input type="radio" name="q1" value="n"> 否</label></div>
    </div>
    <div class="q-row hidden" id="q2row">目标属于 教育 / 大型互联网 / 国企集团？
      <div class="opts"><label><input type="radio" name="q2" value="y"> 是</label><label><input type="radio" name="q2" value="n"> 否</label></div>
    </div>
    <div class="q-row hidden" id="q3row">目标属于 中小企业 / 个人站点？
      <div class="opts"><label><input type="radio" name="q3" value="y"> 是</label><label><input type="radio" name="q3" value="n"> 否</label></div>
    </div>
    <div class="q-row hidden" id="customRow">
      <label class="chk" style="padding:0"><input type="checkbox" id="customChk"> 自定义对象（下一步自行勾选探测操作，全部低速执行）</label>
    </div>
    <p class="note" id="levelResult"></p>
  </div>

  <div class="card hidden" id="card3">
    <h2><span class="num">3</span>P2-P3 执行收集</h2>
    <input type="text" id="domain" placeholder="目标主域名，如 example.com（输 www 子域名自动归并主域名；不勾选任何探测项即为纯被动收集）">
    <div class="row-flex">
      <label class="chk hidden" style="padding:0" id="approveRow"><input type="checkbox" id="approveActive"> 高敏感主动探测已获单独审批（特批留痕）</label>
    </div>
    <div id="customOps" class="hidden" style="margin-top:12px">
      <p class="note" style="margin:0 0 4px">探测操作（仅限已授权范围内的目标；速率按定级自动限制，高敏感对象需先勾选上方特批）：</p>
      <label class="chk" style="padding:0"><input type="checkbox" id="opBrute"> 子域名爆破（内置字典，主动 DNS 查询）</label>
      <label class="chk" style="padding:0"><input type="checkbox" id="opPort"> 存活探测 / 端口扫描（常见端口 TCP 连接）</label>
      <label class="chk" style="padding:0"><input type="checkbox" id="opFingerprint"> Web 指纹识别（状态码 / Server / X-Powered-By / 标题）</label>
      <label class="chk" style="padding:0"><input type="checkbox" id="opDir"> 目录扫描 / 爬虫（少量常见敏感路径）</label>
    </div>
    <div class="row-flex">
      <label class="chk" style="padding:0"><input type="checkbox" id="useHunter"> Hunter 测绘</label>
      <input type="password" id="hunterKey" placeholder="填 Hunter API-KEY（不落盘，仅本次使用）" style="flex:1;min-width:200px;padding:7px 10px;font-size:12px;border:1px solid #d3d1c7;border-radius:8px">
    </div>
    <div class="row-flex">
      <label class="chk" style="padding:0"><input type="checkbox" id="useFofa"> FOFA 测绘</label>
      <input type="text" id="fofaEmail" placeholder="FOFA 邮箱" style="flex:1;min-width:140px;padding:7px 10px;font-size:12px;border:1px solid #d3d1c7;border-radius:8px">
      <input type="password" id="fofaKey" placeholder="FOFA API Key" style="flex:1;min-width:140px;padding:7px 10px;font-size:12px;border:1px solid #d3d1c7;border-radius:8px">
    </div>
    <div class="row-flex">
      <label class="chk" style="padding:0">导入测绘平台导出文件（可选，Hunter/FOFA 网页查询后导出的 CSV）：</label>
      <input type="file" id="csvFile" accept=".csv,.txt" style="font-size:12px">
    </div>
    <div class="row-flex">
      <button class="btn" id="runBtn">开始收集</button>
      <span class="note" id="runHint"></span>
    </div>
    <p class="note">被动收集：crt.sh 证书透明度 + HackerTarget 被动 DNS（不勾探测项即纯被动）；探测项速率按定级自动限制（特殊敏感 1s、一般对象 0.2s、自定义/高敏感 2s），单次最多探测 60 个域名</p>
  </div>

  <div class="card hidden" id="card4">
    <h2><span class="num">4</span>P4-P6 资产清单</h2>
    <pre class="logbox hidden" id="logbox"></pre>
    <div id="resultBox" class="hidden">
      <p class="note" id="statLine"></p>
      <p><a class="dl" id="dlCsv" href="#">下载 CSV 清单</a><a class="dl" id="dlMd" href="#">下载 Markdown 报告</a></p>
      <div style="overflow:auto"><table class="res" id="resTable"></table></div>
      <div class="warn">下一步（P5 范围确认，红线步骤）：清单交客户书面圈定可测资产；范围外资产仅报告，禁止任何测试。</div>
    </div>
  </div>

  <footer class="redline">六条红线：不越权、不拖库、不破坏、不扩散、不留后门、按约销毁。 本工具仅限对已获书面授权的目标使用。</footer>
</div>

<script>
var AUTH_ITEMS = [
  "书面授权在手（授权书/合同/SRC 范围公告）",
  "测试范围已书面确认",
  "禁止项清单已知悉（禁测系统、禁测时段）",
  "应急联系人双向可达",
  "数据保留与销毁要求已明确"
];
var LEVELS = { high: ["高敏感", "b-high"], special: ["特殊敏感", "b-special"], general: ["一般对象", "b-general"], custom: ["自定义", "b-custom"] };
var state = { level: null };

function $(id){ return document.getElementById(id); }

AUTH_ITEMS.forEach(function(t, i){
  var l = document.createElement("label");
  l.className = "chk";
  l.innerHTML = "<input type='checkbox' class='authChk'> <span>" + t + "</span>";
  $("authList").appendChild(l);
});
document.querySelectorAll(".authChk").forEach(function(c){
  c.addEventListener("change", function(){
    var all = Array.prototype.every.call(document.querySelectorAll(".authChk"), function(x){ return x.checked; });
    if (all) { $("card2").classList.remove("hidden"); $("tab2").classList.add("on"); $("authWarn").classList.add("hidden"); }
    else { $("card2").classList.add("hidden"); $("tab2").classList.remove("on"); }
  });
});

function setLevel(lv, via){
  state.level = lv;
  var info = LEVELS[lv];
  $("levelResult").innerHTML = "定级结果（" + via + "）：<span class='badge " + info[1] + "'>" + info[0] + "</span>";
  $("card3").classList.remove("hidden"); $("tab3").classList.add("on");
  $("approveRow").classList.toggle("hidden", lv !== "high");
  $("customOps").classList.remove("hidden");
}
function clearLevel(){
  state.level = null;
  $("levelResult").innerHTML = "";
  $("card3").classList.add("hidden"); $("tab3").classList.remove("on");
  $("card4").classList.add("hidden"); $("tab4").classList.remove("on");
  $("customOps").classList.add("hidden");
}
function resetBelow(step){
  if (step <= 1) {
    document.querySelectorAll("input[name=q2]").forEach(function(r){ r.checked = false; });
    $("q2row").classList.add("hidden");
  }
  document.querySelectorAll("input[name=q3]").forEach(function(r){ r.checked = false; });
  $("q3row").classList.add("hidden");
  $("customChk").checked = false;
  $("customRow").classList.add("hidden");
}
document.querySelector("input[name=q1][value=y]").addEventListener("change", function(){ resetBelow(1); setLevel("high", "决策树 Q1"); });
document.querySelector("input[name=q1][value=n]").addEventListener("change", function(){ resetBelow(1); clearLevel(); $("q2row").classList.remove("hidden"); });
document.querySelector("input[name=q2][value=y]").addEventListener("change", function(){ resetBelow(2); setLevel("special", "决策树 Q2"); });
document.querySelector("input[name=q2][value=n]").addEventListener("change", function(){ resetBelow(2); clearLevel(); $("q3row").classList.remove("hidden"); });
document.querySelector("input[name=q3][value=y]").addEventListener("change", function(){ setLevel("general", "决策树 Q3"); });
document.querySelector("input[name=q3][value=n]").addEventListener("change", function(){
  clearLevel();
  $("customRow").classList.remove("hidden");
});
$("customChk").addEventListener("change", function(){
  if (this.checked) { setLevel("custom", "自定义勾选"); }
  else { clearLevel(); $("customRow").classList.remove("hidden"); }
});

$("runBtn").addEventListener("click", function(){
  var domain = $("domain").value.trim().toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) { alert("域名格式不正确"); return; }
  if (!state.level) { alert("请先完成定级"); return; }
  var body = { domain: domain, level: state.level, authorized: true,
               approve_active: $("approveActive").checked, import_csv: "",
               op_brute: $("opBrute").checked, op_port: $("opPort").checked,
               op_fingerprint: $("opFingerprint").checked, op_dir: $("opDir").checked,
               hunter_key: $("useHunter").checked ? $("hunterKey").value.trim() : "",
               fofa_email: $("useFofa").checked ? $("fofaEmail").value.trim() : "",
               fofa_key: $("useFofa").checked ? $("fofaKey").value.trim() : "" };
  if ($("useHunter").checked && !body.hunter_key) { alert("勾选了 Hunter 但未填 API-KEY"); return; }
  if ($("useFofa").checked && (!body.fofa_email || !body.fofa_key)) { alert("勾选了 FOFA 但邮箱或 Key 未填"); return; }
  var send = function(){
    $("runBtn").disabled = true; $("runHint").textContent = "收集中，请稍候…";
    $("card4").classList.remove("hidden"); $("tab4").classList.add("on");
    $("logbox").classList.remove("hidden"); $("logbox").textContent = "任务已提交…\n";
    $("resultBox").classList.add("hidden");
    fetch("/api/run", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) })
      .then(function(r){ return r.json(); })
      .then(function(d){
        if (d.error) { $("logbox").textContent += "错误：" + d.error; $("runBtn").disabled = false; $("runHint").textContent = ""; return; }
        poll(d.job);
      });
  };
  var f = $("csvFile").files[0];
  if (f) {
    if (f.size > 3 * 1024 * 1024) { alert("文件超过 3MB，请先拆分"); return; }
    var reader = new FileReader();
    reader.onload = function(e){ body.import_csv = e.target.result; send(); };
    reader.readAsText(f);
  } else { send(); }
});
function poll(job){
  fetch("/api/job?id=" + job).then(function(r){ return r.json(); }).then(function(d){
    $("logbox").textContent = d.log.join("\n");
    $("logbox").scrollTop = $("logbox").scrollHeight;
    if (d.status === "running") { setTimeout(function(){ poll(job); }, 1200); return; }
    $("runBtn").disabled = false; $("runHint").textContent = "";
    if (d.status === "error") { $("logbox").textContent += "\n[失败] " + d.error; return; }
    var res = d.result;
    $("statLine").textContent = "定级：" + res.level_label + " ｜ 资产总数：" + res.rows.length + "（Web 应用 " + res.web_count + "）";
    $("dlCsv").href = res.csv_url; $("dlMd").href = res.md_url;
    function esc(s){ return String(s).replace(/[&<>"']/g, function(ch){ return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]; }); }
    var cols = ["序号","资产类型","域名","IP","端口","服务及版本","指纹信息","数据来源"];
    var html = "<tr>" + cols.map(function(c){ return "<th>" + c + "</th>"; }).join("") + "</tr>";
    res.rows.forEach(function(r){
      html += "<tr>" + cols.map(function(c){ return "<td>" + esc(r[c] === undefined ? "" : r[c]) + "</td>"; }).join("") + "</tr>";
    });
    $("resTable").innerHTML = html;
    $("resultBox").classList.remove("hidden");
  });
}
</script>
</body>
</html>
"""


def run_job(job_id, params):
    job = JOBS[job_id]
    aw.log = lambda m: job["log"].append(str(m))
    try:
        domain = params["domain"]
        level = params["level"]
        safe_params = {k: ("***" if ("key" in k or "email" in k) and v else v)
                       for k, v in params.items() if k != "import_csv"}
        aw.audit("web_run", json.dumps(safe_params, ensure_ascii=False))
        job["log"].append(f"[P0] 授权声明已留痕（Web 确认） domain={domain}")
        job["log"].append(f"[P1] 定级：{aw.MATRIX[level]['label']}")
        subs = aw.passive_collect(domain,
                                  hunter_key=params.get("hunter_key", ""),
                                  fofa_email=params.get("fofa_email", ""),
                                  fofa_key=params.get("fofa_key", ""))
        import_csv = params.get("import_csv") or ""
        if import_csv.strip():
            root = aw.root_domain(domain)
            imported = aw.parse_import_csv(import_csv, root)
            before = len(subs)
            subs = sorted(set(subs) | imported)
            job["log"].append(f"[P2] 导入测绘导出文件：解析出 {len(imported)} 个域名，合并后新增 {len(subs) - before} 个")
            aw.audit("P2_import", f"imported={len(imported)}, new={len(subs) - before}")
        ops = ("op_brute", "op_port", "op_fingerprint", "op_dir")
        rule = aw.MATRIX[level]
        rate = rule["rate"]
        need_approve = rule["http"] == "approve"
        approved = params.get("approve_active", False)
        raw = [{"name": s, "ip": "", "port": "", "status": "", "server": "", "title": "",
                "source": "被动(crt.sh)"} for s in subs]
        if not any(params.get(k) for k in ops):
            job["log"].append("[P3] 未勾选探测项：仅被动收集")
        elif need_approve and not approved:
            job["log"].append(f"[P3] {rule['label']}对象的主动探测需单独审批：未勾选特批，"
                              "跳过全部探测项（仅保留被动结果）")
            aw.audit("P3_skipped", "active ops not approved")
        else:
            if need_approve:
                aw.audit("P3_approved", "active ops approved via web 特批")
                job["log"].append("[P3] 已记录主动探测特批")
            root = aw.root_domain(domain)
            baseline = f"www.{root}"
            breaker = aw.CircuitBreaker(
                baseline_host=baseline if aw.resolve_host(baseline) else None)
            if params.get("op_brute") and not breaker.tripped:
                found = aw.brute_subdomains(root, rate, breaker=breaker)
                known = {r["name"] for r in raw}
                added = 0
                for s in sorted(set(found)):
                    if s not in known:
                        raw.append({"name": s, "ip": "", "port": "", "status": "", "server": "",
                                    "title": "", "source": "子域名爆破"})
                        added += 1
                job["log"].append(f"[P3] 子域名爆破：新增 {added} 个域名")
            if params.get("op_port") and not breaker.tripped:
                aw.port_scan(raw, rate, breaker=breaker)
            if params.get("op_fingerprint") and not breaker.tripped:
                aw.fingerprint_probe(raw, rate, breaker=breaker)
            if params.get("op_dir") and not breaker.tripped:
                aw.dir_scan(raw, rate, breaker=breaker)
            if breaker.tripped:
                job["log"].append(f"[熔断] {breaker.reason}，已停止全部主动探测。"
                                  "已收集的资产将正常导出。")
                job["log"].append("[建议] 30 分钟后再试，或检查该目标 SRC 公告的扫描限制")
                aw.audit("P3_aborted", breaker.reason)
        rows = aw.build_rows(raw, level)
        csv_path, md_path = aw.export(domain, level, rows)
        job["result"] = {
            "rows": rows,
            "level_label": aw.MATRIX[level]["label"],
            "web_count": sum(1 for r in rows if r["资产类型"] == "Web应用"),
            "csv_url": "/outputs/" + csv_path.name,
            "md_url": "/outputs/" + md_path.name,
        }
        job["log"].append("[P4-P6] 清单已生成，下一步：P5 范围确认（客户书面圈定）")
        job["status"] = "done"
    except Exception:
        job["status"] = "error"
        job["error"] = traceback.format_exc(limit=3)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/outputs/"):
            name = Path(self.path[len("/outputs/"):]).name
            fp = OUTDIR / name
            if fp.exists() and name.startswith("assets_"):
                data = fp.read_bytes()
                self.send_response(200)
                ctype = "text/csv" if name.endswith(".csv") else "text/markdown"
                self.send_header("Content-Type", ctype + "; charset=utf-8")
                self.send_header("Content-Disposition", "attachment; filename=" + name)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self._json({"error": "not found"}, 404)
        elif self.path.startswith("/api/job"):
            m = re.search(r"id=([\w-]+)", self.path)
            job = JOBS.get(m.group(1)) if m else None
            if not job:
                self._json({"error": "job not found"}, 404)
            else:
                self._json({"status": job["status"], "log": job["log"],
                            "result": job.get("result"), "error": job.get("error")})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/api/run":
            self._json({"error": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            params = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._json({"error": "bad request"}, 400)
            return
        domain = str(params.get("domain", "")).strip().lower()
        level = params.get("level")
        if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain):
            self._json({"error": "域名格式不正确"})
            return
        if level not in aw.MATRIX:
            self._json({"error": "无效的定级"})
            return
        if not params.get("authorized"):
            self._json({"error": "未完成授权确认，拒绝执行"})
            return
        job_id = uuid.uuid4().hex[:12]
        JOBS[job_id] = {"status": "running", "log": [], "result": None}
        threading.Thread(target=run_job, args=(job_id, params), daemon=True).start()
        self._json({"job": job_id})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"资产收集分级工作流 Web 版已启动: http://localhost:{args.port}")
    print("仅监听 127.0.0.1；Ctrl+C 停止。")
    srv.serve_forever()


if __name__ == "__main__":
    main()
