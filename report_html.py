import json
import webbrowser
from pathlib import Path
from datetime import datetime

BASE_DIR    = Path(__file__).parent
REPORT_JSON = BASE_DIR / "scan_results" / "report.json"
REPORT_HTML = BASE_DIR / "scan_results" / "report.html"

SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
}

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, 'Segoe UI', sans-serif;
  background: #f8f9fa;
  color: #111;
  font-size: 14px;
  line-height: 1.6;
}
.wrap { max-width: 860px; margin: 48px auto; padding: 0 24px 80px; }

.header { margin-bottom: 40px; }
.header h1 { font-size: 22px; font-weight: 700; color: #111; }
.header .sub { color: #666; margin-top: 4px; font-size: 13px; }
.header .meta { margin-top: 12px; font-size: 13px; color: #555; }

.stats { display: flex; gap: 16px; margin-bottom: 40px; }
.stat {
  background: #fff;
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  padding: 16px 24px;
  min-width: 120px;
}
.stat .n { font-size: 28px; font-weight: 700; line-height: 1; }
.stat .l { font-size: 12px; color: #666; margin-top: 4px; }

h2 { font-size: 15px; font-weight: 600; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #e5e7eb; }

table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; margin-bottom: 40px; overflow: hidden; }
th { background: #f3f4f6; text-align: left; padding: 10px 14px; font-size: 12px; font-weight: 600; color: #444; border-bottom: 1px solid #e5e7eb; }
td { padding: 10px 14px; border-bottom: 1px solid #f3f4f6; font-size: 13px; }
tr:last-child td { border-bottom: none; }

.badge { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; }
.found { color: #dc2626; font-weight: 600; }
.safe  { color: #16a34a; }

.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; margin-bottom: 16px; overflow: hidden; }
.card-head { padding: 14px 16px; border-bottom: 1px solid #f3f4f6; display: flex; align-items: center; gap: 12px; }
.card-head h3 { font-size: 14px; font-weight: 600; }
.card-head .cid { font-size: 12px; color: #777; }
.card-body { padding: 14px 16px; }
.kv { display: grid; grid-template-columns: 100px 1fr; gap: 4px 8px; font-size: 13px; margin-bottom: 14px; }
.kv .k { color: #777; }
.detect { background: #f0f9ff; border-left: 3px solid #3b82f6; padding: 8px 12px; font-size: 12px; color: #1e40af; font-family: monospace; margin-bottom: 12px; white-space: pre-wrap; }
.poc-ok   { background: #f0fdf4; border-left: 3px solid #16a34a; padding: 8px 12px; font-size: 12px; color: #166534; font-family: monospace; margin-bottom: 12px; }
.poc-fail { background: #f9fafb; border-left: 3px solid #9ca3af; padding: 8px 12px; font-size: 12px; color: #6b7280; font-family: monospace; margin-bottom: 12px; }
.rem h4 { font-size: 12px; font-weight: 600; color: #92400e; margin-bottom: 6px; }
.rem { background: #fffbeb; border-left: 3px solid #f59e0b; padding: 10px 12px; }
.rem li { font-size: 13px; color: #78350f; margin-left: 14px; margin-bottom: 2px; }
"""

def badge(sev):
    color = SEV_COLOR.get(sev, "#888")
    return f'<span class="badge" style="color:{color};border:1px solid {color};background:{color}18">{sev}</span>'

def table_row(r):
    sev      = r["severity"]
    status   = '<span class="found">● 탐지됨</span>' if r["found"] else '<span class="safe">○ 안전</span>'
    poc      = r.get("poc_success", False)
    poc_cell = '<span style="color:#16a34a;font-weight:600">● 성공</span>' if poc else '<span style="color:#9ca3af">—</span>'
    os_info  = r.get("os_info", "") or "—"
    return (
        f"<tr>"
        f"<td><strong>{r['cve']}</strong></td>"
        f"<td>{r['name']}</td>"
        f"<td>{badge(sev)}</td>"
        f"<td>{status}</td>"
        f"<td>{poc_cell}</td>"
        f"<td style='font-size:12px;color:#555'>{os_info}</td>"
        f"<td style='font-family:monospace;font-size:12px;color:#2563eb'>{r['url']}</td>"
        f"</tr>"
    )

def detail_card(r):
    if not r["found"]:
        return ""
    sev      = r["severity"]
    color    = SEV_COLOR.get(sev, "#888")
    rem_html = "".join(f"<li>{i}</li>" for i in r.get("remediation", []))
    extra    = r.get("extra", "")
    poc_ok   = r.get("poc_success", False)
    poc_msg  = r.get("poc_msg", "")

    os_info     = r.get("os_info", "")
    detect_html = f'<div class="detect">{extra}</div>' if extra else ""

    if poc_ok and poc_msg:
        poc_html = f'<div class="poc-ok">PoC 성공: {poc_msg}</div>'
    elif poc_msg:
        poc_html = f'<div class="poc-fail">PoC: {poc_msg}</div>'
    else:
        poc_html = ""

    return f"""
<div class="card">
  <div class="card-head" style="border-left:3px solid {color}">
    <div>
      <h3>{r['name']}  {badge(sev)}</h3>
      <div class="cid">{r['cve']}</div>
    </div>
  </div>
  <div class="card-body">
    <div class="kv">
      <span class="k">대상</span><span style="font-family:monospace;font-size:12px">{r['url']}</span>
      <span class="k">OS</span><span style="font-size:12px">{os_info or '—'}</span>
    </div>
    {detect_html}
    {poc_html}
    <div class="rem">
      <h4>권장 조치</h4>
      <ul>{rem_html}</ul>
    </div>
  </div>
</div>"""

def build(data):
    results  = data["results"]
    total    = len(results)
    detected = sum(1 for r in results if r["found"])
    poc_cnt  = sum(1 for r in results if r.get("poc_success"))
    dt       = datetime.fromisoformat(data["scan_time"]).strftime("%Y-%m-%d  %H:%M")

    sev_counts = {}
    for r in results:
        if r["found"]:
            sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1

    extra_stats = "".join(
        f'<div class="stat"><div class="n" style="color:{SEV_COLOR[s]}">{sev_counts[s]}</div>'
        f'<div class="l">{s}</div></div>'
        for s in ["CRITICAL","HIGH","MEDIUM"] if s in sev_counts
    )

    rows    = "\n".join(table_row(r) for r in results)
    details = "\n".join(detail_card(r) for r in results)

    poc_stat = f'<div class="stat"><div class="n" style="color:#16a34a">{poc_cnt}</div><div class="l">PoC 성공</div></div>' if poc_cnt else ""

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>취약점 진단 보고서</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>취약점 진단 보고서</h1>
    <div class="sub">ASM 파이프라인 기반 취약점 탐지 (Nuclei)</div>
    <div class="meta">
      <span>진단 일시: {dt}</span>
      &nbsp;&nbsp;
      <span>도구: Nuclei v3.3.7</span>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="n">{total}</div><div class="l">스캔 대상</div></div>
    <div class="stat"><div class="n" style="color:#dc2626">{detected}</div><div class="l">탐지된 취약점</div></div>
    <div class="stat"><div class="n" style="color:#16a34a">{total-detected}</div><div class="l">안전</div></div>
    {extra_stats}
    {poc_stat}
  </div>

  <h2>스캔 결과 요약</h2>
  <table>
    <thead><tr><th>CVE ID</th><th>취약점명</th><th>심각도</th><th>탐지결과</th><th>PoC</th><th>OS</th><th>대상 주소</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <h2>취약점 상세</h2>
  {details}

</div>
</body>
</html>"""


def generate():
    data = json.loads(REPORT_JSON.read_text(encoding="utf-8"))
    html = build(data)
    REPORT_HTML.write_text(html, encoding="utf-8")
    return REPORT_HTML


def main():
    if not REPORT_JSON.exists():
        print("report.json 없음 — scanner.py 먼저 실행하세요.")
        return
    path = generate()
    print(f"[+] 보고서 생성: {path}")
    webbrowser.open(path.as_uri())


if __name__ == "__main__":
    main()
