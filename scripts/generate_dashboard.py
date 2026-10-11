
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from html import escape

REPORT = Path("reports/report.json")
HISTORY = Path("docs/history.json")
DASHBOARD = Path("docs/index.html")

RISK_NAMES = {
    "3": "Alto",
    "2": "Medio",
    "1": "Bajo",
    "0": "Informativo",
    "-1": "Desconocido",
}


def read_json(path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def get_alerts(data):
    alerts = []
    if not isinstance(data, dict):
        return alerts

    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        if not isinstance(site, dict):
            continue

        for alert in site.get("alerts", []):
            if not isinstance(alert, dict):
                continue

            risk = str(alert.get("riskcode", "-1"))
            instances = alert.get("instances", [])

            alerts.append({
                "id": str(alert.get("pluginId", "")),
                "name": str(alert.get("name", "Alerta sin nombre")),
                "risk": risk,
                "risk_name": RISK_NAMES.get(risk, "Desconocido"),
                "count": len(instances) if isinstance(instances, list) else 0,
                "description": str(alert.get("desc", "")),
            })

    return alerts


def main():
    if not REPORT.is_file():
        raise SystemExit(
            "No existe reports/report.json. Ejecuta primero el análisis ZAP."
        )

    report = read_json(REPORT, {})
    alerts = get_alerts(report)

    counts = {
        risk: sum(1 for alert in alerts if alert["risk"] == risk)
        for risk in ("3", "2", "1", "0", "-1")
    }

    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    DASHBOARD.parent.mkdir(parents=True, exist_ok=True)

    history = read_json(HISTORY, [])
    if not isinstance(history, list):
        history = []

    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_number = os.environ.get("GITHUB_RUN_NUMBER", "")
    commit = os.environ.get("GITHUB_SHA", "")[:7]

    # No registrar dos veces la misma ejecución.
    if run_id and any(str(item.get("run_id", "")) == run_id
                      for item in history):
        print("Esta ejecución ya está en el historial.")
        return

    snapshot = {
        "run_id": run_id,
        "run_number": run_number,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "total": len(alerts),
        "counts": counts,
        "alerts": alerts,
    }

    history.append(snapshot)
    history = history[-100:]

    HISTORY.write_text(
        json.dumps(history, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # Datos incorporados a la página estática.
    history_json = json.dumps(history, ensure_ascii=False)
    safe_json = (
        history_json
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )

    latest = history[-1]
    previous = history[-2] if len(history) > 1 else None

    def delta(risk):
        if previous is None:
            return "Primera medición"
        difference = (
            latest["counts"].get(risk, 0)
            - previous["counts"].get(risk, 0)
        )
        if difference > 0:
            return f"+{difference} frente al análisis anterior"
        return f"{difference} frente al análisis anterior"

    cards = []
    for risk, title in [
        ("3", "Riesgo alto"),
        ("2", "Riesgo medio"),
        ("1", "Riesgo bajo"),
        ("0", "Informativas"),
    ]:
        cards.append(
            '<article class="metric">'
            f'<span>{title}</span>'
            f'<strong>{latest["counts"].get(risk, 0)}</strong>'
            f'<small>{escape(delta(risk))}</small>'
            '</article>'
        )

    rows = []
    for alert in sorted(
        alerts,
        key=lambda item: (
            -int(item["risk"]) if item["risk"].isdigit() else 0,
            item["name"].lower(),
        ),
    ):
        rows.append(
            "<tr>"
            f'<td>{escape(alert["name"])}</td>'
            f'<td><span class="risk risk-{escape(alert["risk"])}">'
            f'{escape(alert["risk_name"])}</span></td>'
            f'<td>{escape(alert["id"] or "—")}</td>'
            f'<td>{alert["count"]}</td>'
            "</tr>"
        )

    generated_at = escape(latest["timestamp"])
    total = latest["total"]

    html = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Lab Dashboard</title>
<style>
:root {
  color-scheme: dark;
  --bg: #0b1020;
  --panel: #151d30;
  --line: #2b3851;
  --text: #edf3ff;
  --muted: #a6b3c9;
  --blue: #77a9ff;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif;
}
main { max-width: 1150px; margin: auto; padding: 30px 18px 60px; }
header { display:flex; justify-content:space-between; gap:16px;
  align-items:center; flex-wrap:wrap; margin-bottom:26px; }
h1 { font-size: clamp(25px, 4vw, 36px); margin:0; }
h2 { font-size:19px; margin:0 0 18px; }
p { color:var(--muted); }
.pill { border:1px solid var(--line); border-radius:999px;
  padding:7px 12px; color:#b9f6d0; }
.grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr));
  gap:14px; margin:20px 0; }
.metric,.panel { background:var(--panel); border:1px solid var(--line);
  border-radius:16px; padding:19px; min-width:0; }
.metric span,.metric small { display:block; color:var(--muted); }
.metric strong { display:block; font-size:35px; margin:8px 0; }
.metric small { font-size:12px; }
.two { display:grid; grid-template-columns:1.1fr 1fr; gap:14px; }
canvas { width:100%; height:260px; display:block; }
.legend { display:flex; flex-wrap:wrap; gap:12px; color:var(--muted);
  font-size:13px; margin-top:10px; }
table { width:100%; border-collapse:collapse; }
th,td { padding:12px 8px; border-bottom:1px solid var(--line);
  text-align:left; vertical-align:top; }
th { color:var(--muted); font-size:12px; }
.table-wrap { overflow-x:auto; }
.risk { border-radius:6px; padding:4px 7px; font-size:12px; }
.risk-3 { background:#572a35; color:#ffb9c3; }
.risk-2 { background:#594024; color:#ffd09a; }
.risk-1 { background:#244c45; color:#a8f0d4; }
.risk-0 { background:#293b5c; color:#b9d4ff; }
.risk--1 { background:#3b4050; color:#d7dbe5; }
footer { color:var(--muted); font-size:12px; margin-top:24px; }
@media(max-width:800px) {
  .grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .two { grid-template-columns:1fr; }
}
@media(max-width:420px) {
  .grid { grid-template-columns:1fr 1fr; gap:8px; }
  .metric { padding:12px; }
}
</style>
</head>
<body>
<main>
<header>
  <div>
    <h1>Security Lab Dashboard</h1>
    <p>OWASP Juice Shop · Historial de análisis ZAP</p>
  </div>
  <span class="pill">Laboratorio de entrenamiento</span>
</header>

<section class="grid" id="metrics"></section>

<section class="two">
  <article class="panel">
    <h2>Evolución de alertas</h2>
    <canvas id="trend" height="260"></canvas>
    <div class="legend">
      <span>Alto</span><span>Medio</span>
      <span>Bajo</span><span>Informativo</span>
    </div>
  </article>
  <article class="panel">
    <h2>Distribución actual</h2>
    <canvas id="distribution" height="260"></canvas>
    <p id="summary"></p>
  </article>
</section>

<section class="panel" style="margin-top:14px">
  <h2>Alertas del último análisis</h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Alerta</th><th>Riesgo</th><th>ID ZAP</th><th>Instancias</th>
      </tr></thead>
      <tbody id="alerts"></tbody>
    </table>
  </div>
</section>

<section class="panel" style="margin-top:14px">
  <h2>Historial de ejecuciones</h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Fecha UTC</th><th>Ejecución</th><th>Total alertas</th>
        <th>Commit</th>
      </tr></thead>
      <tbody id="history"></tbody>
    </table>
  </div>
</section>
<footer>
  Datos generados automáticamente desde informes JSON de OWASP ZAP.
  Las alertas requieren validación; no equivalen por sí solas a
  vulnerabilidades confirmadas.
</footer>
</main>

<script>
const historyData = __HISTORY__;
const latest = historyData[historyData.length - 1] || {
  total:0, counts:{}, alerts:[]
};
const riskKeys = ["3","2","1","0"];
const riskNames = {"3":"Alto","2":"Medio","1":"Bajo","0":"Informativo"};
const colors = ["#ff7185","#ffbd69","#55d6b0","#77a9ff"];

document.getElementById("metrics").innerHTML = [
  ["3","Riesgo alto"],["2","Riesgo medio"],
  ["1","Riesgo bajo"],["0","Informativas"]
].map(([key,label],i) => {
  const before = historyData.length > 1
    ? Number(historyData[historyData.length-2].counts[key] || 0) : null;
  const current = Number(latest.counts[key] || 0);
  const change = before === null ? "Primera medición"
    : `${current-before > 0 ? "+" : ""}${current-before} frente al análisis anterior`;
  return `<article class="metric"><span>${label}</span>
    <strong>${current}</strong><small>${change}</small></article>`;
}).join("");

document.getElementById("alerts").innerHTML =
  (latest.alerts || []).map(a => {
    const risk = String(a.risk);
    return `<tr><td>${escapeHtml(a.name)}</td>
      <td><span class="risk risk-${risk}">${escapeHtml(a.risk_name)}</span></td>
      <td>${escapeHtml(a.id || "—")}</td><td>${Number(a.count || 0)}</td></tr>`;
  }).join("") || '<tr><td colspan="4">No hay alertas disponibles.</td></tr>';

document.getElementById("history").innerHTML =
  historyData.slice().reverse().map(item => `<tr>
    <td>${escapeHtml(item.timestamp || "")}</td>
    <td>${escapeHtml(item.run_number || item.run_id || "—")}</td>
    <td>${Number(item.total || 0)}</td>
    <td>${escapeHtml(item.commit || "—")}</td>
  </tr>`).join("");

document.getElementById("summary").textContent =
  `${latest.total || 0} alertas registradas en el análisis más reciente.`;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  })[char]);
}

function setupCanvas(id) {
  const canvas = document.getElementById(id);
  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(280, canvas.clientWidth);
  const height = 260;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  return {ctx, width, height};
}

function drawTrend() {
  const {ctx,w,width,height} = (() => {
    const x = setupCanvas("trend");
    return {ctx:x.ctx,w:x.width,width:x.width,height:x.height};
  })();
  ctx.clearRect(0,0,width,height);
  const left=34, right=12, top=18, bottom=34;
  const plotW=width-left-right, plotH=height-top-bottom;
  const values=historyData.slice(-12);
  const maxValue=Math.max(1,...values.map(v=>Number(v.total||0)));
  ctx.font="11px system-ui";
  ctx.fillStyle="#a6b3c9";
  for(let tick=0;tick<=4;tick++){
    const y=top+plotH*tick/4;
    ctx.strokeStyle="#2b3851";ctx.beginPath();
    ctx.moveTo(left,y);ctx.lineTo(width-right,y);ctx.stroke();
    ctx.fillText(String(Math.round(maxValue*(4-tick)/4)),2,y+4);
  }
  const series=riskKeys.map((key,index)=>({
    key,color:colors[index],
    values:values.map(v=>Number((v.counts||{})[key]||0))
  }));
  series.forEach(s=>{
    ctx.strokeStyle=s.color;ctx.lineWidth=2;ctx.beginPath();
    s.values.forEach((value,i)=>{
      const x=left+(values.length===1?plotW/2:i*plotW/(values.length-1));
      const y=top+plotH-(value/maxValue)*plotH;
      if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
    });
    ctx.stroke();
  });
  ctx.fillStyle="#a6b3c9";
  if(values.length){
    ctx.fillText("Ejecuciones recientes: "+values.length,left,height-8);
  }
}

function drawDistribution() {
  const {ctx,width,height}=setupCanvas("distribution");
  ctx.clearRect(0,0,width,height);
  const values=riskKeys.map(key=>Number(latest.counts[key]||0));
  const total=values.reduce((sum,value)=>sum+value,0);
  const cx=width/2,cy=height/2-5,r=Math.min(width*0.24,90);
  let start=-Math.PI/2;
  if(total===0){
    ctx.strokeStyle="#2b3851";ctx.lineWidth=22;
    ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.stroke();
  } else {
    values.forEach((value,i)=>{
      if(value<=0)return;
      const end=start+(value/total)*Math.PI*2;
      ctx.strokeStyle=colors[i];ctx.lineWidth=22;
      ctx.beginPath();ctx.arc(cx,cy,r,start,end);ctx.stroke();
      start=end;
    });
  }
  ctx.fillStyle="#edf3ff";ctx.textAlign="center";
  ctx.font="bold 25px system-ui";ctx.fillText(String(total),cx,cy+4);
  ctx.font="12px system-ui";ctx.fillStyle="#a6b3c9";
  ctx.fillText("alertas",cx,cy+24);
  ctx.textAlign="left";
  const legendY=height-30;
  riskKeys.forEach((key,i)=>{
    const x=12+i*(width-24)/4;
    ctx.fillStyle=colors[i];ctx.fillRect(x,legendY,8,8);
    ctx.fillStyle="#a6b3c9";ctx.font="10px system-ui";
    ctx.fillText(riskNames[key],x+11,legendY+8);
  });
}

drawTrend();
drawDistribution();
window.addEventListener("resize",()=>{drawTrend();drawDistribution();});
</script>
</body>
</html>
"""
    html = html.replace("__HISTORY__", safe_json)
    DASHBOARD.write_text(html, encoding="utf-8")

    print(f"Historial actualizado: {HISTORY}")
    print(f"Dashboard generado: {DASHBOARD}")
    print(f"Total de ejecuciones guardadas: {len(history)}")


if __name__ == "__main__":
    main()
