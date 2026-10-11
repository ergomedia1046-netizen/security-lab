
#!/usr/bin/env python3
"""Añade un resumen de CodeQL al dashboard existente sin reemplazarlo."""

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALERTS_PATH = ROOT / "reports" / "codeql-alerts.json"
DASHBOARD_PATH = ROOT / "docs" / "index.html"

SEVERITIES = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "warning": "Advertencia",
    "note": "Informativa",
    "error": "Error",
}


def load_alerts():
    if not ALERTS_PATH.exists():
        return None

    try:
        data = json.loads(ALERTS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(data, list):
        return None

    return data


def build_panel(alerts):
    if alerts is None:
        status = "No se pudieron consultar los resultados de CodeQL."
        total = "—"
        counts = {}
        rows = ""
    else:
        status = "Consulta completada; se muestran las alertas devueltas por GitHub."
        total = str(len(alerts))
        counts = {}

        for alert in alerts:
            rule = alert.get("rule") or {}
            severity = (
                rule.get("security_severity_level")
                or rule.get("severity")
                or "unknown"
            ).lower()
            counts[severity] = counts.get(severity, 0) + 1

        if alerts:
            table_rows = []

            for alert in alerts[:50]:
                rule = alert.get("rule") or {}
                severity = (
                    rule.get("security_severity_level")
                    or rule.get("severity")
                    or "unknown"
                ).lower()

                name = (
                    rule.get("description")
                    or rule.get("name")
                    or rule.get("id")
                    or "Regla sin nombre"
                )

                state = alert.get("state", "unknown")
                url = alert.get("html_url", "")

                link = (
                    f'<a href="{escape(url, quote=True)}" '
                    'target="_blank" rel="noopener noreferrer">'
                    'Ver alerta en GitHub</a>'
                    if url.startswith("https://github.com/")
                    else "—"
                )

                table_rows.append(
                    "<tr>"
                    f"<td>{escape(SEVERITIES.get(severity, severity.title()))}</td>"
                    f"<td>{escape(str(name))}</td>"
                    f"<td>{escape(str(state))}</td>"
                    f"<td>{link}</td>"
                    "</tr>"
                )

            rows = "".join(table_rows)
        else:
            rows = (
                '<tr><td colspan="4" class="empty">'
                "GitHub no devolvió alertas de CodeQL."
                "</td></tr>"
            )

    severity_summary = " · ".join(
        f"{escape(SEVERITIES.get(key, key.title()))}: {value}"
        for key, value in sorted(counts.items())
    ) or "Sin alertas para resumir."

    return f"""
<section class="panel" id="codeql-panel">
  <h2>CodeQL — análisis estático del código</h2>
  <div class="grid">
    <div class="card">
      <div class="metric-label">Alertas devueltas por GitHub</div>
      <div class="metric">{escape(total)}</div>
      <div class="muted">Consulta de alertas de code scanning</div>
    </div>
    <div class="card">
      <div class="metric-label">Distribución por severidad</div>
      <p>{severity_summary}</p>
    </div>
  </div>
  <p>{escape(status)}</p>
  <p class="muted">Actualizado: {
      datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
  }</p>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Severidad</th><th>Regla</th><th>Estado</th><th>Detalle</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <p class="muted">
    Un resultado vacío no demuestra que el código esté libre de vulnerabilidades.
  </p>
</section>
"""


def main():
    if not DASHBOARD_PATH.exists():
        raise SystemExit(
            f"No existe el dashboard: {DASHBOARD_PATH}"
        )

    html = DASHBOARD_PATH.read_text(encoding="utf-8")
    marker = '<section class="panel" id="codeql-panel">'

    # Permite ejecutar el script varias veces sin duplicar la tarjeta.
    if marker in html:
        start = html.index(marker)
        end = html.find("</section>", start)

        if end == -1:
            raise SystemExit(
                "No se pudo localizar el final de la sección CodeQL existente."
            )

        end += len("</section>")
        html = html[:start] + html[end:]

    alerts = load_alerts()
    panel = build_panel(alerts)

    insertion_point = '<section class="two">'

    if insertion_point not in html:
        raise SystemExit(
            "No se encontró el punto de inserción del dashboard. "
            "No se guardaron cambios."
        )

    html = html.replace(
        insertion_point,
        panel + "\n" + insertion_point,
        1,
    )

    DASHBOARD_PATH.write_text(html, encoding="utf-8")
    print(f"Resumen de CodeQL añadido: {DASHBOARD_PATH}")

    if alerts is None:
        print("ADVERTENCIA: no hay un JSON de alertas válido.")
    else:
        print(f"Alertas de CodeQL recibidas: {len(alerts)}")


if __name__ == "__main__":
    main()
