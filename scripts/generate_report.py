
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPORTS = Path("reports")
JSON_FILE = REPORTS / "report.json"
OUTPUT_FILE = REPORTS / "informe-tecnico.md"

RISK_LABELS = {
    "3": "Alto",
    "2": "Medio",
    "1": "Bajo",
    "0": "Informativo",
    "-1": "Sin clasificar",
}


def text(value, default="No disponible"):
    if value is None:
        return default
    result = str(value).strip()
    return result if result else default


def main():
    REPORTS.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# Informe técnico de seguridad",
        "",
        f"- **Fecha de generación:** {generated}",
        "- **Herramienta:** OWASP ZAP Baseline",
        "- **Objetivo:** OWASP Juice Shop en laboratorio aislado",
        "- **Coste de generación:** US$0; no se utiliza una API de IA",
        "",
    ]

    if not JSON_FILE.is_file():
        lines.extend([
            "## Error de entrada",
            "",
            "No se encontró `reports/report.json`.",
            "Revisa los registros del escaneo ZAP.",
        ])
        OUTPUT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Informe generado sin datos de entrada: {OUTPUT_FILE}")
        return

    try:
        data = json.loads(JSON_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        lines.extend([
            "## Error de lectura",
            "",
            f"No se pudo leer el JSON: {text(exc)}",
        ])
        OUTPUT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("No se pudo interpretar report.json.")
        return

    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        sites = []

    alerts = []
    for site in sites:
        if not isinstance(site, dict):
            continue

        site_name = text(site.get("@name"), "Sitio no identificado")
        site_alerts = site.get("alerts", [])

        if not isinstance(site_alerts, list):
            continue

        for alert in site_alerts:
            if isinstance(alert, dict):
                item = dict(alert)
                item["_site"] = site_name
                alerts.append(item)

    def risk_number(alert):
        try:
            return int(alert.get("riskcode", -1))
        except (TypeError, ValueError):
            return -1

    counts = Counter(
        RISK_LABELS.get(str(risk_number(alert)), "Sin clasificar")
        for alert in alerts
    )

    lines.extend([
        "## 1. Resumen ejecutivo",
        "",
        f"- **Alertas registradas:** {len(alerts)}",
        f"- **Altas:** {counts['Alto']}",
        f"- **Medias:** {counts['Medio']}",
        f"- **Bajas:** {counts['Bajo']}",
        f"- **Informativas:** {counts['Informativo']}",
        "",
        "Las alertas son resultados automáticos y no necesariamente "
        "vulnerabilidades confirmadas. Es necesaria una revisión manual.",
        "",
        "## 2. Hallazgos",
        "",
    ])

    if not alerts:
        lines.extend([
            "No se encontraron alertas en el JSON.",
            "Comprueba que el escaneo terminó correctamente antes "
            "de interpretar este resultado como ausencia de riesgos.",
            "",
        ])

    alerts.sort(key=risk_number, reverse=True)

    for number, alert in enumerate(alerts, start=1):
        risk = str(risk_number(alert))
        severity = RISK_LABELS.get(risk, "Sin clasificar")

        lines.extend([
            f"### {number}. {text(alert.get('name'))}",
            "",
            f"- **Severidad:** {severity}",
            f"- **Sitio:** {text(alert.get('_site'))}",
            f"- **Confianza reportada:** {text(alert.get('confidence'))}",
            "",
            "**Descripción**",
            "",
            text(alert.get("desc"), "ZAP no proporcionó una descripción."),
            "",
            "**Recomendación**",
            "",
            text(
                alert.get("solution"),
                "Revisar el hallazgo y validar la configuración afectada."
            ),
            "",
        ])

        instances = alert.get("instances", [])
        if isinstance(instances, list) and instances:
            lines.extend(["**Ubicaciones y evidencias**", ""])

            for instance in instances[:5]:
                if not isinstance(instance, dict):
                    continue

                uri = text(instance.get("uri"))
                method = text(instance.get("method"))
                param = text(instance.get("param"))

                lines.append(
                    f"- URL: `{uri}`; método: `{method}`; parámetro: `{param}`"
                )

                evidence = instance.get("evidence")
                if evidence:
                    lines.append(f"  - Evidencia: `{text(evidence)[:300]}`")

            if len(instances) > 5:
                lines.append(
                    f"- Se omitieron {len(instances) - 5} ubicaciones adicionales."
                )

            lines.append("")

        reference = alert.get("reference")
        if reference:
            lines.extend([
                "**Referencias**",
                "",
                text(reference),
                "",
            ])

    lines.extend([
        "## 3. Limitaciones",
        "",
        "- El escaneo Baseline se centra principalmente en comprobaciones pasivas.",
        "- Puede haber falsos positivos o problemas no detectados.",
        "- Los resultados no sustituyen una auditoría de seguridad completa.",
        "- No se realizaron pruebas contra sistemas de terceros.",
        "",
        "## 4. Próximos pasos",
        "",
        "1. Revisar primero los hallazgos de severidad alta y media.",
        "2. Validar manualmente cada hallazgo dentro del laboratorio.",
        "3. Corregir los problemas confirmados.",
        "4. Repetir el escaneo y comparar los resultados.",
        "",
        "---",
        "",
        "Informe generado automáticamente mediante Python. "
        "Este generador no utiliza un modelo de IA.",
        "",
    ])

    OUTPUT_FILE.write_text("\n".join(lines), encoding="utf-8")
    print(f"Informe generado correctamente: {OUTPUT_FILE}")
    print(f"Total de alertas procesadas: {len(alerts)}")


if __name__ == "__main__":
    main()
