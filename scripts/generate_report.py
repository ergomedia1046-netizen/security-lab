
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

def clean(value):
    """Convierte valores a texto seguro para el informe Markdown."""
    if value is None:
        return "No disponible"
    return str(value).replace("\r", " ").strip() or "No disponible"

def main():
    REPORTS.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if not JSON_FILE.exists():
        OUTPUT_FILE.write_text(
            "# Informe de seguridad\n\n"
            "No se encontró `report.json`. "
            "Revisa los registros de ejecución de ZAP.\n",
            encoding="utf-8",
        )
        return

    try:
        data = json.loads(JSON_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        OUTPUT_FILE.write_text(
            "# Informe de seguridad\n\n"
            f"No se pudo leer el JSON: {clean(exc)}\n",
            encoding="utf-8",
        )
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
        for alert in site.get("alerts", []):
            if isinstance(alert, dict):
                alert["_site"] = clean(site.get("@name", "No disponible"))
                alerts.append(alert)

    counts = Counter()
    for alert in alerts:
        risk = str(alert.get("riskcode", "-1"))
        counts[RISK_LABELS.get(risk, "Sin clasificar")] += 1

    lines = [
        "# Informe técnico de seguridad",
        "",
        f"- **Generado:** {generated}",
        "- **Herramienta:** OWASP ZAP",
        "- **Entorno:** laboratorio autorizado",
        "- **Alcance:** resultados del análisis automatizado; "
        "no constituye una auditoría exhaustiva.",
        "",
        "## 1. Resumen ejecutivo",
        "",
        f"- **Alertas registradas:** {len(alerts)}",
        f"- **Altas:** {counts['Alto']}",
        f"- **Medias:** {counts['Medio']}",
        f"- **Bajas:** {counts['Bajo']}",
        f"- **Informativas:** {counts['Informativo']}",
        "",
        "Las alertas automáticas requieren validación manual. "
        "La cantidad de alertas no equivale necesariamente a la "
        "cantidad de vulnerabilidades confirmadas.",
        "",
        "## 2. Hallazgos",
        "",
    ]

    if not alerts:
        lines.append(
            "No se encontraron alertas en el JSON. "
            "Confirma que el análisis se completó correctamente."
        )

    for index, alert in enumerate(
        sorted(
            alerts,
            key=lambda a: int(a.get("riskcode", -1))
            if str(a.get("riskcode", "-1")).lstrip("-").isdigit()
            else -1,
            reverse=True,
        ),
        start=1,
    ):
        risk = str(alert.get("riskcode", "-1"))
        severity = RISK_LABELS.get(risk, "Sin clasificar")
        name = clean(alert.get("name"))
        lines.extend([
            f"### {index}. {name}",
            "",
            f"- **Severidad reportada:** {severity}",
            f"- **Sitio:** {alert['_site']}",
            f"- **Confianza:** {clean(alert.get('confidence'))}",
            "",
            "**Descripción**",
            "",
            clean(alert.get("desc", "Sin descripción")),
            "",
            "**Recomendación de ZAP**",
            "",
            clean(alert.get("solution", "Revisar la configuración y validar el hallazgo")),
            "",
        ])

        instances = alert.get("instances", [])
        if isinstance(instances, list) and instances:
            lines.extend(["**Evidencias y ubicaciones (máximo 5)**", ""])
            for instance in instances[:5]:
                if not isinstance(instance, dict):
                    continue
                lines.append(
                    f"- URL: `{clean(instance.get('uri'))}`; "
                    f"método: `{clean(instance.get('method'))}`; "
                    f"parámetro: `{clean(instance.get('param'))}`"
                )
                evidence = instance.get("evidence")
                if evidence:
                    lines.append(f"  - Evidencia: `{clean(evidence)[:500]}`")
            lines.append("")

        reference = alert.get("reference")
        if reference:
            lines.extend(["**Referencias**", "", clean(reference), ""])

    lines.extend([
        "## 3. Limitaciones",
        "",
        "- ZAP Baseline se centra principalmente en comprobaciones pasivas.",
        "- Los resultados pueden incluir falsos positivos.",
        "- No se ha confirmado manualmente cada hallazgo.",
        "- Este informe no demuestra que el sistema sea seguro o inseguro "
        "en todos sus componentes.",
        "",
        "## 4. Próximos pasos",
        "",
        "1. Priorizar los hallazgos de severidad alta y media.",
        "2. Revisar evidencias, configuración y recomendaciones.",
        "3. Validar los hallazgos manualmente dentro del laboratorio.",
        "4. Repetir el análisis después de aplicar correcciones.",
        "",
    ])

    OUTPUT_FILE.write_text("\n".join(lines), encoding="utf-8")
    print(f"Informe creado: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
