
import json
from pathlib import Path

CURRENT = Path("reports/report.json")
BASELINE = Path("reports/baseline.json")
OUTPUT = Path("reports/comparacion.md")


def load_alerts(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    alerts = set()

    for site in sites:
        if not isinstance(site, dict):
            continue

        for alert in site.get("alerts", []):
            if not isinstance(alert, dict):
                continue

            name = alert.get("name", "Alerta sin nombre")
            risk = alert.get("riskcode", "-1")
            alerts.add((str(name), str(risk)))

    return alerts


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    if not CURRENT.is_file():
        OUTPUT.write_text(
            "# Comparación de análisis\n\n"
            "No se encontró reports/report.json.\n",
            encoding="utf-8",
        )
        return

    current = load_alerts(CURRENT)

    lines = [
        "# Comparación de análisis de seguridad",
        "",
        f"- Alertas únicas actuales: **{len(current)}**",
        "",
    ]

    if not BASELINE.is_file():
        lines.extend([
            "## Primera ejecución",
            "",
            "No existe un análisis anterior para comparar.",
            "Guarda un report.json anterior como "
            "`reports/baseline.json` y vuelve a ejecutar.",
            "",
        ])
    else:
        previous = load_alerts(BASELINE)
        new = sorted(current - previous)
        resolved = sorted(previous - current)
        ongoing = sorted(current & previous)

        lines.extend([
            "## Resumen",
            "",
            f"- Nuevas: **{len(new)}**",
            f"- Ya no aparecen: **{len(resolved)}**",
            f"- Continúan: **{len(ongoing)}**",
            "",
        ])

        def add_section(title, items):
            lines.extend([f"## {title}", ""])
            if not items:
                lines.extend(["Ninguna alerta.", ""])
                return

            for name, risk in items:
                lines.append(f"- {name} (riskcode: {risk})")
            lines.append("")

        add_section("Alertas nuevas", new)
        add_section("Alertas que ya no aparecen", resolved)
        add_section("Alertas que continúan", ongoing)

        lines.extend([
            "## Nota",
            "",
            "La comparación usa el nombre y el código de riesgo. "
            "Los cambios de nombre o severidad pueden aparecer "
            "como una alerta nueva y otra desaparecida.",
            "La ausencia de una alerta no demuestra por sí sola "
            "que el problema esté corregido.",
            "",
        ])

    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Comparación generada: {OUTPUT}")


if __name__ == "__main__":
    main()
