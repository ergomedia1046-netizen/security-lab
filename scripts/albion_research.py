
import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

OUTPUT = Path("albion-research")
OUTPUT.mkdir(parents=True, exist_ok=True)

SOURCES = [
    {
        "title": "Albion Online - FAQ oficial",
        "url": "https://albiononline.com/frequently-asked-questions",
        "purpose": "Información oficial y canales de soporte."
    },
    {
        "title": "Guía oficial de problemas técnicos",
        "url": (
            "https://forum.albiononline.com/index.php/"
            "Thread/219999-Common-Technical-Issues-Troubleshooting-Guide/"
        ),
        "purpose": "Diagnóstico de lag, desconexiones y problemas del cliente."
    },
    {
        "title": "Registro de incidencias de conexión",
        "url": (
            "https://forum.albiononline.com/index.php/"
            "Thread/209365-Connection-Issues-Hub-Known-Problems-Player-Reports/"
        ),
        "purpose": "Incidencias de conexión comunicadas públicamente."
    },
]


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "svg"):
            self.skip_depth += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "svg"):
            self.skip_depth = max(0, self.skip_depth - 1)

    def handle_data(self, data):
        if self.skip_depth == 0:
            text = " ".join(data.split())
            if text:
                self.parts.append(text)


def fetch_source(source):
    request = urllib.request.Request(
        source["url"],
        headers={"User-Agent": "Mozilla/5.0 (compatible; ResearchBot/1.0)"},
    )

    result = {
        **source,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "status": "error",
        "text_excerpt": "",
        "error": None,
    }

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type.lower():
                raise ValueError("La respuesta no es una página HTML.")

            raw = response.read(1_000_000)
            html = raw.decode("utf-8", errors="replace")

        parser = TextExtractor()
        parser.feed(html)

        result["text_excerpt"] = " ".join(parser.parts)[:7000]
        result["status"] = "ok"

    except urllib.error.HTTPError as exc:
        result["error"] = f"HTTP {exc.code}: {exc.reason}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:400]}"

    return result


def analyze_with_gemini(sources):
    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

    if not api_key:
        return {
            "status": "skipped",
            "reason": "GEMINI_API_KEY no está disponible en el entorno."
        }

    evidence = []
    for source in sources:
        item = {
            "title": source["title"],
            "url": source["url"],
            "purpose": source["purpose"],
            "retrieval_status": source["status"],
        }

        if source["text_excerpt"]:
            item["retrieved_text"] = source["text_excerpt"]

        if source["error"]:
            item["retrieval_error"] = source["error"]

        evidence.append(item)

    prompt = """
Actúa como analista técnico defensivo de Albion Online.

Analiza la información suministrada en español. Separa:
1. Hechos presentes en la evidencia.
2. Hipótesis que aún no están verificadas.
3. Información que falta.
4. Próximas pruebas defensivas, autorizadas y reproducibles.

El objetivo es investigar problemas de latencia, pérdida de paquetes,
sincronización y posibles problemas de seguridad del servidor Americas.

IMPORTANTE:
- No inventes hechos, citas, incidentes ni detalles de infraestructura.
- Las URL son referencias, no prueba de que su contenido haya sido leído.
- Si una página devolvió 403, declara que no se pudo consultar.
- No concluyas que existe una vulnerabilidad por un pico de ping.
- No propongas atacar, saturar ni eludir protecciones del servidor.
- Explica que las mediciones de GitHub Actions no representan
  la conexión del ordenador del usuario.
- Si la evidencia es insuficiente, indícalo expresamente.

Referencias y evidencia:
""" + json.dumps(evidence, ensure_ascii=False)

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        + model
        + ":generateContent"
    )

    payload = {
        "contents": [
            {"parts": [{"text": prompt}]}
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 4000,
        },
    }

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            data = json.loads(response.read().decode("utf-8"))

        text = data["candidates"][0]["content"]["parts"][0]["text"]

        return {
            "status": "ok",
            "model": model,
            "analysis": text,
        }

    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")[:1500]
        return {
            "status": "error",
            "model": model,
            "reason": f"Gemini HTTP {exc.code}: {details}",
        }
    except Exception as exc:
        return {
            "status": "error",
            "model": model,
            "reason": f"{type(exc).__name__}: {str(exc)[:1000]}",
        }


def main():
    print("Recopilando referencias públicas...")

    sources = [fetch_source(source) for source in SOURCES]

    for source in sources:
        print(f'{source["status"]}: {source["title"]}')
        if source["error"]:
            print(f'  Motivo: {source["error"]}')

    print("Probando el análisis de Gemini por separado...")
    ai = analyze_with_gemini(sources)
    print(f'Estado de Gemini: {ai["status"]}')

    if ai.get("reason"):
        print(f'Motivo de Gemini: {ai["reason"]}')

    report = {
        "project": "Albion Online Research",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "Investigación pública y análisis defensivo",
        "sources": sources,
        "ai_analysis": ai,
        "limitations": [
            "Una URL registrada no significa que su contenido se haya verificado.",
            "Las páginas que devuelven 403 no se consideran consultadas.",
            "No se ha medido la conexión del ordenador del usuario.",
            "No se han realizado pruebas contra servidores del juego.",
            "No se ha confirmado ninguna vulnerabilidad."
        ]
    }

    (OUTPUT / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Investigación de Albion Online",
        "",
        f'Generado: {report["generated_at"]}',
        "",
        "## Fuentes",
        "",
    ]

    for source in sources:
        lines.extend([
            f'### {source["title"]}',
            f'- URL: {source["url"]}',
            f'- Propósito: {source["purpose"]}',
            f'- Estado de consulta: {source["status"]}',
        ])
        if source["error"]:
            lines.append(f'- Error: {source["error"]}')
        if source["text_excerpt"]:
            lines.extend(["", source["text_excerpt"]])
        lines.append("")

    lines.extend(["## Análisis de Gemini", ""])
    if ai.get("status") == "ok":
        lines.append(ai["analysis"])
    else:
        lines.append(
            "No se completó el análisis: "
            + ai.get("reason", "motivo desconocido")
        )

    lines.extend(["", "## Limitaciones", ""])
    lines.extend(f"- {item}" for item in report["limitations"])

    (OUTPUT / "report.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print("Informes generados:")
    print("  albion-research/report.json")
    print("  albion-research/report.md")


if __name__ == "__main__":
    main()
