"""
Módulo de geração de relatórios DevSecOps.
Gera relatórios detalhados em diversos formatos (Markdown, HTML, PDF) com análises
de segurança, métricas e recomendações.
"""

import json
import yaml
import datetime
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import matplotlib.pyplot as plt
# seaborn is optional for nicer charts; load dynamically via importlib to avoid static import errors
import importlib
try:
    sns = importlib.import_module("seaborn")  # optional
except Exception:
    sns = None
import base64
import io
import shutil
import subprocess
import tempfile
import asyncio

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SecurityFinding:
    """Classe para armazenar informações sobre vulnerabilidades encontradas"""
    severity: str
    title: str
    description: str
    recommendation: str
    tool: str
    location: str
    confidence: str = "MEDIUM"
    references: Optional[List[str]] = None


# Traduções mínimas para internacionalização (pt / en)
TRANSLATIONS = {
    "pt": {
        "report_title": "Relatório DevSecOps",
        "date": "Data",
        "executive_summary": "Sumário Executivo",
        "metrics": "Métri cas Principais",
        "severity_analysis": "Análise de Severidade",
        "recommendations": "Recomendações",
        "next_steps": "Próximos Passos",
        "critical_findings": "Problemas Críticos",
        "warnings": "Avisos",
        "suggestions": "Sugestões"
    },
    "en": {
        "report_title": "DevSecOps Report",
        "date": "Date",
        "executive_summary": "Executive Summary",
        "metrics": "Key Metrics",
        "severity_analysis": "Severity Analysis",
        "recommendations": "Recommendations",
        "next_steps": "Next Steps",
        "critical_findings": "Critical Findings",
        "warnings": "Warnings",
        "suggestions": "Suggestions"
    }
}

# Carrega traduções externas se existirem em data/i18n/*.yml
try:
    BASE = Path(__file__).resolve().parents[1]
    I18N_DIR = BASE / "data" / "i18n"
    if I18N_DIR.exists():
        for lang_file in I18N_DIR.glob("*.yml"):
            try:
                with open(lang_file, 'r', encoding='utf-8') as f:
                    loaded = yaml.safe_load(f)
                lang = lang_file.stem
                if isinstance(loaded, dict):
                    TRANSLATIONS[lang] = TRANSLATIONS.get(lang, {})
                    TRANSLATIONS[lang].update(loaded)
                    logger.info(f"Carregadas traduções externas: {lang_file}")
            except Exception as e:
                logger.warning(f"Falha ao carregar {lang_file}: {e}")
except Exception:
    # Não é crítico — continuar com traduções embutidas
    pass

class DevSecOpsReport:
    """Classe principal para geração de relatórios DevSecOps"""
    
    def __init__(self, project_name: str, locale: str = "pt"):
        self.project_name = project_name
        self.locale = locale if locale in TRANSLATIONS else "pt"
        self.date = datetime.datetime.now()
        self.findings: List[SecurityFinding] = []
        self.metrics: Dict[str, Union[int, float, str]] = {}
        self.summaries: Dict[str, str] = {}
        
    def add_finding(self, finding: SecurityFinding) -> None:
        """Adiciona uma descoberta de segurança ao relatório"""
        self.findings.append(finding)
        
    def add_metric(self, name: str, value: Union[int, float, str]) -> None:
        """Adiciona uma métrica ao relatório"""
        self.metrics[name] = value
        
    def add_summary(self, section: str, content: str) -> None:
        """Adiciona um resumo de seção ao relatório"""
        self.summaries[section] = content

    def _t(self, key: str) -> str:
        """Retorna a string traduzida para a chave dada, conforme o locale."""
        return TRANSLATIONS.get(self.locale, TRANSLATIONS["pt"]).get(key, key)

    def _generate_severity_chart(self) -> str:
        """Gera gráfico de severidade das vulnerabilidades"""
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for finding in self.findings:
            if finding.severity.upper() in severity_counts:
                severity_counts[finding.severity.upper()] += 1
        plt.figure(figsize=(10, 6))
        colors = ['darkred', 'red', 'orange', 'yellow']
        labels = list(severity_counts.keys())
        values = list(severity_counts.values())
        plt.bar(labels, values, color=colors)
        plt.title(self._t('severity_analysis'))
        plt.xlabel(self._t('metrics'))
        plt.ylabel(self._t('date'))

        # Converter gráfico para base64
        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight')
        plt.close()
        img.seek(0)
        return base64.b64encode(img.getvalue()).decode()

    def to_markdown(self, output_path: Union[str, Path]) -> str:
        """Gera relatório em formato Markdown"""
        sections = []
        # Cabeçalho
        sections.append(f"# {self._t('report_title')}: {self.project_name}")
        sections.append(f"\n{self._t('date')}: {self.date.strftime('%d/%m/%Y %H:%M:%S')}")

        # Sumário executivo
        sections.append(f"\n## 📊 {self._t('executive_summary')}")
        if "executive_summary" in self.summaries:
            sections.append(self.summaries["executive_summary"])

        # Métricas
        sections.append(f"\n## 📈 {self._t('metrics')}")
        for name, value in self.metrics.items():
            sections.append(f"- **{name}**: {value}")

        # Gráfico de severidade
        sections.append(f"\n## 📊 {self._t('severity_analysis')}")
        chart_b64 = self._generate_severity_chart()
        sections.append(f"\n![Gráfico de Severidade](data:image/png;base64,{chart_b64})")

        # Achados por severidade
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            findings = [f for f in self.findings if f.severity.upper() == severity]
            if findings:
                sections.append(f"\n## {severity} Findings")
                for i, finding in enumerate(findings, 1):
                    sections.append(f"\n### {i}. {finding.title}")
                    sections.append(f"- **Descrição**: {finding.description}")
                    sections.append(f"- **Ferramenta**: {finding.tool}")
                    sections.append(f"- **Localização**: {finding.location}")
                    sections.append(f"- **Recomendação**: {finding.recommendation}")
                    if finding.references:
                        sections.append("- **Referências**:")
                        for ref in finding.references:
                            sections.append(f"  - {ref}")

        # Recomendações
        if "recommendations" in self.summaries:
            sections.append(f"\n## 💡 {self._t('recommendations')}")
            sections.append(self.summaries["recommendations"])

        # Próximos passos
        if "next_steps" in self.summaries:
            sections.append(f"\n## 🎯 {self._t('next_steps')}")
            sections.append(self.summaries["next_steps"])

        # Escrever relatório
        output_path = Path(output_path)
        output_path.write_text("\n\n".join(sections), encoding='utf-8')
        logger.info(f"Relatório Markdown gerado em: {output_path}")
        return str(output_path)

    def _render_html(self) -> str:
        """Renderiza o conteúdo do relatório como string HTML (bootstrap)"""
        chart_b64 = self._generate_severity_chart()
        html_parts = []
        html_parts.append(f"<h1>{self._t('report_title')}: {self.project_name}</h1>")
        html_parts.append(f"<p><strong>{self._t('date')}:</strong> {self.date.strftime('%d/%m/%Y %H:%M:%S')}</p>")

        html_parts.append(f"<h2>{self._t('executive_summary')}</h2>")
        if "executive_summary" in self.summaries:
            html_parts.append(f"<p>{self.summaries['executive_summary']}</p>")

        # Metrics
        html_parts.append(f"<h2>{self._t('metrics')}</h2>")
        if self.metrics:
            html_parts.append('<ul>')
            for k, v in self.metrics.items():
                html_parts.append(f"<li><strong>{k}:</strong> {v}</li>")
            html_parts.append('</ul>')

        # Chart
        html_parts.append(f"<h2>{self._t('severity_analysis')}</h2>")
        html_parts.append(f"<img src=\"data:image/png;base64,{chart_b64}\" alt=\"chart\" style=\"max-width:100%\"/>")

        # Findings
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            findings = [f for f in self.findings if f.severity.upper() == severity]
            if findings:
                html_parts.append(f"<h3>{severity} Findings</h3>")
                for i, finding in enumerate(findings, 1):
                    html_parts.append(f"<h4>{i}. {finding.title}</h4>")
                    html_parts.append(f"<p><strong>Descrição:</strong> {finding.description}</p>")
                    html_parts.append(f"<p><strong>Ferramenta:</strong> {finding.tool} — <strong>Local:</strong> {finding.location}</p>")
                    html_parts.append(f"<p><strong>Recomendação:</strong> {finding.recommendation}</p>")
                    if finding.references:
                        html_parts.append('<p><strong>Referências:</strong></p><ul>')
                        for ref in finding.references:
                            html_parts.append(f"<li><a href=\"{ref}\">{ref}</a></li>")
                        html_parts.append('</ul>')

        # Recommendations and next steps
        if "recommendations" in self.summaries:
            html_parts.append(f"<h2>{self._t('recommendations')}</h2>")
            html_parts.append(f"<p>{self.summaries['recommendations']}</p>")

        if "next_steps" in self.summaries:
            html_parts.append(f"<h2>{self._t('next_steps')}</h2>")
            html_parts.append(f"<p>{self.summaries['next_steps']}</p>")

        body = '\n'.join(html_parts)
        html = f"""
        <!doctype html>
        <html lang="{self.locale}">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
          <title>{self._t('report_title')}</title>
        </head>
        <body class="container my-4">
        {body}
        </body>
        </html>
        """
        return html

    def to_html(self, output_path: Union[str, Path]) -> str:
        """Gera relatório em formato HTML com estilo Bootstrap"""
        html = self._render_html()
        outp = Path(output_path)
        outp.write_text(html, encoding='utf-8')
        logger.info(f"Relatório HTML gerado em: {outp}")
        return str(outp)

    # removed duplicate stub of to_html

    def to_pdf(self, output_path: Union[str, Path]) -> str:
        """Gera relatório em formato PDF usando WeasyPrint"""
        # Primeiro gera HTML e depois converte para PDF (WeasyPrint)
        html = self._render_html()
        outp = Path(output_path)
        try:
            import importlib
            weasyprint = importlib.import_module('weasyprint')
            HTML = getattr(weasyprint, 'HTML')
        except Exception:
            logger.info("WeasyPrint não encontrado — tentando fallback wkhtmltopdf / Chromium...")

            # 1) Tentar wkhtmltopdf
            wk = shutil.which('wkhtmltopdf')
            if wk:
                try:
                    # grava HTML temporário
                    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html', encoding='utf-8') as tmp:
                        tmp.write(html)
                        tmp_path = tmp.name
                    cmd = [wk, tmp_path, str(outp)]
                    subprocess.run(cmd, check=True)
                    logger.info(f"Relatório PDF gerado via wkhtmltopdf em: {outp}")
                    try:
                        Path(tmp_path).unlink()
                    except Exception:
                        pass
                    return str(outp)
                except Exception as e:
                    logger.error(f"wkhtmltopdf falhou: {e}")

            # 2) Tentar Chromium via pyppeteer
            chromium_exe = shutil.which('chromium') or shutil.which('chrome') or shutil.which('chromium-browser') or shutil.which('msedge')
            try:
                pyppeteer = importlib.import_module('pyppeteer')
            except Exception:
                pyppeteer = None

            if pyppeteer and chromium_exe:
                async def _render_with_pyppeteer(html_str: str, out_path: str):
                    # escreve arquivo temporário e carrega via file://
                    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html', encoding='utf-8') as tmp:
                        tmp.write(html_str)
                        tmp_path = tmp.name
                    browser = await pyppeteer.launch({'executablePath': chromium_exe, 'args': ['--no-sandbox']})
                    try:
                        page = await browser.newPage()
                        await page.goto('file://' + tmp_path)
                        await page.pdf({'path': out_path, 'format': 'A4'})
                    finally:
                        await browser.close()
                        try:
                            Path(tmp_path).unlink()
                        except Exception:
                            pass

                try:
                    asyncio.get_event_loop()
                except RuntimeError:
                    asyncio.set_event_loop(asyncio.new_event_loop())

                try:
                    asyncio.get_event_loop().run_until_complete(_render_with_pyppeteer(html, str(outp)))
                    logger.info(f"Relatório PDF gerado via Chromium/pyppeteer em: {outp}")
                    return str(outp)
                except Exception as e:
                    logger.error(f"Falha ao gerar PDF via pyppeteer: {e}")

            # Nenhum método disponível
            msg = ("Nenhum gerador de PDF disponível (WeasyPrint/wkhtmltopdf/pyppeteer+Chromium). "
                   "Instale um deles ou gere HTML via to_html() e converta manualmente.")
            logger.error(msg)
            raise RuntimeError(msg)

        # Se WeasyPrint estava disponível, usar normalmente
        try:
            HTML(string=html).write_pdf(str(outp))
            logger.info(f"Relatório PDF gerado em: {outp}")
            return str(outp)
        except Exception as e:
            logger.error(f"Erro ao gerar PDF com WeasyPrint: {e}")
            raise

    def export_json(self, output_path: Union[str, Path]) -> str:
        """Exporta dados do relatório em formato JSON"""
        data = {
            "project_name": self.project_name,
            "date": self.date.isoformat(),
            "findings": [vars(f) for f in self.findings],
            "metrics": self.metrics,
            "summaries": self.summaries
        }
        
        output_path = Path(output_path)
        output_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        logger.info(f"Dados JSON exportados para: {output_path}")
        return str(output_path)

def create_report(
    project_name: str,
    findings: List[Dict],
    metrics: Dict[str, Union[int, float, str]],
    summaries: Dict[str, str],
    output_dir: Union[str, Path],
    locale: str = "pt"
) -> DevSecOpsReport:
    """
    Função auxiliar para criar um relatório completo
    
    Args:
        project_name: Nome do projeto
        findings: Lista de descobertas de segurança
        metrics: Métricas do projeto
        summaries: Resumos das seções
        output_dir: Diretório de saída
    
    Returns:
        DevSecOpsReport: Instância do relatório gerado
    """
    report = DevSecOpsReport(project_name, locale=locale)
    
    # Adicionar findings
    for f in findings:
        finding = SecurityFinding(**f)
        report.add_finding(finding)
    
    # Adicionar métricas
    for name, value in metrics.items():
        report.add_metric(name, value)
    
    # Adicionar resumos
    for section, content in summaries.items():
        report.add_summary(section, content)
    
    # Criar diretório de saída
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Gerar relatórios em diferentes formatos
    report.to_markdown(output_dir / "report.md")
    report.to_html(output_dir / "report.html")
    report.to_pdf(output_dir / "report.pdf")
    report.export_json(output_dir / "report.json")
    
    return report
