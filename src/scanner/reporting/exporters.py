import json
import os
from abc import ABC, abstractmethod
from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import Any
from .models import Report

class ReportExporterInterface(ABC):
    """Base interface for all report exporters."""
    
    @abstractmethod
    async def export(self, report: Report, output_path: str) -> str:
        """Export the report to the target path and return the final path."""
        pass

class JSONExporter(ReportExporterInterface):
    """Exports the report as a native JSON structure."""
    
    async def export(self, report: Report, output_path: str) -> str:
        os.makedirs(output_path, exist_ok=True)
        json_data = report.model_dump_json(indent=4)
        
        target_file = os.path.join(output_path, "report.json")
        if os.path.exists(target_file):
            try:
                os.remove(target_file)
            except Exception:
                pass

        with open(target_file, "w", encoding="utf-8") as f:
            f.write(json_data)
            
        return target_file

class SARIFExporter(ReportExporterInterface):
    """Exports the report in the Static Analysis Results Interchange Format (SARIF)."""
    
    async def export(self, report: Report, output_path: str) -> str:
        os.makedirs(output_path, exist_ok=True)
        results = []
        for finding in report.findings:
            level = "none"
            if finding.severity.value in ["High", "Critical"]:
                level = "error"
            elif finding.severity.value == "Medium":
                level = "warning"
            elif finding.severity.value == "Low":
                level = "note"
                
            result = {
                "ruleId": finding.plugin_id,
                "level": level,
                "message": {
                    "text": finding.title
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.endpoint
                        }
                    }
                }]
            }
            results.append(result)
            
        sarif_doc = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Enterprise Security Scanner",
                            "version": report.metadata.scanner_version,
                            "informationUri": "https://example.com/scanner"
                        }
                    },
                    "results": results
                }
            ]
        }
        
        target_file = os.path.join(output_path, "report.sarif")
        if os.path.exists(target_file):
            try:
                os.remove(target_file)
            except Exception:
                pass

        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=4)
            
        return target_file

class MarkdownExporter(ReportExporterInterface):
    """Exports a beautiful markdown executive summary using Jinja2."""
    
    def __init__(self, template_dir: str):
        self.env = Environment(loader=FileSystemLoader(template_dir))
        
    async def export(self, report: Report, output_path: str) -> str:
        if os.path.isdir(output_path) or not output_path.lower().endswith(".md"):
            os.makedirs(output_path, exist_ok=True)
            target_file = os.path.join(output_path, "report.md")
        else:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            target_file = output_path

        template = self.env.get_template("executive_report.md.j2")
        rendered = template.render(report=report)

        if os.path.exists(target_file) and not os.path.isdir(target_file):
            try:
                os.remove(target_file)
            except Exception:
                pass

        with open(target_file, "w", encoding="utf-8") as f:
            f.write(rendered)

        return target_file

class HTMLExporter(ReportExporterInterface):
    """Exports a highly professional HTML report using Jinja2 templates."""

    def __init__(self, template_dir: str):
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

    async def export(self, report: Report, output_path: str) -> str:
        os.makedirs(output_path, exist_ok=True)
        template = self.env.get_template("executive_report.html.j2")
        rendered = template.render(report=report)

        target_file = os.path.join(output_path, "report.html")
        if os.path.exists(target_file):
            try:
                os.remove(target_file)
            except Exception:
                pass

        with open(target_file, "w", encoding="utf-8") as f:
            f.write(rendered)

        return target_file

class PDFExporter(ReportExporterInterface):
    """Exports a professional PDF report by rendering to HTML first, then printing via Playwright."""

    def __init__(self, browser_manager: Any, html_exporter: HTMLExporter):
        self.browser_manager = browser_manager
        self.html_exporter = html_exporter

    async def export(self, report: Report, output_path: str) -> str:
        os.makedirs(output_path, exist_ok=True)
        html_path = await self.html_exporter.export(report, output_path)
        pdf_path = os.path.join(output_path, "report.pdf")

        if os.path.exists(pdf_path):
            try:
                os.remove(pdf_path)
            except Exception:
                pass

        await self.browser_manager.print_pdf(html_path, pdf_path)
        return pdf_path