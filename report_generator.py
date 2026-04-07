from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import html
from colorama import init, Fore, Back, Style
from pydantic import BaseModel, Field, field_validator
import click

init(autoreset=True)


class Severity(str, click.Choice):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls(value.lower())


class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity = Field(default=Severity.INFO)
    category: str
    recommendation: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: click.get_current_context().timestamp.isoformat() if click.get_current_context().exists else None)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        if not v:
            import datetime
            v = datetime.datetime.now().isoformat()
        return v


class AuditReport(BaseModel):
    report_id: str
    generated_at: str
    target_environment: str
    findings: List[Finding] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)

    @field_validator("target_environment")
    @classmethod
    def validate_env(cls, v: str) -> str:
        if not v:
            raise ValueError("Target environment cannot be empty")
        return v.strip()

    @property
    def stats(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            severity = finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity).lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts[severity] = 1
        counts["total"] = len(self.findings)
        return counts


class ReportGenerator:
    @staticmethod
    def create_cli_text(report: AuditReport) -> str:
        """
        Generates a colored CLI report string for terminal output.

        Args:
            report: An instance of AuditReport containing audit findings.

        Returns:
            A formatted string ready for console display.
        """
        try:
            output = []
            output.append(f"{Style.BRIGHT}=== LOCAL DEV SENTINEL REPORT ==={Style.RESET_ALL}")
            output.append(f"Report ID: {report.report_id}")
            output.append(f"Target: {report.target_environment}")
            output.append(f"Generated: {report.generated_at}")
            output.append("-" * 50)

            stats = report.stats
            output.append(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
            output.append(f"  Total Findings: {stats['total']}")
            output.append(f"  Critical: {Fore.RED}{stats['critical']}{Style.RESET_ALL}")
            output.append(f"  High: {Fore.YELLOW}{stats['high']}{Style.RESET_ALL}")
            output.append(f"  Medium: {Fore.GREEN}{stats['medium']}{Style.RESET_ALL}")
            output.append(f"  Low: {Fore.BLUE}{stats['low']}{Style.RESET_ALL}")
            output.append(f"  Info: {Fore.WHITE}{stats['info']}{Style.RESET_ALL}")
            output.append("-" * 50)
            output.append(f"{Style.BRIGHT}FINDINGS:{Style.RESET_ALL}")

            for finding in report.findings:
                if finding.severity == Severity.CRITICAL:
                    color = Fore.RED
                elif finding.severity == Severity.HIGH:
                    color = Fore.YELLOW
                elif finding.severity == Severity.MEDIUM:
                    color = Fore.GREEN
                elif finding.severity == Severity.LOW:
                    color = Fore.BLUE
                else:
                    color = Fore.WHITE

                output.append(f"{color}[{finding.severity.value.upper()}] {finding.title}{Style.RESET_ALL}")
                output.append(f"  Category: {finding.category}")
                output.append(f"  ID: {finding.id}")
                output.append(f"  Desc: {finding.description}")
                if finding.recommendation:
                    output.append(f"  Fix: {finding.recommendation}")
                output.append("")

            output.append(f"{Style.BRIGHT}=== END OF REPORT ==={Style.RESET_ALL}")
            return "\n".join(output)

        except Exception as e:
            return f"Error generating CLI report: {str(e)}"

    @staticmethod
    def create_html_report(report: AuditReport) -> str:
        """
        Generates an HTML report string for browser viewing.

        Args:
            report: An instance of AuditReport containing audit findings.

        Returns:
            A formatted HTML string.
        """
        try:
            stats = report.stats
            findings_html = []

            for finding in report.findings:
                severity_color = "gray"
                if finding.severity == Severity.CRITICAL:
                    severity_color = "red"
                elif finding.severity == Severity.HIGH:
                    severity_color = "orange"
                elif finding.severity == Severity.MEDIUM:
                    severity_color = "green"
                elif finding.severity == Severity.LOW:
                    severity_color = "blue"

                finding_html = f"""
                <div class="finding">
                    <div class="severity-bar" style="background-color: {severity_color};"></div>
                    <h3>{html.escape(finding.title)}</h3>
                    <p><strong>Severity:</strong> <span style="color: {severity_color};">{html.escape(finding.severity.value)}</span></p>
                    <p><strong>Description:</strong> {html.escape(finding.description)}</p>
                    <p><strong>Recommendation:</strong> {html.escape(finding.recommendation or "None provided")}</p>
                </div>
                """
                findings_html.append(finding_html)

            body_html = "\n".join(findings_html)
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Local Dev Sentinel Report</title>
                <style>
                    body {{ font-family: sans-serif; padding: 20px; }}
                    .finding {{ border-left: 5px solid; padding: 10px; margin-bottom: 10px; border-left-color: gray; }}
                    .summary {{ background: #f4f4f4; padding: 15px; margin-bottom: 20px; }}
                    .critical {{ color: red; }} .high {{ color: orange; }}
                    .medium {{ color: green; }} .low {{ color: blue; }}
                </style>
            </head>
            <body>
                <h1>Local Dev Sentinel Report</h1>
                <div class="summary">
                    <p><strong>Environment:</strong> {html.escape(report.target_environment)}</p>
                    <p><strong>Generated:</strong> {html.escape(report.generated_at)}</p>
                    <p><strong>Total Findings:</strong> {stats['total']}</p>
                </div>
                <h2>Findings</h2>
                {body_html}
            </body>
            </html>
            """
            return html_content
        except Exception as e:
            return f"<html><body>Error generating HTML: {html.escape(str(e))}</body></html>"

    @staticmethod
    def create_json_report(report: AuditReport) -> str:
        """
        Generates a structured JSON report string for programmatic integration.

        Args:
            report: An instance of AuditReport containing audit findings.

        Returns:
            A formatted JSON string.
        """
        try:
            data = report.model_dump(mode="json")
            data["summary"] = data.get("stats", data.get("summary", {}))
            return json.dumps(data, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)

    @staticmethod
    def save_report(report: AuditReport, output_path: Path, format_type: str) -> Path:
        """
        Saves the generated report to a file.

        Args:
            report: An instance of AuditReport.
            output_path: The destination Path for the file.
            format_type: The file format ('cli', 'html', 'json').

        Returns:
            The Path object of the saved file.

        Raises:
            ValueError: If an unsupported format type is provided.
        """
        try:
            output_path = Path(output_path).expanduser().resolve()
            if not output_path.parent.exists():
                output_path.parent.mkdir(parents=True, exist_ok=True)

            content = ""
            if format_type == "cli":
                content = ReportGenerator.create_cli_text(report)
                extension = ".txt"
            elif format_type == "html":
                content = ReportGenerator.create_html_report(report)
                extension = ".html"
            elif format_type == "json":
                content = ReportGenerator.create_json_report(report)
                extension = ".json"
            else:
                raise ValueError(f"Unsupported format type: {format_type}. Valid options: cli, html, json.")

            output_path = output_path.with_suffix(extension)
            with open(output_path, "w", encoding="utf-8") as file:
                file.write(content)

            return output_path
        except PermissionError:
            raise PermissionError(f"Permission denied when saving report to {output_path}")
        except OSError as e:
            raise RuntimeError(f"File system error occurred while saving report: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error during report generation: {str(e)}")

    @staticmethod
    def validate_format(format_type: str) -> str:
        """
        Validates the format type string using click.Choice for CLI integration support.

        Args:
            format_type: The string representation of the desired format.

        Returns:
            The validated format type string.
        """
        try:
            click_type = click.Choice(choices=["cli", "html", "json"])
            click_type.convert(format_type, None, None)
            return format_type
        except click.BadParameter:
            raise ValueError(f"Invalid format: {format_type}. Must be one of cli, html, json.")