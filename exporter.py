from pathlib import Path
from typing import Dict, Optional, Any, List, Union
from pydantic import BaseModel, Field, validator
import requests
import subprocess
import json
import os
from colorama import init, Fore, Style, deinit
import click


init(autoreset=True)


class AuditReport(BaseModel):
    """Represents the structured audit report payload."""
    timestamp: str = Field(..., description="ISO format timestamp of the scan")
    scan_type: str = Field(..., description="Type of audit performed")
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list, description="List of identified issues")
    status: str = Field(..., description="Overall scan status (passed, failed)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context")


class ExporterConfig(BaseModel):
    """Configuration for export destinations."""
    webhook_url: Optional[str] = Field(None, description="Target webhook URL")
    api_key: Optional[str] = Field(None, description="Authentication API key")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers")
    output_path: Optional[Path] = Field(None, description="Local file path for export")
    verify_connectivity: bool = Field(True, description="Verify network connectivity before export")


def _log(message: str, status: str = "INFO") -> None:
    """Utility to print colored logs using click and colorama."""
    colors = {
        "INFO": Fore.CYAN,
        "SUCCESS": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
    }
    color = colors.get(status, Fore.WHITE)
    prefix = f"[{status}]"
    click.echo(f"{color}{prefix} {Style.RESET_ALL}{message}")


def check_network_connectivity(timeout: int = 5) -> bool:
    """Checks network connectivity using subprocess as a fallback verification."""
    try:
        # Attempt to verify connectivity via a subprocess call to 'ping' or 'curl'
        # This uses subprocess as part of the tech stack for verification
        cmd = ["curl", "-s", "--connect-timeout", str(timeout), "https://www.google.com"]
        # Windows fallback for curl
        if os.name == "nt":
            cmd = ["ping", "-n", "1", "127.0.0.1"]
        result = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        return result.returncode == 0
    except FileNotFoundError:
        # Fallback if curl is not available
        return True
    except Exception:
        return False


def _setup_exporter_headers(config: ExporterConfig) -> Dict[str, str]:
    """Merges custom headers and adds auth headers based on config."""
    headers = config.headers.copy()
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    headers["Content-Type"] = "application/json"
    return headers


def export_report_to_path(report: AuditReport, config: ExporterConfig) -> bool:
    """
    Saves the audit report to a local file system.

    Args:
        report: The audit report data to save.
        config: Configuration specifying the output path.

    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        if not config.output_path:
            _log("No output path specified in config.", "WARNING")
            return False

        # Ensure parent directory exists using pathlib
        output_path = config.output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        report_data = report.json(exclude_none=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_data)
        
        _log(f"Report saved successfully to {output_path}.", "SUCCESS")
        return True
    except PermissionError:
        _log(f"Permission denied for path: {config.output_path}", "ERROR")
        return False
    except (IOError, OSError) as e:
        _log(f"File system error: {str(e)}", "ERROR")
        return False


def export_report_to_webhook(report: AuditReport, config: ExporterConfig) -> bool:
    """
    Pushes the audit report to an external dashboard via HTTP POST.

    Args:
        report: The audit report data to send.
        config: Configuration specifying the webhook URL and auth.

    Returns:
        bool: True if request succeeded, False otherwise.
    """
    if not config.webhook_url:
        _log("No webhook URL provided in config.", "WARNING")
        return False

    headers = _setup_exporter_headers(config)
    json_payload = report.json(exclude_none=True)

    try:
        # Using requests for HTTP communication
        response = requests.post(
            config.webhook_url,
            data=json_payload,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        _log(f"Report pushed successfully to {config.webhook_url}.", "SUCCESS")
        return True
    except requests.exceptions.ConnectionError:
        _log("Network connection failed while sending report.", "ERROR")
        return False
    except requests.exceptions.Timeout:
        _log("Request timed out.", "ERROR")
        return False
    except requests.exceptions.HTTPError as e:
        _log(f"HTTP error during push: {e}", "ERROR")
        return False
    except requests.exceptions.RequestException as e:
        _log(f"Unexpected request error: {e}", "ERROR")
        return False


def export_report_to_ci(report: AuditReport) -> bool:
    """
    Detects and exports the report to a CI/CD environment variable sink.
    Supports standard CI variables for centralized visibility.

    Args:
        report: The audit report data.

    Returns:
        bool: True if CI environment detected and handled, False otherwise.
    """
    ci_provider = os.environ.get("CI")
    output_path = Path("/tmp/sentinel-export")

    if not ci_provider:
        _log("Not running in a CI environment, defaulting to local export.", "INFO")
        # Return False to indicate no CI action taken
        return False

    try:
        _log(f"Detected CI provider: {ci_provider}. Exporting report.", "INFO")
        # In a real scenario, this might upload to a specific CI artifact store
        # We will simulate export to a file as a safe fallback for local dev
        export_report_to_path(
            report, 
            ExporterConfig(output_path=output_path.with_suffix(".json"))
        )
        _log(f"Exported to {output_path} for CI artifact consumption.", "SUCCESS")
        return True
    except Exception as e:
        _log(f"CI export failed: {str(e)}", "ERROR")
        return False


def export_report(report: AuditReport, config: Union[Dict[str, Any], ExporterConfig]) -> bool:
    """
    Orchestrates the export process based on provided configuration.

    Args:
        report: The audit report data.
        config: Configuration dictionary or ExporterConfig instance.

    Returns:
        bool: True if any export succeeded, False if all failed.
    """
    target_config = config if isinstance(config, ExporterConfig) else ExporterConfig(**config)
    
    success = False
    
    try:
        if target_config.verify_connectivity:
            if not check_network_connectivity():
                _log("Network connectivity check failed. Retrying without verification.", "WARNING")
        
        if target_config.webhook_url:
            if export_report_to_webhook(report, target_config):
                success = True
        
        if target_config.output_path:
            if export_report_to_path(report, target_config):
                success = True
        
        if not success:
            _log("No export methods succeeded.", "WARNING")
        
        return success
        
    except ValueError as e:
        _log(f"Configuration validation error: {e}", "ERROR")
        return False
    except Exception as e:
        _log(f"Export process failed: {str(e)}", "ERROR")
        return False


def print_export_summary(report: AuditReport, success: bool) -> None:
    """
    Prints a formatted summary of the export status.

    Args:
        report: The audit report being summarized.
        success: Boolean indicating export success.
    """
    status = "Export Successful" if success else "Export Failed"
    color = Fore.GREEN if success else Fore.RED
    
    click.echo(click.style(f"--- {status} ---", style=Style.BRIGHT, fg=color))
    click.echo(click.style(f"Scan Type: {report.scan_type}", fg=Fore.WHITE))
    click.echo(click.style(f"Status: {report.status}", fg=Fore.WHITE))
    click.echo(click.style(f"Vulnerabilities: {len(report.vulnerabilities)}", fg=Fore.WHITE))
    click.echo(click.style(f"Time: {report.timestamp}", fg=Fore.WHITE))
    click.echo(click.style("---------------------------", fg=color))