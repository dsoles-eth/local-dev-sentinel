from __future__ import annotations

import colorama
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, ValidationError

try:
    colorama.init()
except Exception:
    pass

COLOR_SUCCESS = "green"
COLOR_WARNING = "yellow"
COLOR_ERROR = "red"
COLOR_INFO = "cyan"


class AuditFinding(BaseModel):
    """Model representing a single security audit finding."""
    finding_id: str = Field(..., description="Unique identifier for the finding")
    timestamp: datetime = Field(default_factory=datetime.now)
    severity: str = Field(..., description="Severity level (low, medium, high, critical)")
    category: str = Field(..., description="Category of the security issue")
    message: str = Field(..., description="Human-readable description of the issue")
    file_path: Optional[str] = Field(None, description="Source file path associated with the issue")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context data")

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class HistoryLogger:
    """
    Handles persistence and retrieval of audit findings over time.
    Supports trend analysis and regression detection.
    """

    DEFAULT_LOG_DIR = Path.home() / ".local_dev_sentinel"
    DEFAULT_LOG_FILE = "audit_history.json"

    def __init__(self, log_dir: Optional[Path] = None, log_file: Optional[Path] = None):
        """
        Initialize the history logger.

        Args:
            log_dir: Directory to store history files. Defaults to ~/.local_dev_sentinel.
            log_file: Name or path of the history file. Defaults to audit_history.json.
        """
        try:
            self.log_dir = log_dir or self.DEFAULT_LOG_DIR
            self.log_file = log_dir / log_file if log_file and isinstance(log_file, Path) else self.log_dir / log_file or self.DEFAULT_LOG_FILE
            
            # Ensure log directory exists
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self.log_dir = Path.cwd()
            self.log_file = Path("audit_history.json")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize logger directory: {e}")

    def add_finding(self, finding: AuditFinding) -> bool:
        """
        Append a new audit finding to the history log.

        Args:
            finding: An instance of AuditFinding containing the new data.

        Returns:
            bool: True if the finding was saved successfully, False otherwise.
        """
        try:
            current_data = self._read_history()
            current_data["findings"].append(finding.dict())
            self._write_history(current_data)
            return True
        except ValidationError:
            return False
        except Exception as e:
            return False

    def get_history(self, limit: Optional[int] = None) -> List[AuditFinding]:
        """
        Retrieve historical audit findings.

        Args:
            limit: Maximum number of recent findings to retrieve.

        Returns:
            List[AuditFinding]: A list of parsed finding objects.
        """
        try:
            raw_history = self._read_history()
            findings_data = raw_history.get("findings", [])
            findings_list = [AuditFinding(**f) for f in findings_data]
            
            if limit:
                findings_list = findings_list[:limit]
            
            return findings_list
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return []
        except Exception:
            return []

    def analyze_trends(self) -> Dict[str, Any]:
        """
        Analyze the history log for recurring patterns and regressions.

        Returns:
            Dict[str, Any]: A dictionary containing analysis results including
            frequency counts, recent severity, and potential regression flags.
        """
        try:
            findings = self.get_history()
            if not findings:
                return {
                    "total_findings": 0,
                    "recent_findings": 0,
                    "regressions": [],
                    "recurring_patterns": []
                }

            categories: Dict[str, int] = {}
            severity_counts: Dict[str, int] = {"high": 0, "low": 0, "medium": 0, "critical": 0}
            recent_findings = [f for f in findings if (datetime.now() - f.timestamp).total_seconds() < 3600] # Last hour
            
            for finding in findings:
                categories[finding.category] = categories.get(finding.category, 0) + 1
                if finding.severity in severity_counts:
                    severity_counts[finding.severity] += 1

            regressions = []
            # Detect regression: Severity > Low appearing frequently recently
            high_severity_recent = [f for f in recent_findings if f.severity in ["high", "critical"]]
            if len(high_severity_recent) > 5:
                regressions.append("High severity issues exceeding threshold (5+) in last hour.")

            recurring_patterns = []
            for cat, count in categories.items():
                if count >= 5:
                    recurring_patterns.append({"category": cat, "frequency": count})

            return {
                "total_findings": len(findings),
                "recent_findings": len(recent_findings),
                "severity_breakdown": severity_counts,
                "regressions": regressions,
                "recurring_patterns": recurring_patterns
            }
        except Exception as e:
            return {"error": str(e)}

    def _read_history(self) -> Dict[str, Any]:
        """Read the history JSON file safely."""
        try:
            if not self.log_file.exists():
                return {"findings": [], "last_updated": datetime.now().isoformat()}
            with open(self.log_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {"findings": [], "last_updated": datetime.now().isoformat()}
        except Exception:
            return {"findings": [], "last_updated": datetime.now().isoformat()}

    def _write_history(self, data: Dict[str, Any]) -> bool:
        """Write data to the history JSON file safely."""
        try:
            data["last_updated"] = datetime.now().isoformat()
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except (PermissionError, IOError):
            return False

    def clear_history(self) -> bool:
        """Remove all history logs."""
        try:
            if self.log_file.exists():
                self.log_file.unlink()
            return True
        except OSError:
            return False

    def print_summary(self) -> None:
        """Print a summary of the history analysis to the console."""
        try:
            analysis = self.analyze_trends()
            print(f"\n{colorama.Fore.CYAN}Local Dev Sentinel - History Summary{colorama.Fore.RESET}")
            print(f"Total Findings: {analysis.get('total_findings', 0)}")
            print(f"Recent Findings (1hr): {analysis.get('recent_findings', 0)}")
            
            if analysis.get('severity_breakdown'):
                sev = analysis['severity_breakdown']
                print(f"Critical: {colorama.Fore.RED}{sev.get('critical', 0)}{colorama.Fore.RESET}")
                print(f"High: {colorama.Fore.YELLOW}{sev.get('high', 0)}{colorama.Fore.RESET}")
            
            if analysis.get('regressions'):
                print(f"{colorama.Fore.RED}REGRESSIONS DETECTED:{colorama.Fore.RESET}")
                for reg in analysis['regressions']:
                    print(f"  - {reg}")
            
            if analysis.get('recurring_patterns'):
                print(f"{colorama.Fore.YELLOW}Recurring Patterns:{colorama.Fore.RESET}")
                for pattern in analysis['recurring_patterns']:
                    print(f"  - {pattern['category']}: {pattern['frequency']}")
            print("-" * 40)
        except Exception as e:
            print(f"{colorama.Fore.RED}Error generating summary: {e}{colorama.Fore.RESET}")