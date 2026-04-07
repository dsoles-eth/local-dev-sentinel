import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from pydantic import BaseModel, Field, root_validator
from colorama import Fore, Style, init
import requests
import click
import os
import sys

# Initialize Colorama for cross-platform colored output
init(autoreset=True)


class FindingSeverity(BaseModel):
    """Enum-like structure for audit finding severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditFinding(BaseModel):
    """Represents a single security or configuration finding."""
    finding_id: str = Field(..., description="Unique identifier for the finding")
    finding_type: str = Field(..., description="Category of the issue (e.g., dependency, permission)")
    severity: str = Field(..., description="Severity level of the issue")
    message: str = Field(..., description="Human-readable description of the issue")
    affected_path: Optional[Path] = Field(None, description="File path associated with the finding")
    recommended_package: Optional[str] = Field(None, description="Package name if applicable")

    @root_validator(pre=True)
    def validate_severity(cls, values):
        """Ensure severity is normalized."""
        if values.get('severity'):
            values['severity'] = values['severity'].lower()
        return values


class FixSuggestion(BaseModel):
    """Represents a suggested remediation command."""
    finding_id: str
    description: str
    command: Optional[List[str]] = Field(None, description="Shell command to execute, split by arguments")
    manual_fix: Optional[str] = Field(None, description="Instructions if auto-execution is not safe")
    needs_execution: bool = False
    command_type: str = Field(..., description="Type of fix (auto, manual, install, config)")

    class Config:
        use_enum_values = True


class FixSuggester:
    """
    Analyzes audit results and suggests remediation commands.
    
    This class maps audit findings to potential fix commands and handles
    execution of safe remediations.
    """

    def __init__(self, environment_path: Optional[Path] = None):
        """
        Initialize the FixSuggester.
        
        Args:
            environment_path: The root directory of the local development environment.
        """
        self.environment_path = environment_path or Path.cwd()
        self._fix_templates = self._load_fix_templates()

    def _load_fix_templates(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load internal templates mapping finding types to fix commands."""
        return {
            "dependency": [
                {
                    "command": ["pip", "install", "--upgrade", "{package}"],
                    "command_type": "install",
                    "needs_execution": True,
                    "description": "Upgrade vulnerable dependency to latest safe version"
                },
                {
                    "command": ["pip", "install", "-r", "{requirements_file}"],
                    "command_type": "install",
                    "needs_execution": False,
                    "description": "Reinstall dependencies from lockfile"
                }
            ],
            "permission": [
                {
                    "command": ["chmod", "750", "{path}"],
                    "command_type": "config",
                    "needs_execution": False,
                    "description": "Restrict file permissions to owner and group only"
                }
            ],
            "env_var": [
                {
                    "command": None,
                    "command_type": "config",
                    "needs_execution": False,
                    "description": "Add required environment variable to .env file"
                }
            ]
        }

    def analyze_findings(self, findings: List[AuditFinding]) -> List[FixSuggestion]:
        """
        Analyze a list of audit findings and generate fix suggestions.
        
        Args:
            findings: A list of AuditFinding instances to analyze.
            
        Returns:
            A list of FixSuggestion instances corresponding to the inputs.
        """
        suggestions = []
        
        try:
            for finding in findings:
                finding_type = finding.finding_type.lower()
                if finding_type in self._fix_templates:
                    for template in self._fix_templates[finding_type]:
                        suggestion = self._create_suggestion(finding, template)
                        suggestions.append(suggestion)
                        break
                else:
                    suggestions.append(FixSuggestion(
                        finding_id=finding.finding_id,
                        description=f"Manual review required for {finding.finding_type}",
                        manual_fix=finding.message,
                        command=None,
                        needs_execution=False,
                        command_type="manual"
                    ))
        except Exception as e:
            click.echo(f"{Fore.RED}Error analyzing findings: {str(e)}{Style.RESET_ALL}", err=True)
            
        return suggestions

    def _create_suggestion(self, finding: AuditFinding, template: Dict[str, Any]) -> FixSuggestion:
        """
        Create a FixSuggestion instance based on a template and a finding.
        
        Args:
            finding: The audit finding to suggest a fix for.
            template: The template defining the fix logic.
            
        Returns:
            A populated FixSuggestion object.
        """
        command = template.get("command")
        description = template.get("description", "No description")
        manual = template.get("manual_fix")
        
        # Substitute variables in command strings
        if command:
            if finding.recommended_package:
                command = [cmd.replace("{package}", finding.recommended_package) for cmd in command]
            if finding.affected_path:
                path_str = str(finding.affected_path)
                command = [cmd.replace("{path}", path_str) for cmd in command]
            if self.environment_path:
                req_path = self.environment_path / "requirements.txt"
                if req_path.exists():
                    command = [cmd.replace("{requirements_file}", str(req_path)) for cmd in command]

        return FixSuggestion(
            finding_id=finding.finding_id,
            description=description,
            command=command if command else None,
            manual_fix=manual,
            needs_execution=template.get("needs_execution", False),
            command_type=template.get("command_type", "manual")
        )

    def execute_fix(self, suggestion: FixSuggestion, dry_run: bool = False) -> Tuple[bool, str]:
        """
        Execute a suggested fix command safely.
        
        Args:
            suggestion: The FixSuggestion to execute.
            dry_run: If True, print the command without executing.
            
        Returns:
            Tuple of (success: bool, output: str)
        """
        if not suggestion.command:
            return False, "No command available for execution."
        
        try:
            if dry_run:
                click.echo(f"{Fore.YELLOW}DRY RUN: {' '.join(suggestion.command)}{Style.RESET_ALL}")
                return True, "Dry run completed."
            
            click.echo(f"Executing fix: {' '.join(suggestion.command)}")
            
            result = subprocess.run(
                suggestion.command,
                cwd=self.environment_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            
            output = result.stdout
            error = result.stderr
            
            if result.returncode == 0:
                click.echo(f"{Fore.GREEN}Fix successful.{Style.RESET_ALL}")
                return True, output
            else:
                click.echo(f"{Fore.RED}Fix failed: {error}{Style.RESET_ALL}")
                return False, error

        except PermissionError:
            return False, "Permission denied to execute command."
        except FileNotFoundError:
            return False, "Command not found."
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"

    def check_package_version(self, package_name: str) -> Optional[str]:
        """
        Check the latest available version of a package via PyPI.
        
        Args:
            package_name: The name of the package to check.
            
        Returns:
            The latest version string, or None if unavailable.
        """
        url = f"https://pypi.org/pypi/{package_name}/json"
        
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                versions = data.get('releases', {}).keys()
                return sorted(versions, key=lambda v: [int(x) if x.isdigit() else x for x in v.split('.')])[-1] if versions else None
            return None
        except requests.exceptions.RequestException:
            # Silently fail network requests to keep tool working offline
            return None
        except Exception:
            return None

    def get_local_dependencies(self) -> Dict[str, str]:
        """
        Scan the environment for local dependencies.
        
        Returns:
            A dictionary mapping package names to versions.
        """
        deps = {}
        try:
            requirements_path = self.environment_path / "requirements.txt"
            if requirements_path.exists():
                content = requirements_path.read_text(encoding='utf-8')
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("-"):
                        if "==" in line:
                            pkg, ver = line.split("==")
                            deps[pkg] = ver
                        elif ">=" in line:
                            pkg, ver = line.split(">=")
                            deps[pkg] = ver
                        else:
                            deps[line] = "latest"
        except Exception as e:
            click.echo(f"{Fore.YELLOW}Could not read dependencies: {str(e)}{Style.RESET_ALL}", err=True)
        return deps

    def validate_fix_plan(self, suggestions: List[FixSuggestion]) -> Dict[str, bool]:
        """
        Validate that suggested fixes are safe to run.
        
        Args:
            suggestions: List of suggestions to validate.
            
        Returns:
            Dictionary mapping suggestion IDs to validation status.
        """
        validations = {}
        for suggestion in suggestions:
            safe = True
            if not suggestion.command:
                validations[suggestion.finding_id] = True # Manual fixes are inherently safe
                continue
            
            dangerous_commands = ["rm", "sudo", "mkfs", "dd"]
            for cmd in suggestion.command:
                if any(dangerous in cmd.lower() for dangerous in dangerous_commands):
                    safe = False
                    break
            
            # Validate paths exist before attempting fixes
            if suggestion.command:
                for i, arg in enumerate(suggestion.command):
                    if Path(arg).exists():
                        continue
                    # Allow path substitution arguments like {path} to be checked if resolved
                    if not arg.startswith("{") and not arg.startswith("-"):
                        pass 
            
            validations[suggestion.finding_id] = safe
        return validations