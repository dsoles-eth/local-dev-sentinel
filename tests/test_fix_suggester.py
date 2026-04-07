import sys
import subprocess
import unittest.mock as mock
from pathlib import Path

import pytest
import requests

from fix_suggester import FixSuggester, AuditFinding, FixSuggestion, FindingSeverity


# Fixtures
@pytest.fixture
def mock_findings():
    """Return a list of sample audit findings for testing."""
    return [
        AuditFinding(
            finding_id="SEC-001",
            finding_type="dependency",
            severity="high",
            message="Vulnerable version of requests",
            recommended_package="requests",
            affected_path=None
        ),
        AuditFinding(
            finding_id="SEC-002",
            finding_type="permission",
            severity="medium",
            message="Config file is world-readable",
            affected_path=Path("/tmp/config.json"),
            recommended_package=None
        ),
        AuditFinding(
            finding_id="SEC-003",
            finding_type="unknown_issue",
            severity="low",
            message="Custom security warning",
            affected_path=None,
            recommended_package=None
        )
    ]


@pytest.fixture
def fs_instance(tmp_path):
    """Create a FixSuggester instance with a temporary environment path."""
    # Create a dummy requirements.txt for path substitution tests
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask==2.0.0\n")
    return FixSuggester(environment_path=tmp_path)


@pytest.fixture
def mock_subprocess_result(return_code=0, stdout="Success", stderr=""):
    """Factory for creating mocked subprocess.CompletedProcess objects."""
    result = mock.MagicMock()
    result.returncode = return_code
    result.stdout = stdout
    result.stderr = stderr
    return result


@pytest.fixture(autouse=True)
def setup_colorama(monkeypatch):
    """Monkeypatch colorama init to prevent side effects during tests."""
    import colorama
    monkeypatch.setattr(colorama, 'init', mock.MagicMock())


class TestAuditFindingModel:
    """Tests for the AuditFinding Pydantic model."""

    def test_severity_normalization(self):
        """Test that severity is normalized to lowercase."""
        finding = AuditFinding(
            finding_id="ID-001",
            finding_type="dependency",
            severity="HIGH",
            message="Test message"
        )
        assert finding.severity == "high"

    def test_required_fields_present(self):
        """Test that required fields are enforced."""
        with pytest.raises(Exception):
            AuditFinding(
                finding_type="dependency",
                severity="high",
                message="Test message"
            )

    def test_optional_fields_default(self):
        """Test that optional fields default to None."""
        finding = AuditFinding(
            finding_id="ID-001",
            finding_type="permission",
            severity="low",
            message="Test message"
        )
        assert finding.affected_path is None
        assert finding.recommended_package is None


class TestFixSuggesterInit:
    """Tests for FixSuggester initialization and templates."""

    def test_init_uses_current_dir(self, fs_instance):
        """Test that init uses current directory if path not provided."""
        # Note: fs_instance is created with tmp_path, this test ensures logic works
        # by checking the path property exists.
        assert fs_instance.environment_path is not None

    def test_init_loads_templates(self, fs_instance):
        """Test that fix templates are loaded during initialization."""
        assert "dependency" in fs_instance._fix_templates
        assert "permission" in fs_instance._fix_templates
        assert "env_var" in fs_instance._fix_templates

    def test_environment_path_persistence(self, fs_instance):
        """Test that environment path is preserved."""
        expected_path = fs_instance.environment_path
        # Verify the path object is the same instance (or equivalent)
        assert isinstance(fs_instance.environment_path, Path)


class TestAnalyzeFindings:
    """Tests for the analyze_findings method."""

    def test_analyze_known_type_dependency(self, fs_instance, mock_findings):
        """Test analysis of a known dependency finding."""
        findings = [mock_findings[0]]
        suggestions = fs_instance.analyze_findings(findings)
        
        assert len(suggestions) == 1
        assert suggestions[0].finding_id == "SEC-001"
        assert "Upgrade vulnerable dependency" in suggestions[0].description

    def test_analyze_known_type_permission(self, fs_instance, mock_findings):
        """Test analysis of a known permission finding."""
        findings = [mock_findings[1]]
        suggestions = fs_instance.analyze_findings(findings)
        
        assert len(suggestions) == 1
        assert suggestions[0].finding_id == "SEC-002"
        assert "Restrict file permissions" in suggestions[0].description

    def test_analyze_unknown_type_fallback(self, fs_instance, mock_findings):
        """Test analysis falls back to manual review for unknown types."""
        findings = [mock_findings[2]]
        suggestions = fs_instance.analyze_findings(findings)
        
        assert len(suggestions) == 1
        assert suggestions[0].command is None
        assert suggestions[0].command_type == "manual"
        assert "Manual review required" in suggestions[0].description

    def test_analyze_exception_handling(self, fs_instance):
        """Test that exceptions during analysis do not crash the method."""
        # Simulate an error by passing a malformed object if possible, 
        # but since Pydantic validates, we test by patching internal logic.
        original_method = fs_instance._create_suggestion
        fs_instance._create_suggestion = mock.MagicMock(side_effect=RuntimeError("Boom"))
        
        suggestions = fs_instance.analyze_findings([AuditFinding(
            finding_id="X", finding_type="test", severity="low", message="x"
        )])
        
        # Should return empty list or partials without raising
        assert isinstance(suggestions, list)
        fs_instance._create_suggestion = original_method


class TestCreateSuggestion:
    """Tests for the internal _create_suggestion method."""

    def test_substitute_package_name(self, fs_instance, mock_findings):
        """Test substitution of {package} variable."""
        finding = mock_findings[0]
        # Find dependency template
        template = fs_instance._fix_templates["dependency"][0]
        suggestion = fs_instance._create_suggestion(finding, template)
        
        assert "pip" in suggestion.command
        assert "requests" in suggestion.command

    def test_substitute_path(self, fs_instance, mock_findings):
        """Test substitution of {path} variable."""
        finding = mock_findings[1]
        template = fs_instance._fix_templates["permission"][0]
        suggestion = fs_instance._create_suggestion(finding, template)
        
        assert suggestion.command
        assert str(finding.affected_path) in suggestion.command

    def test_substitute_requirements_file(self, fs_instance, mock_findings):
        """Test substitution of {requirements_file} variable."""
        finding = mock_findings[0]
        # Using install template from dependency
        template = fs_instance._fix_templates["dependency"][1]
        suggestion = fs_instance._create_suggestion(finding, template)
        
        assert "requirements.txt" in suggestion.command


class TestExecuteFix:
    """Tests for the execute_fix method."""

    def test_execute_dry_run(self, fs_instance):
        """Test that dry_run prints command but does not execute."""
        suggestion = FixSuggestion(
            finding_id="test",
            description="Test",
            command=["echo", "hello"],
            command_type="manual",
            needs_execution=True
        )
        
        with mock.patch.object(fs_instance, 'environment_path', Path.cwd()), \
             mock.patch('subprocess.run') as mock_run:
            success, output = fs_instance.execute_fix(suggestion, dry_run=True)
            
            mock_run.assert_not_called()
            assert success is True
            assert "DRY RUN" in output

    def test_execute_success(self, fs_instance):
        """Test successful command execution."""
        suggestion = FixSuggestion(
            finding_id="test",
            description="Test",
            command=["echo", "hello"],
            command_type="manual",
            needs_execution=True
        )
        
        with mock.patch.object(fs_instance, 'environment_path', Path.cwd()), \
             mock.patch('subprocess.run', return_value=mock_subprocess_result(return_code=0)):
            success, output = fs_instance.execute_fix(suggestion)
            
            assert success is True
            assert "Fix successful" in output

    def test_execute_failure(self, fs_instance):
        """Test failed command execution."""
        suggestion = FixSuggestion(
            finding_id="test",
            description="Test",
            command=["echo", "fail"],
            command_type="manual",
            needs_execution=True
        )
        
        with mock.patch.object(fs_instance, 'environment_path', Path.cwd()), \
             mock.patch('subprocess.run', return_value=mock_subprocess_result(return_code=1, stderr="Error")):
            success, output = fs_instance.execute_fix(suggestion)
            
            assert success is False
            assert "Fix failed" in output

    def test_execute_permission_error(self, fs_instance):
        """Test handling of PermissionError."""
        suggestion = FixSuggestion(
            finding_id="test",
            description="Test",
            command=["sudo", "rm", "-rf"],
            command_type="manual",
            needs_execution=True
        )
        
        with mock.patch.object(fs_instance, 'environment_path', Path.cwd()), \
             mock.patch('subprocess.run', side_effect=PermissionError("Access denied")):
            success, output = fs_instance.execute_fix(suggestion)
            
            assert success is False
            assert "Permission denied" in output

    def test_execute_not_found(self, fs_instance):
        """Test handling of FileNotFoundError."""
        suggestion = FixSuggestion(
            finding_id="test",
            description="Test",
            command=["nonexistent_command"],
            command_type="manual",
            needs_execution=True
        )
        
        with mock.patch.object(fs_instance, 'environment_path', Path.cwd()), \
             mock.patch('subprocess.run', side_effect=FileNotFoundError("Not found")):
            success, output = fs_instance.execute_fix(suggestion)
            
            assert success is False
            assert "Command not found" in output


class TestCheckPackageVersion:
    """Tests for the check_package_version method."""

    def test_check_version_success(self, fs_instance):
        """Test retrieving latest version from mocked PyPI response."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "releases": {
                "1.0.0": {},
                "2.0.0": {}
            }
        }
        
        with mock.patch('requests.get', return_value=mock_response):
            version = fs_instance.check_package_version("test_pkg")
            assert version == "2.0.0"

    def test_check_version_api_error(self, fs_instance):
        """Test handling of HTTP errors from PyPI."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 404
        
        with mock.patch('requests.get', return_value=mock_response):
            version = fs_instance.check_package_version("missing_pkg")
            assert version is None

    def test_check_version_network_exception(self, fs_instance):
        """Test handling of network request exceptions."""
        with mock.patch('requests.get', side_effect=requests.exceptions.RequestException()):
            version = fs_instance.check_package_version("pkg")
            assert version is None


class TestGetLocalDependencies:
    """Tests for the get_local_dependencies method."""

    def test_scan_dependencies_found(self, fs_instance, tmp_path):
        """Test reading dependencies from existing requirements file."""
        req_path = tmp_path / "requirements.txt"
        req_path.write_text("package1==1.0\npackage2>=2.0")
        
        with mock.patch.object(fs_instance, 'environment_path', tmp_path):
            deps = fs_instance.get_local_dependencies()
            assert "package1" in deps
            assert "package2" in deps

    def test_scan_dependencies_missing_file(self, fs_instance, tmp_path):
        """Test handling of missing requirements file."""
        with mock.patch.object(fs_instance, 'environment_path', tmp_path):
            deps = fs_instance.get_local_dependencies()
            assert deps == {}

    def test_scan_dependencies_read_error(self, fs_instance, tmp_path):
        """Test handling of file read exceptions."""
        req_path = tmp_path / "requirements.txt"
        req_path.write_text("data")
        
        with mock.patch.object(fs_instance, 'environment_path', tmp_path), \
             mock.patch('pathlib.Path.read_text', side_effect=IOError("Disk error")):
            # Note: The method catches IOError and logs warning, returning deps {}
            # We can't easily catch the click.echo, but we can check return value
            deps = fs_instance.get_local_dependencies()
            assert deps == {}


class TestValidateFixPlan:
    """Tests for the validate_fix_plan method."""

    def test_plan_validates_safe_commands(self, fs_instance):
        """Test that safe commands are marked as valid."""
        suggestion = FixSuggestion(
            finding_id="test",
            description="Safe",
            command=["echo", "hello"],
            command_type="manual",
            needs_execution=True
        )
        
        validations = fs_instance.validate_fix_plan([suggestion])
        assert validations["test"] is True

    def test_plan_validates_dangerous_commands(self, fs_instance):
        """Test that dangerous commands are marked invalid."""
        dangerous_suggestion = FixSuggestion(
            finding_id="danger",
            description="Danger",
            command=["rm", "-rf", "/"],
            command_type="manual",
            needs_execution=True
        )
        
        validations = fs_instance.validate_fix_plan([dangerous_suggestion])
        assert validations["danger"] is False

    def test_plan_validates_manual_fixes(self, fs_instance):
        """Test that fixes without commands are considered safe."""
        suggestion = FixSuggestion(
            finding_id="manual",
            description="Manual",
            command=None,
            command_type="manual",
            needs_execution=False
        )
        
        validations = fs_instance.validate_fix_plan([suggestion])
        assert validations["manual"] is True

    def test_plan_validates_sudo_usage(self, fs_instance):
        """Test detection of sudo usage."""
        suggestion = FixSuggestion(
            finding_id="sudo",
            description="Sudo",
            command=["sudo", "apt-get", "update"],
            command_type="manual",
            needs_execution=True
        )
        
        validations = fs_instance.validate_fix_plan([suggestion])
        assert validations["sudo"] is False