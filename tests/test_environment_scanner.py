import pytest
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
from click.testing import CliRunner
import datetime

import environment_scanner
from environment_scanner import EnvironmentScanner, ScanResult, main


# Fixtures
@pytest.fixture
def base_path(tmp_path):
    """Create a temporary directory for scanning."""
    return tmp_path


@pytest.fixture
def scanner(base_path):
    """Create a scanner instance pointing to the temporary path."""
    return EnvironmentScanner(base_path)


@pytest.fixture(autouse=True)
def mock_echo(monkeypatch):
    """Mock click.echo for all tests to prevent console output."""
    monkeypatch.setattr(environment_scanner.click, 'echo', lambda *args, **kwargs: None)


@pytest.fixture
def mock_os_environ(monkeypatch):
    """Mock os.environ to control environment variable scanning."""
    mock_env = MagicMock()
    mock_env.__iter__ = lambda self: iter(list(os.environ.items()))
    mock_env.__getitem__ = lambda self, key: os.environ.get(key, None)
    monkeypatch.setattr(os, 'environ', mock_env)
    return mock_env


@pytest.fixture
def mock_subprocess_run(monkeypatch):
    """Mock subprocess.run for dependency checks."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "django==3.2.0\nrequests==2.26.0"
    mock_result.stderr = ""
    mock_run = MagicMock(return_value=mock_result)
    monkeypatch.setattr(environment_scanner.subprocess, 'run', mock_run)
    return mock_run


@pytest.fixture
def runner():
    """CLI Runner for testing command line interface."""
    return CliRunner()


# Tests for ScanResult class
class TestScanResult:
    def test_scan_result_initialization(self):
        result = ScanResult(timestamp="2023-01-01T00:00:00", status="pending")
        assert result.timestamp == "2023-01-01T00:00:00"
        assert result.status == "pending"
        assert result.issues == []
        assert result.summary == {}

    def test_scan_result_add_issue(self):
        result = ScanResult(timestamp="2023-01-01T00:00:00", status="pending")
        result.add_issue("TEST_TYPE", "HIGH", "Test Description", "Details")
        assert len(result.issues) == 1
        assert result.issues[0]["type"] == "TEST_TYPE"
        assert result.issues[0]["severity"] == "HIGH"

    def test_scan_result_summary_increment(self):
        result = ScanResult(timestamp="2023-01-01T00:00:00", status="pending")
        result.add_issue("SENSITIVE_FILE", "HIGH", "File found")
        result.add_issue("SENSITIVE_FILE", "HIGH", "File found")
        result.add_issue("SECRET_MATCH", "HIGH", "Secret found")
        assert result.summary["SENSITIVE_FILE"] == 2
        assert result.summary["SECRET_MATCH"] == 1


# Tests for EnvironmentScanner Class
class TestEnvironmentScannerInit:
    def test_base_path_resolution(self, scanner):
        assert isinstance(scanner.base_path, Path)
        assert scanner.base_path.exists()

    def test_patterns_initialized(self, scanner):
        assert len(scanner.secrets_regex_patterns) > 0
        assert len(scanner.sensitive_files) > 0

    def test_severity_colors_initialized(self, scanner):
        assert "high" in scanner.severity_colors
        assert "medium" in scanner.severity_colors
        assert scanner.severity_colors["high"] is not None


# Tests for scan_env_vars
class TestScanEnvVars:
    @patch.object(EnvironmentScanner, '_log_issue')
    def test_sensitive_env_var_detected(self, mock_log, monkeypatch, scanner):
        monkeypatch.setenv("MY_SECRET_KEY", "secretvalue")
        monkeypatch.setenv("ANOTHER_VAR", "value")
        result = scanner.scan_env_vars()
        assert mock_log.called
        assert result.status == "pending"

    @patch.object(EnvironmentScanner, '_log_issue')
    def test_secret_regex_match(self, mock_log, monkeypatch, scanner):
        monkeypatch.setenv("AWS_KEY", "AKIAIOSFODNN7EXAMPLE")
        result = scanner.scan_env_vars()
        mock_log.assert_called()

    @patch.object(EnvironmentScanner, '_log_issue')
    def test_no_secrets_found(self, mock_log, monkeypatch, scanner):
        monkeypatch.setenv("DEBUG_MODE", "true")
        monkeypatch.setenv("LOG_LEVEL", "info")
        result = scanner.scan_env_vars()
        # Filter to check if high severity issues were logged for keys
        for call in mock_log.call_args_list:
            assert call.args[1] != "SECRET_MATCH"


# Tests for scan_directory
class TestScanDirectory:
    @patch.object(EnvironmentScanner, '_log_issue')
    def test_sensitive_file_detected(self, mock_log, scanner, base_path):
        # Create a sensitive file
        sensitive_file = base_path / ".env"
        sensitive_file.touch()
        # Ensure scanner points to base_path
        scanner.base_path = base_path
        result = scanner.scan_directory()
        # Check if _log_issue was called with sensitive file issue
        assert any("CONFIG_DRIFT" in str(call) for call in mock_log.call_args_list)

    @patch.object(EnvironmentScanner, '_log_issue')
    @patch("environment_scanner.open", new_callable=mock_open, read_data="AKIAIOSFODNN7EXAMPLE")
    def test_secret_in_file_content(self, mock_file, mock_log, scanner, base_path):
        test_file = base_path / "config.yaml"
        test_file.write_text("password: secret")
        scanner.base_path = base_path
        result = scanner.scan_directory()
        assert mock_log.called

    @patch.object(EnvironmentScanner, '_log_issue')
    def test_permission_error_handling(self, mock_log, scanner, base_path):
        # Create a file to be created, but simulate error
        test_file = base_path / "sensitive_file"
        test_file.touch()
        test_file.chmod(0o000)
        # Since this is a unit test, actual permission changes might be ignored on Windows or CI
        # We rely on the exception handler in the code
        scanner.base_path = base_path
        try:
            result = scanner.scan_directory()
            assert True
        except Exception:
            assert False


# Tests for check_dependencies
class TestCheckDependencies:
    @patch.object(EnvironmentScanner, '_log_issue')
    def test_package_auditing(self, mock_log, mock_subprocess_run, scanner):
        result = scanner.check_dependencies()
        mock_subprocess_run.assert_called()
        assert "django" in str(mock_log.call_args_list)

    @patch.object(EnvironmentScanner, '_log_issue')
    def test_subprocess_timeout(self, mock_log, monkeypatch, scanner):
        monkeypatch.setattr(environment_scanner.subprocess, 'run', side_effect=environment_scanner.subprocess.TimeoutExpired(cmd="pip", timeout=10))
        result = scanner.check_dependencies()
        assert any("SUBPROCESS_TIMEOUT" in str(call) for call in mock_log.call_args_list)

    @patch.object(EnvironmentScanner, '_log_issue')
    def test_pip_not_found(self, mock_log, monkeypatch, scanner):
        monkeypatch.setattr(environment_scanner.subprocess, 'run', side_effect=FileNotFoundError("No pip"))
        result = scanner.check_dependencies()
        assert any("ENV_SETUP" in str(call) for call in mock_log.call_args_list)


# Tests for check_services
class TestCheckServices:
    @patch.object(EnvironmentScanner, '_log_issue')
    def test_service_running(self, mock_log, scanner):
        # _check_local_database returns True by default in mock or real logic (it returns True)
        result = scanner.check_services()
        # Since the logic inside _check_local_database returns True, no issues should be logged for SERVICE_DOWN
        assert not any("SERVICE_DOWN" in str(call) for call in mock_log.call_args_list)

    @patch.object(EnvironmentScanner, '_log_issue')
    @patch.object(EnvironmentScanner, '_check_local_database')
    def test_service_down(self, mock_check, mock_log, scanner):
        mock_check.return_value = False
        result = scanner.check_services()
        assert any("SERVICE_DOWN" in str(call) for call in mock_log.call_args_list)

    @patch.object(EnvironmentScanner, '_log_issue')
    def test_empty_services_list(self, mock_log, scanner):
        original_services = scanner.required_services
        scanner.required_services = []
        result = scanner.check_services()
        scanner.required_services = original_services
        assert len(mock_log.call_args_list) == 0


# Tests for run_full_audit
class TestRunFullAudit:
    @patch.object(EnvironmentScanner, 'scan_env_vars')
    @patch.object(EnvironmentScanner, 'scan_directory')
    @patch.object(EnvironmentScanner, 'check_dependencies')
    @patch.object(EnvironmentScanner, 'check_services')
    def test_full_audit_execution(self, mock_services, mock_deps, mock_dir, mock_env, scanner):
        result = scanner.run_full_audit()
        mock_env.assert_called()
        mock_dir.assert_called()
        mock_deps.assert_called()
        mock_services.assert_called()

    def test_audit_status_updated(self, scanner):
        # Mock internal methods to prevent actual work
        with patch.object(scanner, 'scan_env_vars'), \
             patch.object(scanner, 'scan_directory'), \
             patch.object(scanner, 'check_dependencies'), \
             patch.object(scanner, 'check_services'):
            scanner.run_full_audit()
            assert scanner.results.status == "completed"

    def test_audit_timestamp(self, scanner):
        # Just verify timestamp is present on ScanResult
        result = scanner.results
        assert hasattr(result, 'timestamp')
        assert len(result.timestamp) > 0


# Tests for CLI Commands
class TestCLI:
    def test_cli_env_command(self, runner, scanner):
        result = runner.invoke(main, ['env'])
        assert result.exit_code == 0
        assert "Scanning Environment Variables" in result.output

    def test_cli_audit_all_command(self, runner, scanner):
        result = runner.invoke(main, ['audit-all', '--path', str(scanner.base_path)])
        assert result.exit_code == 0
        assert "Audit Complete" in result.output

    def test_cli_audit_all_json_output(self, runner, scanner):
        result = runner.invoke(main, ['audit-all', '--path', str(scanner.base_path), '--json-output'])
        assert result.exit_code == 0
        assert "{" in result.output  # Verify JSON output presence
        assert "issues" in result.output


# Tests for get_issues and print_summary
class TestSummaryAndIssues:
    def test_get_issues_returns_list(self, scanner):
        scanner.results.add_issue("TEST", "LOW", "Test")
        issues = scanner.get_issues()
        assert isinstance(issues, list)
        assert len(issues) == 1

    def test_get_issues_empty(self, scanner):
        issues = scanner.get_issues()
        assert len(issues) == 0

    def test_print_summary_output(self, scanner, capsys):
        scanner.results.add_issue("TEST", "LOW", "Test")
        # We cannot capture click.echo inside the class without mocking, 
        # but we can assert state change.
        # For CLI tests we use capsys via runner.invoke.
        # Here we just ensure print_summary method exists and runs.
        with patch.object(environment_scanner.click, 'echo'):
            scanner.print_summary(scanner.results)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])