import pytest
from pathlib import Path
from unittest.mock import patch, mock_open, Mock, MagicMock
from config_validator import (
    check_hardcoded_secrets,
    check_file_permissions,
    check_dependency_integrity,
    check_remote_config_status,
    validate_project,
    Vulnerability,
    ValidationResult
)
import json
import subprocess


class TestCheckHardcodedSecrets:
    @patch('config_validator.open', new_callable=mock_open, read_data="db_password = secret123\nusername = admin\n")
    @patch.object(Path, 'exists', return_value=True)
    def test_detects_password_secrets(self, mock_exists, mock_file):
        """Test that hardcoded passwords are detected"""
        test_path = Path('/test/config.txt')
        vulnerabilities = check_hardcoded_secrets(test_path)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].severity == "critical"
        assert vulnerabilities[0].category == "Hardcoded Secret"
        assert test_path in vulnerabilities[0].location

    @patch('config_validator.open', new_callable=mock_open, read_data="username = admin\npassword = \n\n")
    @patch.object(Path, 'exists', return_value=True)
    def test_no_false_positives_on_empty_secrets(self, mock_exists, mock_file):
        """Test that empty secret values don't trigger false positives"""
        test_path = Path('/test/config.txt')
        vulnerabilities = check_hardcoded_secrets(test_path)
        
        # Empty secrets should not be flagged
        assert len(vulnerabilities) == 0

    @patch('config_validator.open', side_effect=FileNotFoundError)
    @patch.object(Path, 'exists', return_value=True)
    def test_handles_file_not_found(self, mock_exists, mock_file):
        """Test handling of missing configuration files"""
        test_path = Path('/nonexistent/config.txt')
        vulnerabilities = check_hardcoded_secrets(test_path)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].severity == "high"
        assert vulnerabilities[0].category == "File Missing"

    @patch('config_validator.open', side_effect=PermissionError)
    @patch.object(Path, 'exists', return_value=True)
    def test_handles_permission_denied(self, mock_exists, mock_file):
        """Test handling of permission denied errors"""
        test_path = Path('/restricted/config.txt')
        vulnerabilities = check_hardcoded_secrets(test_path)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].severity == "high"
        assert vulnerabilities[0].category == "Permissions"


class TestCheckFilePermissions:
    @patch('config_validator.Path.stat')
    @patch.object(Path, 'exists', return_value=True)
    def test_detects_world_writable_permissions(self, mock_exists, mock_stat):
        """Test detection of world-writable files"""
        mock_stat.return_value.st_mode = 0o777
        test_path = Path('/test/config.txt')
        vulnerabilities = check_file_permissions(test_path)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].severity == "high"
        assert vulnerabilities[0].category == "File Permissions"

    @patch('config_validator.Path.stat')
    @patch.object(Path, 'exists', return_value=True)
    def test_detects_world_readable_permissions(self, mock_exists, mock_stat):
        """Test detection of world-readable sensitive files"""
        mock_stat.return_value.st_mode = 0o644
        test_path = Path('/test/config.txt')
        vulnerabilities = check_file_permissions(test_path)
        
        assert len(vulnerabilities) >= 1
        assert vulnerabilities[0].severity == "medium"
        assert "world-readable" in vulnerabilities[0].description.lower()

    @patch('config_validator.Path.stat', side_effect=FileNotFoundError)
    @patch.object(Path, 'exists', return_value=True)
    def test_handles_file_missing(self, mock_exists, mock_stat):
        """Test handling of missing file for permission check"""
        test_path = Path('/nonexistent/config.txt')
        vulnerabilities = check_file_permissions(test_path)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].severity == "high"
        assert vulnerabilities[0].category == "File Missing"


class TestCheckDependencyIntegrity:
    @patch.object(Path, 'exists', return_value=True)
    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open, read_data="requests==2.28.0\n")
    def test_passes_all_dependencies_match(self, mock_file, mock_subprocess, mock_exists):
        """Test when all dependencies match requirements"""
        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps([{"name": "requests", "version": "2.28.0"}])
        )
        mock_file.return_value.readline = lambda: ""
        mock_file.return_value.readlines = lambda: ["requests==2.28.0\n"]
        mock_file.return_value.__iter__ = lambda self: iter(self.readline)
        
        test_path = Path('/test/project')
        vulnerabilities = check_dependency_integrity(test_path)
        
        assert len(vulnerabilities) == 0

    @patch.object(Path, 'exists', return_value=True)
    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open, read_data="requests==2.28.0\n")
    def test_detects_dependency_mismatch(self, mock_file, mock_subprocess, mock_exists):
        """Test detection of version mismatch"""
        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps([{"name": "requests", "version": "2.27.0"}])
        )
        test_path = Path('/test/project')
        vulnerabilities = check_dependency_integrity(test_path)
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].severity == "medium"
        assert vulnerabilities[0].category == "Dependency Mismatch"

    @patch.object(Path, 'exists', return_value=False)
    def test_handles_no_requirements_file(self, mock_exists):
        """Test when requirements.txt doesn't exist"""
        test_path = Path('/test/project')
        vulnerabilities = check_dependency_integrity(test_path)
        
        assert len(vulnerabilities) == 0


class TestCheckRemoteConfigStatus:
    @patch('config_validator.requests.get')
    def test_passes_on_successful_connection(self, mock_get):
        """Test successful remote configuration check"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'X-Frame-Options': 'SAMEORIGIN'}
        mock_get.return_value = mock_response
        
        test_url = "https://example.com/config"
        result = check_remote_config_status(test_url)
        
        assert result.status == "pass"
        assert "Status: 200" in result.message

    @patch('config_validator.requests.get')
    def test_fails_on_non_ok_status(self, mock_get):
        """Test failure on non-OK HTTP status"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.headers = {}
        mock_get.return_value = mock_response
        
        test_url = "https://example.com/config"
        result = check_remote_config_status(test_url)
        
        assert result.status == "fail"

    @patch('config_validator.requests.get')
    def test_handles_connection_timeout(self, mock_get):
        """Test handling of connection timeout"""
        mock_get.side_effect = Exception("Timeout")
        
        test_url = "https://example.com/config"
        result = check_remote_config_status(test_url)
        
        assert result.status == "fail"


class TestValidateProject:
    @patch('config_validator.check_hardcoded_secrets')
    @patch('config_validator.check_file_permissions')
    @patch('config_validator.check_dependency_integrity')
    @patch('config_validator.check_remote_config_status')
    def test_validation_passes_clean(self, mock_remote, mock_deps, mock_perms, mock_secrets):
        """Test validation when no issues found"""
        mock_secrets.return_value = []
        mock_perms.return_value = []
        mock_deps.return_value = []
        mock_remote.return_value = MagicMock(status="pass", message="OK")
        
        test_path = Path('/test/config.yml')
        
        validate_project(
            config_paths=[test_path],
            check_deps=True,
            check_remote=False,
            remote_url=""
        )
        
        mock_secrets.assert_called_once_with(test_path)
        mock_perms.assert_called_once_with(test_path)
        mock_deps.assert_called_once()

    @patch('config_validator.check_hardcoded_secrets')
    @patch('config_validator.check_file_permissions')
    @patch('config_validator.check_dependency_integrity')
    @patch('config_validator.check_remote_config_status')
    def test_validation_finds_issues(self, mock_remote, mock_deps, mock_perms, mock_secrets):
        """Test validation when vulnerabilities are found"""
        mock_secrets.return_value = [
            Vulnerability(
                severity="critical",
                category="Hardcoded Secret",
                description="Secret found",
                location="test"
            )
        ]
        mock_perms.return_value = []
        mock_deps.return_value = []
        mock_remote.return_value = MagicMock(status="pass", message="OK")
        
        test_path = Path('/test/config.yml')
        
        validate_project(
            config_paths=[test_path],
            check_deps=False,
            check_remote=False,
            remote_url=""
        )
        
        mock_secrets.assert_called()

    @patch('config_validator.click.echo')
    @patch('config_validator.check_hardcoded_secrets')
    @patch('config_validator.check_file_permissions')
    @patch('config_validator.check_dependency_integrity')
    @patch('config_validator.check_remote_config_status')
    def test_skips_directories(self, mock_remote, mock_deps, mock_perms, mock_secrets, mock_echo):
        """Test that directories are skipped during validation"""
        mock_secrets.return_value = []
        mock_perms.return_value = []
        mock_deps.return_value = []
        mock_remote.return_value = MagicMock(status="pass", message="OK")
        
        test_dir = Path('/test/directory')
        test_dir.is_file = Mock(return_value=False)
        test_dir.is_dir = Mock(return_value=True)
        
        validate_project(
            config_paths=[test_dir],
            check_deps=False,
            check_remote=False,
            remote_url=""
        )
        
        mock_secrets.assert_not_called()


class TestCLI:
    @patch('config_validator.validate_project')
    @patch('config_validator._initialize_terminal_colors')
    def test_cli_validates_paths(self, mock_init, mock_validate):
        """Test CLI validation command with paths"""
        from click.testing import CliRunner
        from config_validator import cli
        
        runner = CliRunner()
        result = runner.invoke(cli, ['validate', '/test/path'], catch_exceptions=False)
        
        assert result.exit_code == 0
        mock_validate.assert_called_once()

    @patch('config_validator.validate_project')
    @patch('config_validator._initialize_terminal_colors')
    def test_cli_fails_without_paths(self, mock_init, mock_validate):
        """Test CLI fails when no paths provided"""
        from click.testing import CliRunner
        from config_validator import cli
        
        runner = CliRunner()
        result = runner.invoke(cli, ['validate'], catch_exceptions=False)
        
        assert result.exit_code != 0
        assert "ERROR" in result.output

    @patch('config_validator.check_remote_config_status')
    @patch('config_validator._initialize_terminal_colors')
    def test_remote_check_command(self, mock_init, mock_check):
        """Test the dedicated remote check command"""
        from click.testing import CliRunner
        from config_validator import cli
        
        mock_check.return_value = ValidationResult(
            status="pass",
            message="Remote OK",
            details=[]
        )
        
        runner = CliRunner()
        result = runner.invoke(cli, ['remote-check', '--url', 'https://example.com'])
        
        assert result.exit_code == 0
        assert "Status" in result.output


class TestFixturesAndMocks:
    @pytest.fixture
    def mock_vulnerability(self):
        return Vulnerability(
            severity="medium",
            category="Test",
            description="Test vulnerability",
            location="test"
        )

    @pytest.fixture
    def mock_path(self, tmp_path):
        test_file = tmp_path / "test_config.yml"
        test_file.write_text("db_password = secret\n")
        return test_file

    def test_vulnerability_model(self, mock_vulnerability):
        """Test Vulnerability model structure"""
        assert mock_vulnerability.severity in ["low", "medium", "high", "critical"]
        assert mock_vulnerability.location is not None

    def test_validation_result_model(self):
        """Test ValidationResult model structure"""
        result = ValidationResult(
            status="pass",
            message="All checks passed",
            details=[]
        )
        assert result.status == "pass"
        assert isinstance(result.details, list)

    @patch('config_validator.check_hardcoded_secrets')
    def test_error_handling_in_secrets(self, mock_secrets):
        """Test that errors during secret checking are handled gracefully"""
        mock_secrets.side_effect = Exception("Unexpected error")
        
        test_path = Path('/test/config.yml')
        vulnerabilities = check_hardcoded_secrets(test_path)
        
        # Should not raise exception, just return vulnerabilities or empty list
        assert isinstance(vulnerabilities, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])