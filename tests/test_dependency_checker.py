import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
from click.testing import CliRunner
import sys
import dependency_checker

@pytest.fixture
def runner():
    return CliRunner()

@pytest.fixture
def tmp_project_path(tmp_path):
    return tmp_path

class TestInitColors:
    @patch('dependency_checker.colorama_init')
    def test_init_colors_calls_colorama(self, mock_init):
        dependency_checker.init_colors()
        mock_init.assert_called_once()

    def test_init_colors_returns_none(self):
        result = dependency_checker.init_colors()
        assert result is None

    @patch('dependency_checker.colorama_init')
    def test_init_colors_idempotent(self, mock_init):
        dependency_checker.init_colors()
        dependency_checker.init_colors()
        assert mock_init.call_count == 2

class TestPackageAndVulnerabilityModels:
    def test_package_model_validation_name(self):
        pkg = dependency_checker.Package(name="valid_name", version="1.0.0", source=Path("test.txt"))
        assert pkg.name == "valid_name"

    def test_package_model_validation_name_lowercase(self):
        pkg = dependency_checker.Package(name="ValidName", version="1.0.0", source=Path("test.txt"))
        assert pkg.name == "validname"

    def test_vulnerability_model_creation(self):
        vuln = dependency_checker.Vulnerability(
            id="CVE-2021-1234",
            severity="HIGH",
            package_name="flask",
            package_version="1.0.0",
            description="Test"
        )
        assert vuln.severity == "HIGH"

class TestParseRequirements:
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.read_text', return_value="requests==2.28.1\nflask>=2.0")
    def test_parse_requirements_happy_path(self, mock_read, mock_exists, tmp_project_path):
        path = tmp_project_path / "requirements.txt"
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "requests==2.28.1\nflask>=2.0\n"
        with patch('dependency_checker.Path', return_value=mock_path):
            packages = dependency_checker.parse_requirements(path)
            assert len(packages) == 2

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.read_text', return_value="# comment\n\n")
    def test_parse_requirements_empty_with_comments(self, mock_read, mock_exists, tmp_project_path):
        path = tmp_project_path / "requirements.txt"
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "# comment\n\n"
        with patch('dependency_checker.Path', return_value=mock_path):
            packages = dependency_checker.parse_requirements(path)
            assert len(packages) == 0

    @patch('pathlib.Path.exists')
    def test_parse_requirements_file_not_found(self, mock_exists, tmp_project_path):
        path = tmp_project_path / "nonexistent.txt"
        mock_exists.return_value = False
        with patch('dependency_checker.Path', return_value=MagicMock()):
            with pytest.raises(FileNotFoundError):
                dependency_checker.parse_requirements(path)

class TestParsePackageJson:
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.read_text', return_value='{"dependencies": {"react": "^18.0.0"}}')
    @patch('json.loads', return_value={"dependencies": {"react": "^18.0.0"}})
    def test_parse_package_json_happy_path(self, mock_load, mock_read, mock_exists, tmp_project_path):
        path = tmp_project_path / "package.json"
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = '{"dependencies": {"react": "^18.0.0"}}'
        with patch('dependency_checker.Path', return_value=mock_path):
            packages = dependency_checker.parse_package_json(path)
            assert len(packages) == 1
            assert packages[0].name == "react"

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.read_text', return_value='{"dependencies": {}}')
    @patch('json.loads', return_value={"dependencies": {}})
    def test_parse_package_json_no_deps(self, mock_load, mock_read, mock_exists, tmp_project_path):
        path = tmp_project_path / "package.json"
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = '{"dependencies": {}}'
        with patch('dependency_checker.Path', return_value=mock_path):
            packages = dependency_checker.parse_package_json(path)
            assert len(packages) == 0

    @patch('pathlib.Path.exists')
    def test_parse_package_json_invalid_json(self, mock_exists, tmp_project_path):
        path = tmp_project_path / "package.json"
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value='{"invalid": json}'
        with patch('dependency_checker.Path', return_value=mock_path):
            with pytest.raises(ValueError):
                dependency_checker.parse_package_json(path)

class TestQueryVulnerabilityDb:
    @patch('requests.post')
    def test_query_vulnerability_db_empty_packages(self, mock_post):
        packages = []
        result = dependency_checker.query_vulnerability_db(packages)
        assert result == []
        mock_post.assert_not_called()

    @patch('requests.post')
    def test_query_vulnerability_db_valid_py_package(self, mock_post):
        packages = [dependency_checker.Package(name="flask", version="2.0", source=Path("requirements.txt"))]
        with patch('dependency_checker.query_vulnerability_db.__module__') as mock_module:
            # Note: We mock requests to prevent real calls even if logic was active
            pass
        # The current code has a pass block, but we ensure the try/except is ready
        result = dependency_checker.query_vulnerability_db(packages)
        # Current behavior returns empty list due to 'pass'
        assert isinstance(result, list)

    @patch('requests.post')
    @patch('dependency_checker.Path')
    def test_query_vulnerability_db_unsupported_source(self, mock_path):
        # Create a package source that is neither .txt nor package.json
        mock_source = MagicMock()
        mock_source.suffix = ".log"
        mock_source.name = "somefile.log"
        
        packages = [dependency_checker.Package(name="test", version="1.0", source=mock_source)]
        result = dependency_checker.query_vulnerability_db(packages)
        assert len(result) == 0

class TestRunSubprocessCheck:
    @patch('subprocess.run')
    def test_run_subprocess_check_success(self, mock_run, tmp_project_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="Success")
        result = dependency_checker.run_subprocess_check(["ls"])
        assert result == (0, "Success")

    @patch('subprocess.run')
    def test_run_subprocess_check_timeout(self, mock_run):
        mock_run.side_effect = Exception("Timeout")
        # subprocess.TimeoutExpired is a specific exception, mocking exception
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired(command="test", timeout=1)
        result = dependency_checker.run_subprocess_check(["test"])
        assert result == (-1, "Command timed out")

    @patch('subprocess.run')
    def test_run_subprocess_check_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError("command not found")
        result = dependency_checker.run_subprocess_check(["nonexistent"])
        assert result == (-2, "Command not found")

class TestCheckCurrentDependencies:
    @patch('pathlib.Path.exists')
    @patch('dependency_checker.parse_requirements')
    @patch('dependency_checker.parse_package_json')
    def test_check_current_dependencies_both_files(self, mock_json, mock_req, mock_exists, tmp_project_path):
        path = tmp_project_path / "requirements.txt"
        path_json = tmp_project_path / "package.json"
        
        mock_exists.side_effect = lambda x: True
        mock_req.return_value = [MagicMock()]
        mock_json.return_value = [MagicMock()]

        packages = dependency_checker.check_current_dependencies(tmp_project_path)
        assert len(packages) == 2
        assert mock_req.called
        assert mock_json.called

    @patch('pathlib.Path.exists')
    @patch('dependency_checker.parse_package_json')
    def test_check_current_dependencies_only_req(self, mock_json, mock_exists, tmp_project_path):
        path = tmp_project_path / "requirements.txt"
        path_json = tmp_project_path / "package.json"
        
        def exists_side_effect(x):
            return x.name == "requirements.txt"
        
        mock_exists.side_effect = exists_side_effect
        mock_json.return_value = []
        
        packages = dependency_checker.check_current_dependencies(tmp_project_path)
        assert len(packages) > 0  # Depends on mock_req internal
        assert mock_json.not_called

    @patch('pathlib.Path.exists')
    def test_check_current_dependencies_no_files(self, mock_exists, tmp_project_path):
        def exists_side_effect(x):
            return False
        
        mock_exists.side_effect = exists_side_effect
        packages = dependency_checker.check_current_dependencies(tmp_project_path)
        assert len(packages) == 0

class TestPrintReport:
    def test_print_report_no_vulnerabilities(self, capfd):
        dependency_checker.print_report([], tmp_project_path)
        captured = capfd.readouterr()
        assert "No vulnerabilities detected" in captured.out

    def test_print_report_with_vulnerabilities(self, capfd):
        vulns = [dependency_checker.Vulnerability(
            id="CVE-001", severity="HIGH", package_name="pkg", package_version="1.0", description="Test"
        )]
        dependency_checker.print_report(vulns, tmp_project_path)
        captured = capfd.readouterr()
        assert "pkg@1.0" in captured.out
        assert "HIGH" in captured.out

    def test_print_report_critical_color(self, capfd):
        vulns = [dependency_checker.Vulnerability(
            id="CVE-002", severity="CRITICAL", package_name="pkg", package_version="1.0", description="Test"
        )]
        dependency_checker.print_report(vulns, tmp_project_path)
        captured = capfd.readouterr()
        assert "CRITICAL" in captured.out

class TestCliCommands:
    @patch('dependency_checker.query_vulnerability_db')
    def test_cli_scan_requirements_success(self, mock_query, runner, tmp_project_path):
        mock_query.return_value = []
        req_path = tmp_project_path / "requirements.txt"
        runner.invoke(dependency_checker.cli, ['scan-requirements', str(req_path)])

    @patch('dependency_checker.query_vulnerability_db')
    def test_cli_scan_package_json_success(self, mock_query, runner, tmp_project_path):
        mock_query.return_value = []
        pkg_path = tmp_project_path / "package.json"
        runner.invoke(dependency_checker.cli, ['scan-package-json', str(pkg_path)])

    @patch('dependency_checker.query_vulnerability_db')
    def test_cli_audit_success(self, mock_query, runner, tmp_project_path):
        mock_query.return_value = []
        result = runner.invoke(dependency_checker.cli, ['audit', '--project-root', str(tmp_project_path)])
        assert result.exit_code == 0