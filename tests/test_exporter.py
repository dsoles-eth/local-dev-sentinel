import pytest
from unittest.mock import Mock, patch, MagicMock, PropertyMock
from pathlib import Path
import os
import json
from exporter import (
    AuditReport,
    ExporterConfig,
    _log,
    check_network_connectivity,
    _setup_exporter_headers,
    export_report_to_path,
    export_report_to_webhook,
    export_report_to_ci,
    export_report,
    print_export_summary,
)


# Fixtures
@pytest.fixture
def mock_report():
    return AuditReport(
        timestamp="2024-01-15T10:30:00Z",
        scan_type="dependency_audit",
        vulnerabilities=[
            {"id": "CVE-2024-001", "severity": "high", "description": "Test vulnerability"}
        ],
        status="passed",
        metadata={"tool_version": "1.0.0"}
    )


@pytest.fixture
def minimal_config():
    return ExporterConfig()


@pytest.fixture
def webhook_config():
    return ExporterConfig(
        webhook_url="https://example.com/webhook",
        api_key="test-api-key-123",
        headers={"X-Custom-Header": "test-value"}
    )


@pytest.fixture
def file_config():
    return ExporterConfig(output_path=Path("/tmp/test-audit-report.json"))


@pytest.fixture
def ci_config():
    return ExporterConfig(
        webhook_url="https://ci.example.com/report",
        output_path=Path("/tmp/ci-report.json")
    )


@pytest.fixture(autouse=True)
def mock_colorama():
    with patch('exporter.init'), patch('exporter.deinit'), \
         patch('exporter.click') as mock_click:
        yield


@pytest.fixture(autouse=True)
def mock_ci_environment():
    with patch.dict(os.environ, {}, clear=False):
        yield


class TestAuditReport:
    def test_audit_report_creation(self, mock_report):
        assert mock_report.timestamp == "2024-01-15T10:30:00Z"
        assert mock_report.scan_type == "dependency_audit"
        assert len(mock_report.vulnerabilities) == 1
        assert mock_report.status == "passed"

    def test_audit_report_with_minimal_data(self):
        report = AuditReport(
            timestamp="2024-01-15T10:30:00Z",
            scan_type="security_scan",
            status="failed",
            vulnerabilities=[],
            metadata={}
        )
        assert report.scan_type == "security_scan"
        assert report.vulnerabilities == []

    def test_audit_report_validation_error(self):
        with pytest.raises(Exception):
            AuditReport(
                timestamp="invalid-timestamp",
                scan_type="test",
                status="invalid-status"
            )


class TestExporterConfig:
    def test_config_with_webhook(self, webhook_config):
        assert webhook_config.webhook_url == "https://example.com/webhook"
        assert webhook_config.api_key == "test-api-key-123"
        assert webhook_config.verify_connectivity is True

    def test_config_default_values(self, minimal_config):
        assert minimal_config.webhook_url is None
        assert minimal_config.output_path is None
        assert minimal_config.verify_connectivity is True
        assert minimal_config.headers == {}

    def test_config_validation(self):
        config = ExporterConfig(
            webhook_url="https://valid.example.com",
            output_path=Path("/output/report.json")
        )
        assert config.webhook_url is not None
        assert config.output_path is not None


class TestLogFunction:
    def test_log_with_different_statuses(self):
        with patch('exporter.click.echo') as mock_echo:
            _log("Test message", "INFO")
            mock_echo.assert_called()

    def test_log_error_status(self):
        with patch('exporter.click.echo') as mock_echo:
            _log("Error occurred", "ERROR")
            mock_echo.assert_called()

    def test_log_warning_status(self):
        with patch('exporter.click.echo') as mock_echo:
            _log("Warning message", "WARNING")
            mock_echo.assert_called()


class TestNetworkConnectivity:
    def test_network_connectivity_success(self):
        with patch('exporter.subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0)
            result = check_network_connectivity()
            assert result is True

    def test_network_connectivity_failure(self):
        with patch('exporter.subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=1)
            result = check_network_connectivity()
            assert result is False

    def test_network_connectivity_curl_not_found(self):
        with patch('exporter.subprocess.run', side_effect=FileNotFoundError):
            result = check_network_connectivity()
            assert result is True


class TestSetupExporterHeaders:
    def test_headers_with_api_key(self):
        config = ExporterConfig(api_key="secret-key")
        headers = _setup_exporter_headers(config)
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer secret-key"
        assert headers["Content-Type"] == "application/json"

    def test_headers_without_api_key(self):
        config = ExporterConfig()
        headers = _setup_exporter_headers(config)
        assert "Authorization" not in headers
        assert headers["Content-Type"] == "application/json"

    def test_headers_with_custom_headers(self):
        config = ExporterConfig(
            headers={"X-Custom": "value", "X-Another": "test"}
        )
        headers = _setup_exporter_headers(config)
        assert headers["X-Custom"] == "value"
        assert headers["X-Another"] == "test"
        assert headers["Content-Type"] == "application/json"


class TestExportToPath:
    def test_export_to_path_success(self, mock_report, file_config, tmp_path):
        file_config.output_path = tmp_path / "report.json"
        with patch('exporter.export_report_to_path'):
            result = export_report_to_path(mock_report, file_config)
            assert result is True

    def test_export_to_path_no_output_path(self, mock_report):
        config = ExporterConfig()
        with patch('exporter._log') as mock_log:
            result = export_report_to_path(mock_report, config)
            assert result is False

    def test_export_to_path_permission_error(self, mock_report, tmp_path):
        config = ExporterConfig(output_path=tmp_path / "report.json")
        with patch('exporter.Path.mkdir', side_effect=PermissionError()):
            result = export_report_to_path(mock_report, config)
            assert result is False

    def test_export_to_path_io_error(self, mock_report, tmp_path):
        config = ExporterConfig(output_path=tmp_path / "report.json")
        with patch('exporter.Path.mkdir'), \
             patch('builtins.open', side_effect=IOError("test error")):
            result = export_report_to_path(mock_report, config)
            assert result is False


class TestExportToWebhook:
    def test_export_to_webhook_success(self, mock_report, webhook_config):
        with patch('exporter.requests.post') as mock_post:
            mock_post.return_value = Mock(status_code=200, json=lambda: {}, raise_for_status=lambda: None)
            result = export_report_to_webhook(mock_report, webhook_config)
            assert result is True

    def test_export_to_webhook_no_url(self, mock_report):
        config = ExporterConfig()
        with patch('exporter._log') as mock_log:
            result = export_report_to_webhook(mock_report, config)
            assert result is False

    def test_export_to_webhook_connection_error(self, mock_report, webhook_config):
        with patch('exporter.requests.post') as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError()
            result = export_report_to_webhook(mock_report, webhook_config)
            assert result is False

    def test_export_to_webhook_http_error(self, mock_report, webhook_config):
        with patch('exporter.requests.post') as mock_post:
            mock_response = Mock(status_code=400, raise_for_status=lambda: requests.exceptions.HTTPError("Bad Request"))
            mock_post.return_value = mock_response
            result = export_report_to_webhook(mock_report, webhook_config)
            assert result is False

    def test_export_to_webhook_timeout(self, mock_report, webhook_config):
        with patch('exporter.requests.post') as mock_post:
            mock_post.side_effect = requests.exceptions.Timeout()
            result = export_report_to_webhook(mock_report, webhook_config)
            assert result is False


class TestExportToCI:
    def test_export_to_ci_detects_ci_environment(self, mock_report):
        with patch('exporter.os.environ') as mock_env:
            mock_env.get.return_value = "GITHUB_ACTIONS"
            with patch('exporter.export_report_to_path') as mock_export:
                result = export_report_to_ci(mock_report)
                assert result is True
                mock_export.assert_called()

    def test_export_to_ci_no_ci_environment(self, mock_report):
        with patch('exporter.os.environ') as mock_env:
            mock_env.get.return_value = None
            result = export_report_to_ci(mock_report)
            assert result is False

    def test_export_to_ci_fallback_to_path(self, mock_report):
        with patch('exporter.os.environ') as mock_env:
            mock_env.get.return_value = "CIRCLECI"
            with patch('exporter.export_report_to_path') as mock_export:
                mock_export.return_value = True
                result = export_report_to_ci(mock_report)
                assert result is True


class TestExportReport:
    def test_export_report_webhook_success(self, mock_report, webhook_config):
        with patch('exporter.check_network_connectivity', return_value=True), \
             patch('exporter.export_report_to_webhook', return_value=True):
            result = export_report(mock_report, webhook_config)
            assert result is True

    def test_export_report_file_success(self, mock_report, file_config):
        with patch('exporter.check_network_connectivity', return_value=True), \
             patch('exporter.export_report_to_path', return_value=True):
            result = export_report(mock_report, file_config)
            assert result is True

    def test_export_report_no_methods_succeed(self, mock_report):
        with patch('exporter.check_network_connectivity', return_value=True), \
             patch('exporter.export_report_to_webhook', return_value=False), \
             patch('exporter.export_report_to_path', return_value=False):
            result = export_report(mock_report, ExporterConfig())
            assert result is False

    def test_export_report_config_validation_error(self, mock_report):
        with pytest.raises(Exception):
            export_report(mock_report, {"invalid": "config"})

    def test_export_report_dict_config(self, mock_report, webhook_config):
        with patch('exporter.check_network_connectivity', return_value=True), \
             patch('exporter.export_report_to_webhook', return_value=True):
            config_dict = {
                "webhook_url": webhook_config.webhook_url,
                "api_key": webhook_config.api_key,
                "headers": webhook_config.headers
            }
            result = export_report(mock_report, config_dict)
            assert result is True


class TestPrintExportSummary:
    def test_export_summary_success(self, mock_report):
        with patch('exporter.click.echo') as mock_echo:
            print_export_summary(mock_report, success=True)
            assert mock_echo.call_count > 0

    def test_export_summary_failure(self, mock_report):
        with patch('exporter.click.echo') as mock_echo:
            print_export_summary(mock_report, success=False)
            assert mock_echo.call_count > 0

    def test_export_summary_displays_correct_info(self, mock_report):
        with patch('exporter.click.echo') as mock_echo:
            print_export_summary(mock_report, success=True)
            call_args = str(mock_echo.call_args)
            assert mock_report.scan_type in call_args
            assert mock_report.status in call_args
            assert str(len(mock_report.vulnerabilities)) in call_args
            assert mock_report.timestamp in call_args


class TestIntegrationScenarios:
    def test_full_export_with_webhook(self, mock_report, webhook_config):
        with patch('exporter.check_network_connectivity', return_value=True), \
             patch('exporter.export_report_to_webhook', return_value=True):
            result = export_report(mock_report, webhook_config)
            assert result is True

    def test_full_export_with_file(self, mock_report, file_config, tmp_path):
        file_config.output_path = tmp_path / "test-report.json"
        with patch('exporter.check_network_connectivity', return_value=True), \
             patch('exporter.export_report_to_path', return_value=True):
            result = export_report(mock_report, file_config)
            assert result is True

    def test_export_with_multiple_destinations(self, mock_report, webhook_config, file_config):
        with patch('exporter.check_network_connectivity', return_value=True), \
             patch('exporter.export_report_to_webhook', return_value=True), \
             patch('exporter.export_report_to_path', return_value=True):
            config = ExporterConfig(
                webhook_url=webhook_config.webhook_url,
                output_path=file_config.output_path,
                api_key=webhook_config.api_key
            )
            result = export_report(mock_report, config)
            assert result is True

    def test_export_fails_all_methods(self, mock_report):
        with patch('exporter.check_network_connectivity', return_value=True), \
             patch('exporter.export_report_to_webhook', return_value=False), \
             patch('exporter.export_report_to_path', return_value=False):
            result = export_report(mock_report, ExporterConfig())
            assert result is False