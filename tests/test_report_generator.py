import pytest
from unittest import mock
from datetime import datetime
import click
from pathlib import Path
import json

import report_generator
from report_generator import Severity, Finding, AuditReport, ReportGenerator


@pytest.fixture
def fixed_datetime():
    return datetime(2023, 1, 1, 12, 0, 0)


@pytest.fixture
def mock_click_context(fixed_datetime):
    mock_ctx = mock.Mock()
    mock_ctx.exists = True
    mock_ctx.timestamp = fixed_datetime
    return mock_ctx


@pytest.fixture
def sample_findings():
    return [
        Finding(id="F001", title="Critical Vulnerability", description="SQL Injection", category="Security", severity=Severity.CRITICAL),
        Finding(id="F002", title="High Risk", description="Missing Auth", category="Security", severity=Severity.HIGH),
        Finding(id="F003", title="Medium Issue", description="Deprecated Lib", category="Dependency", severity=Severity.MEDIUM),
        Finding(id="F004", title="Low Info", description="Config Check", category="Config", severity=Severity.LOW),
    ]


@pytest.fixture
def sample_report(sample_findings):
    return AuditReport(
        report_id="RPT-123",
        generated_at="2023-01-01T12:00:00",
        target_environment="production",
        findings=sample_findings
    )


@pytest.fixture
def valid_report_instance(sample_findings, monkeypatch):
    # Ensure click context mocking works for Finding instantiation
    mock_ctx = mock.Mock()
    mock_ctx.exists = True
    mock_ctx.timestamp = datetime(2023, 1, 1, 12, 0, 0)
    monkeypatch.setattr("report_generator.click.get_current_context", lambda: mock_ctx)
    monkeypatch.setattr("report_generator.datetime.datetime.now", lambda: datetime(2023, 1, 1, 12, 0, 0))
    
    findings = [
        Finding(id=f"ID{i}", title=f"Title{i}", description="Desc", category="Cat", severity=severity)
        for i, severity in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.INFO])
    ]
    return AuditReport(
        report_id="TEST-001",
        generated_at="2023-01-01",
        target_environment="local",
        findings=findings
    )


class TestSeverity:
    def test_severity_is_enum_value(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
    
    def test_severity_from_str_success(self):
        assert Severity.from_str("critical") == Severity.CRITICAL
        assert Severity.from_str("HIGH") == Severity.HIGH
    
    def test_severity_from_str_case_insensitive(self):
        assert Severity.from_str("MeDiuM") == Severity.MEDIUM


class TestFinding:
    def test_finding_creation_success(self, monkeypatch):
        mock_ctx = mock.Mock()
        mock_ctx.exists = True
        mock_ctx.timestamp = datetime(2023, 1, 1)
        monkeypatch.setattr("report_generator.click.get_current_context", lambda: mock_ctx)
        
        f = Finding(id="123", title="Test", description="Desc", severity=Severity.LOW)
        assert f.id == "123"
        assert f.severity == Severity.LOW

    def test_finding_validation_error(self):
        with pytest.raises(Exception):
            # Triggering validation if target_env was on finding (it's on AuditReport), 
            # but we can test empty string on category if we extend or just check model logic
            # Simulating model validation failure by passing invalid type for enum
            Finding(id="123", title="Test", description="Desc", severity="invalid_severity")
            
    def test_finding_default_timestamp(self, monkeypatch):
        # Force fallback to datetime.now by setting context.exists to False
        mock_ctx = mock.Mock()
        mock_ctx.exists = False
        monkeypatch.setattr("report_generator.click.get_current_context", lambda: mock_ctx)
        monkeypatch.setattr("report_generator.datetime.datetime.now", lambda: datetime(2023, 5, 5))
        
        f = Finding(id="123", title="Test", description="Desc")
        assert "2023-05-05" in f.timestamp

    def test_finding_optional_fields(self):
        f = Finding(id="123", title="Test", description="Desc", recommendation="Fix this")
        assert f.recommendation == "Fix this"


class TestAuditReport:
    def test_report_stats_calculation(self, valid_report_instance):
        stats = valid_report_instance.stats
        assert stats["total"] == 3
        assert stats["critical"] == 1
        assert stats["high"] == 1
        assert stats["low"] == 0

    def test_report_validation_non_empty_env(self):
        with pytest.raises(ValueError):
            AuditReport(
                report_id="123",
                generated_at="2023-01-01",
                target_environment="  ",
                findings=[]
            )
        
    def test_report_validation_empty_env(self):
        with pytest.raises(ValueError):
            AuditReport(
                report_id="123",
                generated_at="2023-01-01",
                target_environment="",
                findings=[]
            )
        with pytest.raises(ValueError):
            AuditReport(
                report_id="123",
                generated_at="2023-01-01",
                target_environment=None,
                findings=[]
            )


class TestReportGeneratorCLI:
    def test_create_cli_text_output_contains_headers(self, valid_report_instance):
        output = ReportGenerator.create_cli_text(valid_report_instance)
        assert "=== LOCAL DEV SENTinel REPORT ===" in output
        assert "FINDINGS" in output
        assert "=== END OF REPORT ===" in output

    def test_create_cli_text_colors_present(self, valid_report_instance):
        output = ReportGenerator.create_cli_text(valid_report_instance)
        # Check for colorama escape codes presence in non-strict way (ANSI codes)
        assert "[" in output  # Standard formatting
        assert "FINDINGS" in output

    def test_create_cli_text_handles_exception(self, valid_report_instance):
        # Mock internals to crash
        with mock.patch.object(valid_report_instance, 'stats', property(lambda self: 1/0)):
            output = ReportGenerator.create_cli_text(valid_report_instance)
            assert "Error generating CLI report" in output


class TestReportGeneratorHTML:
    def test_create_html_report_contains_structure(self, valid_report_instance):
        output = ReportGenerator.create_html_report(valid_report_instance)
        assert "<html" in output
        assert "<body" in output
        assert "Local Dev Sentinel Report" in output

    def test_create_html_report_escapes_content(self, valid_report_instance):
        finding = Finding(id="1", title="Test", description="<script>alert(1)</script>", severity=Severity.INFO)
        report = AuditReport(report_id="1", generated_at="2023-01-01", target_environment="test", findings=[finding])
        output = ReportGenerator.create_html_report(report)
        assert "&lt;script&gt;" in output or "&lt;" in output

    def test_create_html_report_handles_exception(self):
        report = AuditReport(report_id="1", generated_at="2023-01-01", target_environment="test", findings=[])
        # Force exception by corrupting stats access logic or similar
        # Since create_html_report catches Exception, we test generic error return
        with mock.patch.object(report, 'stats', property(lambda self: [])):
            output = ReportGenerator.create_html_report(report)
            # Should contain html tags still or error message inside html
            assert "<html" in output


class TestReportGeneratorJSON:
    def test_create_json_report_valid_json(self, valid_report_instance):
        output = ReportGenerator.create_json_report(valid_report_instance)
        data = json.loads(output)
        assert "report_id" in data
        assert "findings" in data

    def test_create_json_report_summary_included(self, valid_report_instance):
        output = ReportGenerator.create_json_report(valid_report_instance)
        data = json.loads(output)
        # The logic adds summary from stats or existing summary
        assert "summary" in data or "stats" in data

    def test_create_json_report_handles_exception(self):
        # Mock model_dump to raise exception
        report = AuditReport(report_id="1", generated_at="2023-01-01", target_environment="test", findings=[])
        with mock.patch.object(report, "model_dump", side_effect=ValueError("dump error")):
            output = ReportGenerator.create_json_report(report)
            data = json.loads(output)
            assert "error" in data


class TestReportGeneratorSave:
    @mock.patch("report_generator.ReportGenerator.create_cli_text")
    @mock.patch("pathlib.Path.mkdir")
    @mock.patch("builtins.open")
    def test_save_report_cli_format(self, mock_open, mock_mkdir, mock_cli, valid_report_instance, monkeypatch):
        mock_file = mock.MagicMock()
        mock_file.name = "report.txt"
        mock_open.return_value.__enter__.return_value = mock_file
        
        mock_path = mock.Mock(spec=Path)
        monkeypatch.setattr("report_generator.Path", mock_path)
        mock_path.return_value = mock_path # Path instance

        result = ReportGenerator.save_report(valid_report_instance, Path("/tmp/test_cli"), "cli")
        
        mock_mkdir.assert_called_once()
        assert result.suffix == ".txt"

    @mock.patch("report_generator.ReportGenerator.create_html_report")
    @mock.patch("pathlib.Path.mkdir")
    @mock.patch("builtins.open")
    def test_save_report_html_format(self, mock_open, mock_mkdir, mock_html, valid_report_instance, monkeypatch):
        mock_file = mock.MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        mock_path = mock.Mock(spec=Path)
        monkeypatch.setattr("report_generator.Path", mock_path)
        mock_path.return_value = mock_path

        result = ReportGenerator.save_report(valid_report_instance, Path("/tmp/test_html"), "html")
        
        assert result.suffix == ".html"

    def test_save_report_unsupported_format(self, valid_report_instance):
        with pytest.raises(ValueError, match="Unsupported format type"):
            ReportGenerator.save_report(valid_report_instance, Path("/tmp/test"), "xml")

    def test_save_report_permission_error(self, valid_report_instance, monkeypatch):
        mock_path = mock.Mock(spec=Path)
        monkeypatch.setattr("report_generator.Path", mock_path)
        mock_path.return_value = mock_path
        mock_path.parent.exists.return_value = False
        mock_path.parent.mkdir.side_effect = PermissionError
        
        with pytest.raises(PermissionError):
            ReportGenerator.save_report(valid_report_instance, Path("/tmp/test_perm"), "cli")


class TestReportGeneratorValidateFormat:
    def test_validate_format_valid_cli(self):
        result = ReportGenerator.validate_format("cli")
        assert result == "cli"

    def test_validate_format_valid_html(self):
        result = ReportGenerator.validate_format("html")
        assert result == "html"

    def test_validate_format_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid format"):
            ReportGenerator.validate_format("pdf")

    def test_validate_format_case_sensitive(self):
        with pytest.raises(ValueError):
            ReportGenerator.validate_format("CLI")
    
    @mock.patch("report_generator.click.Choice")
    def test_validate_format_click_error_mapping(self, mock_choice_class, monkeypatch):
        mock_choice = mock.Mock()
        mock_choice.convert = mock.Mock(side_effect=click.BadParameter("bad"))
        mock_choice_class.return_value = mock_choice
        
        with pytest.raises(ValueError):
            ReportGenerator.validate_format("bad_format")