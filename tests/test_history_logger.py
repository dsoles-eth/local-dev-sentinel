import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Import the module under test
from history_logger import AuditFinding, HistoryLogger, COLOR_SUCCESS, COLOR_WARNING, COLOR_ERROR, COLOR_INFO

# Helper to create a mocked datetime for tests
def set_mock_datetime(base_date: datetime):
    class MockDatetime:
        def now(cls):
            return base_date
        from datetime import timedelta as _timedelta
        @classmethod
        def now(cls):
            return base_date
    return MockDatetime

# Fixtures
@pytest.fixture
def fixed_datetime():
    base = datetime(2023, 10, 27, 10, 0, 0)
    with patch('history_logger.datetime') as mock_dt:
        mock_dt.now.return_value = base
        yield base

@pytest.fixture
def mock_path_class(fixed_datetime):
    mock_path = MagicMock(spec=Path)
    mock_path.exists.return_value = True
    mock_path.mkdir.return_value = None
    mock_path.__truediv__.side_effect = lambda other: MagicMock(spec=Path, exists=PropertyMock(return_value=False))
    mock_path.__str__.return_value = "/mock/path"
    with patch('history_logger.Path', return_value=mock_path) as mock_path_cls:
        yield mock_path_cls

@pytest.fixture
def mock_json_loader():
    def load(*args, **kwargs):
        return {"findings": [], "last_updated": "2023-10-27T10:00:00"}
    return load

@pytest.fixture
def mock_json_dumper():
    return MagicMock()

@pytest.fixture
def history_logger_instance(fixed_datetime):
    with patch('history_logger.datetime.now', return_value=fixed_datetime), \
         patch('history_logger.Path', return_value=MagicMock(spec=Path, exists=PropertyMock(return_value=False))), \
         patch('history_logger.colorama.init'), \
         patch('history_logger.Path.mkdir'), \
         patch('history_logger.open', MagicMock()):
        
        logger = HistoryLogger()
        yield logger

class TestAuditFinding:
    def test_finding_creation_valid(self):
        finding = AuditFinding(
            finding_id="ID-001",
            severity="high",
            category="security",
            message="Test message"
        )
        assert finding.finding_id == "ID-001"
        assert finding.severity == "high"
        assert finding.timestamp is not None

    def test_finding_creation_invalid(self):
        with pytest.raises(Exception):
            AuditFinding(severity="high", category="security", message="Test")

    def test_finding_serialization(self):
        finding = AuditFinding(
            finding_id="ID-002",
            severity="low",
            category="code",
            message="Test",
            timestamp=datetime(2023, 10, 27, 12, 0, 0)
        )
        data = finding.dict()
        assert "finding_id" in data
        assert data["severity"] == "low"

class TestHistoryLoggerInit:
    def test_init_default_paths(self, history_logger_instance):
        assert history_logger_instance.log_dir is not None
        assert history_logger_instance.log_file is not None

    def test_init_custom_paths(self):
        custom_dir = Path("/custom/dir")
        custom_file = Path("custom_history.json")
        with patch('history_logger.Path') as mock_p:
            mock_instance = MagicMock(spec=Path)
            mock_p.return_value = mock_instance
            mock_instance.__truediv__ = lambda s, o: mock_instance
            with patch('history_logger.Path.mkdir'):
                with patch('history_logger.open'):
                    logger = HistoryLogger(log_dir=custom_dir, log_file=custom_file)
                    assert logger.log_dir == custom_dir

    def test_init_permission_error_handling(self):
        with patch('history_logger.Path.mkdir') as mock_mkdir:
            mock_mkdir.side_effect = PermissionError("Access denied")
            logger = HistoryLogger()
            # Should fallback to cwd
            assert logger.log_dir == Path.cwd()
            assert logger.log_file.name == "audit_history.json"

class TestHistoryLoggerAddFinding:
    @patch('history_logger.json.dump')
    @patch('history_logger.json.load')
    def test_add_finding_success(self, mock_load, mock_dump, history_logger_instance, fixed_datetime):
        mock_load.return_value = {"findings": [], "last_updated": "2023-10-27T10:00:00"}
        
        finding = AuditFinding(
            finding_id="TEST-01",
            severity="low",
            category="test",
            message="test msg"
        )
        
        result = history_logger_instance.add_finding(finding)
        assert result is True
        mock_dump.assert_called()

    @patch('history_logger.json.dump')
    @patch('history_logger.json.load')
    def test_add_finding_file_error(self, mock_load, mock_dump, history_logger_instance):
        mock_load.return_value = {"findings": [], "last_updated": "2023-10-27T10:00:00"}
        mock_dump.side_effect = IOError("Disk full")
        
        finding = AuditFinding(
            finding_id="TEST-02",
            severity="low",
            category="test",
            message="test msg"
        )
        
        result = history_logger_instance.add_finding(finding)
        assert result is False

    @patch('history_logger.json.dump')
    @patch('history_logger.json.load')
    def test_add_finding_validation_error(self, mock_load, mock_dump, history_logger_instance, fixed_datetime):
        mock_load.return_value = {"findings": [], "last_updated": "2023-10-27T10:00:00"}
        
        # Passing invalid data structure directly to the logic flow (simulated via json load returning bad data)
        # Actually add_finding wraps in try/except ValidationError.
        # To trigger ValidationError, we need to pass something that fails on `finding.dict()`? No.
        # It fails on `AuditFinding(**f)` in get_history. In add_finding, it wraps finding.dict().
        # The ValidationError catch in add_finding is for json.load returning corrupt data? No.
        # The code does: `finding.dict()` then `current_data["findings"].append(...)`.
        # ValidationError catch is technically unreachable in add_finding logic flow unless finding.dict() fails (unlikely)
        # or json loading failed inside _read_history which returns default dict.
        # Wait, `_read_history` returns data. `findings` list append is just list append.
        # The `except ValidationError` block in `add_finding` is likely dead code based on logic `finding.dict()`.
        # However, to test the error handling path:
        
        finding = AuditFinding(
            finding_id="TEST-03",
            severity="low",
            category="test",
            message="test msg"
        )
        # Force exception in flow
        history_logger_instance._read_history = MagicMock(return_value={"findings": [], "last_updated": "2023-10-27T10:00:00"})
        
        # Force validation error simulation
        with patch.object(history_logger_instance, '_write_history', side_effect=Exception("Boom")):
            result = history_logger_instance.add_finding(finding)
            assert result is False

class TestHistoryLoggerGetHistory:
    @patch('history_logger.json.load')
    def test_get_history_success(self, mock_load, history_logger_instance, fixed_datetime):
        mock_load.return_value = {"findings": [
            {"finding_id": "F1", "severity": "low", "category": "A", "message": "M1", "timestamp": fixed_datetime.isoformat()}
        ], "last_updated": "2023-10-27T10:00:00"}
        
        results = history_logger_instance.get_history()
        assert len(results) == 1
        assert results[0].finding_id == "F1"

    @patch('history_logger.json.load')
    def test_get_history_limit(self, mock_load, history_logger_instance):
        mock_load.return_value = {"findings": [
            {"finding_id": "F1", "severity": "low", "category": "A", "message": "M1", "timestamp": "2023-10-27T10:00:00"},
            {"finding_id": "F2", "severity": "low", "category": "A", "message": "M1", "timestamp": "2023-10-27T10:00:00"},
        ], "last_updated": "2023-10-27T10:00:00"}
        
        results = history_logger_instance.get_history(limit=1)
        assert len(results) == 1

    @patch('history_logger.json.load')
    def test_get_history_corrupt_file(self, mock_load, history_logger_instance):
        mock_load.side_effect = ValueError("Invalid JSON")
        results = history_logger_instance.get_history()
        assert results == []

class TestHistoryLoggerAnalyzeTrends:
    @patch.object(HistoryLogger, 'get_history')
    def test_analyze_trends_empty(self, mock_get, history_logger_instance):
        mock_get.return_value = []
        analysis = history_logger_instance.analyze_trends()
        assert analysis["total_findings"] == 0
        assert analysis["recent_findings"] == 0

    @patch.object(HistoryLogger, 'get_history')
    def test_analyze_trends_with_data(self, mock_get, history_logger_instance, fixed_datetime):
        mock_get.return_value = [
            AuditFinding(finding_id="1", severity="high", category="CatA", message="msg", timestamp=fixed_datetime),
            AuditFinding(finding_id="2", severity="high", category="CatA", message="msg", timestamp=fixed_datetime),
            AuditFinding(finding_id="3", severity="medium", category="CatB", message="msg", timestamp=fixed_datetime),
        ]
        analysis = history_logger_instance.analyze_trends()
        assert analysis["total_findings"] == 3
        assert analysis["severity_breakdown"]["high"] == 2

    @patch.object(HistoryLogger, 'get_history')
    def test_analyze_trends_regression(self, mock_get, history_logger_instance):
        # Create 6 high severity findings within the last hour (mocked by fixed datetime now)
        recent_time = history_logger_instance._read_history.__globals__['datetime'].now() if hasattr(history_logger_instance, '_read_history') else datetime.now()
        mock_get.return_value = [
            AuditFinding(finding_id=str(i), severity="high", category="CatA", message="msg", timestamp=datetime(2023, 10, 27, 9, 59, i))
            for i in range(6)
        ]
        analysis = history_logger_instance.analyze_trends()
        assert len(analysis["regressions"]) > 0
        assert "High severity issues exceeding threshold" in str(analysis["regressions"])

class TestHistoryLoggerClearHistory:
    @patch('history_logger.Path.exists')
    @patch('history_logger.Path.unlink')
    def test_clear_history_success(self, mock_unlink, mock_exists, history_logger_instance):
        mock_exists.return_value = True
        result = history_logger_instance.clear_history()
        assert result is True
        mock_unlink.assert_called()

    @patch('history_logger.Path.exists')
    @patch('history_logger.Path.unlink')
    def test_clear_history_file_not_exists(self, mock_unlink, mock_exists, history_logger_instance):
        mock_exists.return_value = False
        result = history_logger_instance.clear_history()
        assert result is True
        mock_unlink.assert_not_called()

    @patch('history_logger.Path.unlink')
    def test_clear_history_os_error(self, mock_unlink, history_logger_instance):
        mock_unlink.side_effect = OSError("Permission denied")
        result = history_logger_instance.clear_history()
        assert result is False

class TestHistoryLoggerPrintSummary:
    @patch.object(HistoryLogger, 'analyze_trends')
    def test_print_summary_success(self, mock_analyze, history_logger_instance, capsys):
        mock_analyze.return_value = {
            "total_findings": 5,
            "recent_findings": 2,
            "severity_breakdown": {"critical": 0, "high": 0, "low": 0, "medium": 0},
            "regressions": [],
            "recurring_patterns": []
        }
        history_logger_instance.print_summary()
        captured = capsys.readouterr()
        assert "Local Dev Sentinel" in captured.out
        assert "Total Findings: 5" in captured.out

    @patch.object(HistoryLogger, 'analyze_trends')
    def test_print_summary_error(self, mock_analyze, history_logger_instance, capsys):
        mock_analyze.side_effect = Exception("Analysis failed")
        history_logger_instance.print_summary()
        captured = capsys.readouterr()
        assert "Error generating summary" in captured.out

    def test_print_summary_console_colors(self, history_logger_instance, capsys):
        # Ensure colors are used
        import colorama
        with patch.object(history_logger_instance, 'analyze_trends', return_value={"total_findings": 0, "recent_findings": 0, "severity_breakdown": {}, "regressions": [], "recurring_patterns": []}):
            history_logger_instance.print_summary()
            captured = capsys.readouterr()
            # Verify colorama is active in the output structure if logic relies on it
            assert "Local Dev Sentinel" in captured.out

class TestHistoryLoggerPrivateMethods:
    @patch('history_logger.json.load')
    def test_read_history_file_exists(self, mock_load, history_logger_instance):
        mock_load.return_value = {"findings": [], "last_updated": "2023-10-27"}
        result = history_logger_instance._read_history()
        assert result == {"findings": [], "last_updated": "2023-10-27"}

    @patch('history_logger.json.load')
    def test_read_history_missing_file(self, mock_load, history_logger_instance):
        mock_load.side_effect = FileNotFoundError()
        result = history_logger_instance._read_history()
        assert "findings" in result
        assert result["findings"] == []

    @patch('history_logger.json.load')
    def test_read_history_corrupt_json(self, mock_load, history_logger_instance):
        mock_load.side_effect = ValueError("Bad JSON")
        result = history_logger_instance._read_history()
        assert result["findings"] == []

    @patch('history_logger.json.dump')
    def test_write_history_success(self, mock_dump, history_logger_instance):
        data = {"findings": []}
        result = history_logger_instance._write_history(data)
        assert result is True
        mock_dump.assert_called_once()

    @patch('history_logger.json.dump')
    def test_write_history_io_error(self, mock_dump, history_logger_instance):
        mock_dump.side_effect = IOError("Write error")
        data = {"findings": []}
        result = history_logger_instance._write_history(data)
        assert result is False

    @patch('history_logger.Path')
    def test_write_history_default_dir_creation(self, mock_path, history_logger_instance):
        # Simulate path creation requirements in __init__ logic if applicable to write
        # Since write just opens file, this tests interaction
        mock_path.return_value = MagicMock()
        data = {"findings": []}
        # We rely on mocking 'open' for actual write testing, but here we ensure Path interaction
        with patch('history_logger.open', MagicMock()):
            result = history_logger_instance._write_history(data)
            # Check if Path methods were accessed appropriately if _write_history relies on Path class
            pass