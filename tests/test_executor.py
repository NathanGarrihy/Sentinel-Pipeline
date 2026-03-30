import hashlib
import subprocess
from unittest.mock import MagicMock

from sentinel.core.executor import ExecutorProtocol, ToolExecutor
from sentinel.models.execution import ExecutionResult


class TestToolExecutor:
    def test_execute_returns_correct_result(self, mocker) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "hello world"
        mock_result.returncode = 0
        mocker.patch("sentinel.core.executor.subprocess.run", return_value=mock_result)

        executor = ToolExecutor()
        result = executor.execute(["echo", "hello world"])

        expected_hash = hashlib.sha256("hello world".encode()).hexdigest()
        assert result.stdout == "hello world"
        assert result.exit_code == 0
        assert result.output_hash == expected_hash

    def test_execute_passes_correct_args(self, mocker) -> None:
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0
        mock_run = mocker.patch(
            "sentinel.core.executor.subprocess.run", return_value=mock_result
        )

        executor = ToolExecutor()
        executor.execute(["trivy", "image", "myapp:latest"])

        mock_run.assert_called_once_with(
            ["trivy", "image", "myapp:latest"],
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_nonzero_exit_code(self, mocker) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "error output"
        mock_result.returncode = 1
        mocker.patch("sentinel.core.executor.subprocess.run", return_value=mock_result)

        executor = ToolExecutor()
        result = executor.execute(["false"])

        assert result.exit_code == 1
        assert result.stdout == "error output"


class TestExecutorProtocol:
    def test_mock_satisfies_protocol(self) -> None:
        mock_executor = MagicMock(spec=ExecutorProtocol)
        mock_executor.execute.return_value = ExecutionResult(
            stdout="mocked", stderr="", exit_code=0, output_hash="aaa"
        )

        result = mock_executor.execute(["test"])
        assert result.stdout == "mocked"

    def test_tool_executor_satisfies_protocol(self) -> None:
        executor: ExecutorProtocol = ToolExecutor()
        assert hasattr(executor, "execute")
