
import sys
import pytest
import qsvm
import yaml
import subprocess

class TestCli:
    def test_1(self):
        sys.argv = ["qsvm", "--help"]

        with pytest.raises(SystemExit):
            res = qsvm.cli.process_args()

    def test_2(self):
        res = subprocess.run(
            ["python3", "-m", "qsvm", "--user", "create", "--stdout", "test"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=None,
            text=True
        )

        assert res.returncode == 0

        parsed = yaml.safe_load(res.stdout)
        assert parsed is not None

    def test_3(self):
        res = subprocess.run(
            ["python3", "-m", "qsvm", "test"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=None,
            text=True
        )

        assert res.returncode == 0

        assert res.stdout.strip() == "ok"

