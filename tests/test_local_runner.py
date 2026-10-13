"""Exercise the real Windows scheduler wrapper with a fake verifier."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.name == "nt", "Windows scheduler wrapper")
class LocalRunnerTests(unittest.TestCase):
    def run_wrapper(self, codes, direct=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            shutil.copyfile(Path(__file__).resolve().parents[1] / "refresh-local.ps1",
                            root / "refresh-local.ps1")
            (root / "codes.json").write_text(json.dumps(codes), encoding="utf-8")
            (root / "verify.py").write_text('''
import json, sys
from pathlib import Path
p = Path("attempts.json")
attempts = json.loads(p.read_text()) if p.exists() else []
attempts.append(sys.argv[1:])
p.write_text(json.dumps(attempts))
print("fake verifier output", file=sys.stderr)
sys.exit(json.loads(Path("codes.json").read_text())[len(attempts)-1])
''', encoding="utf-8")
            command = ["powershell.exe", "-NoProfile", "-NonInteractive",
                       "-ExecutionPolicy", "Bypass", "-File", str(root / "refresh-local.ps1"),
                       "-Python", sys.executable, "-Core", "test core.exe", "-RetryDelaySeconds", "0"]
            if direct:
                command.append("-Direct")
            result = subprocess.run(command, capture_output=True, timeout=30)
            attempts = json.loads((root / "attempts.json").read_text())
            log = (root / "data/local-refresh.log").read_text(encoding="utf-8-sig")
            return result.returncode, attempts, log

    def test_network_error_falls_back_to_direct(self):
        code, attempts, log = self.run_wrapper([1, 0])
        self.assertEqual(code, 0)
        self.assertEqual(attempts, [["--core", "test core.exe"],
                                    ["--core", "test core.exe", "--proxy="]])
        self.assertIn("GitHub route: direct", log)
        self.assertIn("fake verifier output", log)

    def test_publish_error_falls_back_to_configured_proxy(self):
        code, attempts, _ = self.run_wrapper([3, 0], direct=True)
        self.assertEqual(code, 0)
        self.assertIn("--proxy=", attempts[0])
        self.assertNotIn("--proxy=", attempts[1])

    def test_no_qualified_nodes_does_not_retry(self):
        code, attempts, _ = self.run_wrapper([4], direct=True)
        self.assertEqual(code, 4)
        self.assertEqual(len(attempts), 1)

    def test_three_failures_return_failure(self):
        code, attempts, _ = self.run_wrapper([1, 3, 1], direct=True)
        self.assertEqual(code, 1)
        self.assertEqual(["--proxy=" in a for a in attempts], [True, False, True])
