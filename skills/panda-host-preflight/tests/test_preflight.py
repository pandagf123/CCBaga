"""Offline, deterministic regression tests for the host preflight Skill."""
from __future__ import annotations

import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / "scripts" / "preflight.py"
SPEC = importlib.util.spec_from_file_location("panda_host_preflight", FILE)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PreflightTests(unittest.TestCase):
    def good(self):
        return {
            "os": "linux", "arch": "x86_64", "non_root": True,
            "memory_mib": 4096, "root_free_mib": 1024,
        }

    def test_all_minimums_pass_at_boundary(self):
        self.assertEqual(set(module.classify(self.good()).values()), {"PASS"})

    def test_unknown_is_not_a_success(self):
        values = self.good()
        values["memory_mib"] = None
        self.assertEqual(module.classify(values)["memory_minimum"], "UNKNOWN")

    def test_root_denied(self):
        values = self.good()
        values["non_root"] = False
        self.assertEqual(module.classify(values)["non_root"], "FAIL")

    def test_low_memory_and_disk_denied(self):
        values = self.good()
        values["memory_mib"] = 4095
        values["root_free_mib"] = 1023
        checks = module.classify(values)
        self.assertEqual(checks["memory_minimum"], "FAIL")
        self.assertEqual(checks["free_disk_minimum"], "FAIL")

    def test_invalid_arch_denied(self):
        values = self.good()
        values["arch"] = "mips"
        self.assertEqual(module.classify(values)["supported_arch"], "FAIL")

    def test_no_external_network_by_default(self):
        with patch.object(module, "tls_probe", side_effect=AssertionError("network requested")):
            with patch.object(module.platform, "system", return_value="Linux"), \
                 patch.object(module.platform, "machine", return_value="x86_64"), \
                 patch.object(module.os, "geteuid", return_value=1000), \
                 patch.object(module, "memory_mib", return_value=8192), \
                 patch.object(module, "free_mib", return_value=4096), \
                 patch.object(module.shutil, "which", return_value=None):
                result = module.build_report()
        self.assertEqual(result["decision"], "READY_FOR_INSTALL_REVIEW")
        self.assertIsNone(result["network"]["results"])
        self.assertFalse(result["observed"]["claude_cli_on_path"])

    def test_explicit_network_only_to_fixed_hosts(self):
        with patch.object(module, "tls_probe", return_value="PASS") as probe, \
             patch.object(module.platform, "system", return_value="Linux"), \
             patch.object(module.platform, "machine", return_value="aarch64"), \
             patch.object(module.os, "geteuid", return_value=1000), \
             patch.object(module, "memory_mib", return_value=8192), \
             patch.object(module, "free_mib", return_value=4096), \
             patch.object(module.shutil, "which", return_value="/secret/path"):
            report = module.build_report(network=True, timeout=2.0)
        self.assertEqual([c.args[0] for c in probe.call_args_list], list(module.HOSTS))
        self.assertTrue(report["network"]["performed"])
        payload = json.dumps(report)
        self.assertNotIn("/secret/path", payload)
        self.assertNotIn("token", str(report["observed"]).lower())

    def test_cli_presence_does_not_imply_authenticated(self):
        with patch.object(module.platform, "system", return_value="Linux"), \
             patch.object(module.platform, "machine", return_value="x86_64"), \
             patch.object(module.os, "geteuid", return_value=0), \
             patch.object(module, "memory_mib", return_value=8192), \
             patch.object(module, "free_mib", return_value=4096), \
             patch.object(module.shutil, "which", return_value="/usr/bin/claude"):
            result = module.build_report()
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertTrue(result["observed"]["claude_cli_on_path"])

    def test_main_json_and_status_code(self):
        fake = {
            "decision": "UNKNOWN", "schema": module.SCHEMA,
            "observed": {}, "checks": {}, "network": {},
        }
        out = io.StringIO()
        with patch.object(module, "build_report", return_value=fake), redirect_stdout(out):
            rc = module.main([])
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out.getvalue())["schema"], module.SCHEMA)

    def test_timeout_validation(self):
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
            module.main(["--timeout", "0"])
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
