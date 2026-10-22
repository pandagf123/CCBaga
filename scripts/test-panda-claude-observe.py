"""Offline no-network regressions for CCBaga's observational Claude adapter."""
from __future__ import annotations

import importlib.util
import json
import os
import plistlib
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location(
    "panda_claude_observe", Path(__file__).with_name("panda-claude-observe.py")
)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

BASE_RESULT = {
    "schema": "panda.ccbaga.sv-claude-observation.v1",
    "identity": "EXPECTED",
    "uid": 1000,
    "cli": "PRESENT",
    "version": "2.1.304",
    "auth": "NOT_SIGNED_IN",
}


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "id_ed25519"
        self.key.write_text("fixture only", encoding="utf-8")
        self.key.chmod(0o600)

    def fake_exec(self, argv, **kwargs):
        self.executed_args = argv
        self.executed_options = kwargs
        return SimpleNamespace(returncode=0, stdout=json.dumps(BASE_RESULT), stderr="")

    def test_local_missing_is_not_a_claim_of_absence_everywhere(self):
        out = m.local_inventory(home=self.root, system_app_dir=self.root / "system")
        self.assertEqual(out["applications"]["CCBaga-A.app"]["state"],
                         "NOT_IN_STANDARD_LOCATIONS")
        self.assertEqual(out["signed_or_running"], "NOT_CHECKED")

    def test_valid_existing_bundle_metadata(self):
        p = self.root / "system" / "CCBaga-A.app" / "Contents"
        p.mkdir(parents=True)
        (p / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "ai.local.requirement-french",
            "CFBundleShortVersionString": "0.2.0",
        }))
        out = m.local_inventory(home=self.root, system_app_dir=self.root / "system")
        self.assertEqual(out["applications"]["CCBaga-A.app"]["state"], "FOUND")

    def test_wrong_bundle_id_never_passes(self):
        p = self.root / "system" / "CCBaga-A.app" / "Contents"
        p.mkdir(parents=True)
        (p / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "fake.app"}))
        out = m.local_inventory(home=self.root, system_app_dir=self.root / "system")
        self.assertEqual(out["applications"]["CCBaga-A.app"]["state"], "NEEDS_REVIEW")

    def test_bundle_symlink_is_not_followed(self):
        (self.root / "system").mkdir()
        (self.root / "system" / "CCBaga-A.app").symlink_to(self.root, target_is_directory=True)
        out = m.local_inventory(home=self.root, system_app_dir=self.root / "system")
        self.assertEqual(out["applications"]["CCBaga-A.app"]["locations"][0]["state"],
                         "UNTRUSTED_PATH")

    def test_wrong_remote_uid_fails_closed(self):
        rec = dict(BASE_RESULT, uid=1002)
        with self.assertRaisesRegex(ValueError, "SV_USER_IDENTITY_MISMATCH"):
            m.safe_remote_result(json.dumps(rec))

    def test_wrong_remote_schema_fails_closed(self):
        rec = dict(BASE_RESULT, schema="unknown")
        with self.assertRaisesRegex(ValueError, "REMOTE_SCHEMA_MISMATCH"):
            m.safe_remote_result(json.dumps(rec))

    def test_remote_payload_cannot_leak_identity_fields(self):
        rec = dict(BASE_RESULT, email="sensitive@example.test",
                   token="do-not-print", account_id="secret")
        out = m.safe_remote_result(json.dumps(rec))
        self.assertNotIn("email", json.dumps(out))
        self.assertNotIn("token", json.dumps(out))
        self.assertNotIn("account_id", json.dumps(out))

    def test_invented_auth_status_rejected(self):
        rec = dict(BASE_RESULT, auth="ELIGIBLE_AND_SUBSCRIBED")
        with self.assertRaisesRegex(ValueError, "SV_AUTH_STATE_INVALID"):
            m.safe_remote_result(json.dumps(rec))

    def test_remote_ssh_command_uses_fixed_options_and_no_shell(self):
        out = m.remote_status("example.test", self.key, executor=self.fake_exec)
        self.assertEqual(out["version"], "2.1.304")
        argv = self.executed_args
        self.assertEqual(argv[0], "ssh")
        self.assertEqual(argv[-2:], ["example.test", "python3 -"])
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ProxyCommand=none", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertEqual(self.executed_options["input"], m.SV_PROBE)
        self.assertTrue(self.executed_options["capture_output"])
        self.assertIn("timeout", self.executed_options)

    def test_host_with_ssh_option_is_rejected_before_any_execution(self):
        with self.assertRaisesRegex(ValueError, "HOST_NOT_ALLOWED"):
            m.remote_status("-oProxyCommand=unsafe", self.key, executor=self.fake_exec)

    def test_relative_path_or_extra_ssh_user_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "HOST_NOT_ALLOWED"):
            m.remote_status("ubuntu@example.test", self.key, executor=self.fake_exec)

    def test_world_readable_ssh_identity_fails_closed(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "SSH_IDENTITY_NOT_PRIVATE_OR_NOT_OWNED"):
            m.remote_status("example.test", self.key, executor=self.fake_exec)

    def test_symlink_ssh_identity_fails_closed(self):
        link = self.root / "link"
        link.symlink_to(self.key)
        with self.assertRaisesRegex(ValueError, "SSH_IDENTITY_SYMLINK_DENIED"):
            m.remote_status("example.test", link, executor=self.fake_exec)

    def test_ssh_error_does_not_expose_stderr_secret(self):
        def failing(argv, **kwargs):
            return SimpleNamespace(returncode=255, stdout="",
                                   stderr="password=secret; token=secret")
        with self.assertRaisesRegex(ValueError, "^SSH_FAILED$") as caught:
            m.remote_status("example.test", self.key, executor=failing)
        self.assertNotIn("secret", str(caught.exception))

    def test_ssh_timeout_fails_closed(self):
        def timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 40)
        with self.assertRaisesRegex(ValueError, "SSH_TIMEOUT"):
            m.remote_status("example.test", self.key, executor=timeout)

    def test_remote_overlong_output_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "REMOTE_OUTPUT_TOO_LARGE"):
            m.safe_remote_result("x" * 4097)

    def test_probe_does_not_attempt_login_or_model_calls(self):
        self.assertIn('"auth", "status", "--text"', m.SV_PROBE)
        self.assertNotIn('"auth", "login"', m.SV_PROBE)
        self.assertNotIn('"-p"', m.SV_PROBE)
        self.assertNotIn('os.environ', m.SV_PROBE)
        self.assertNotIn("shell=True", m.SV_PROBE)

    def test_bad_version_is_not_a_status(self):
        rec = dict(BASE_RESULT, version="2.1.304; curl secret")
        with self.assertRaisesRegex(ValueError, "SV_VERSION_INVALID"):
            m.safe_remote_result(json.dumps(rec))


if __name__ == "__main__":
    unittest.main()
