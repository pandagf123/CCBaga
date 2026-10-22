# [INPUT]: Synthetic macOS bundles, mock strict SSH/known_hosts, and malicious no-network fixtures.
# [OUTPUT]: Offline fail-closed test results; no login, real SSH, browser, or credentials.
# [POS]: P2 fixed-host SV observer regression suite, independent of live Mac/SV install.
# [PROTOCOL]: Keep suite synchronized with observer script, docs and bounded workflow.
"""Offline no-network regressions for CCBaga's observational Claude adapter."""
from __future__ import annotations

import importlib.util
import base64
import hashlib
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
        self.known_hosts = self.root / "known_hosts"
        self.known_hosts.write_text("# fixture only\n", encoding="utf-8")
        self.known_hosts.chmod(0o600)
        self.host_key = base64.b64encode(b"synthetic ED25519 known_hosts fixture").decode()
        self.expected_fingerprint = ("SHA256:" + base64.b64encode(
            hashlib.sha256(b"synthetic ED25519 known_hosts fixture").digest()
        ).decode().rstrip("="))

    def fake_lookup(self, argv, **kwargs):
        self.lookup_args = argv
        return SimpleNamespace(returncode=0,
            stdout="|1|hashedFixture ssh-ed25519 " + self.host_key + "\n", stderr="")

    def remote_status(self, host=None, identity=None, executor=None, lookup=None,
                      **options):
        return m.remote_status(
            m.SV_HOST if host is None else host,
            self.key if identity is None else identity,
            executor=self.fake_exec if executor is None else executor,
            known_hosts=self.known_hosts,
            lookup=self.fake_lookup if lookup is None else lookup,
            expected_identity=self.key,
            expected_host_fingerprint=self.expected_fingerprint,
            **options)

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
        out = self.remote_status(executor=self.fake_exec)
        self.assertEqual(out["version"], "2.1.304")
        argv = self.executed_args
        self.assertEqual(argv[0], "ssh")
        self.assertEqual(argv[-2:], [m.SV_HOST, "python3 -"])\n        self.assertIn("-F", argv)\n        self.assertIn("/dev/null", argv)\n        self.assertIn("HostKeyAlgorithms=ssh-ed25519", argv)\n        self.assertIn("IdentityAgent=none", argv)\n        self.assertIn("UserKnownHostsFile=" + str(self.known_hosts), argv)\n        self.assertIn("ssh-keygen", self.lookup_args)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ProxyCommand=none", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertEqual(self.executed_options["input"], m.SV_PROBE)
        self.assertTrue(self.executed_options["capture_output"])
        self.assertIn("timeout", self.executed_options)

    def test_host_with_ssh_option_is_rejected_before_any_execution(self):
        with self.assertRaisesRegex(ValueError, "HOST_NOT_ALLOWED"):
            self.remote_status("-oProxyCommand=unsafe", executor=self.fake_exec)

    def test_relative_path_or_extra_ssh_user_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "HOST_NOT_ALLOWED"):
            self.remote_status("ubuntu@example.test", executor=self.fake_exec)

    def test_world_readable_ssh_identity_fails_closed(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "SSH_IDENTITY_NOT_PRIVATE_OR_NOT_OWNED"):
            self.remote_status(executor=self.fake_exec)

    def test_symlink_ssh_identity_fails_closed(self):
        link = self.root / "link"
        link.symlink_to(self.key)
        with self.assertRaisesRegex(ValueError, "SSH_IDENTITY_SYMLINK_DENIED"):
            self.remote_status(identity=link, executor=self.fake_exec)

    def test_ssh_error_does_not_expose_stderr_secret(self):
        def failing(argv, **kwargs):
            return SimpleNamespace(returncode=255, stdout="",
                                   stderr="password=secret; token=secret")
        with self.assertRaisesRegex(ValueError, "^SSH_FAILED$") as caught:
            self.remote_status(executor=failing)
        self.assertNotIn("secret", str(caught.exception))

    def test_ssh_timeout_fails_closed(self):
        def timeout(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 40)
        with self.assertRaisesRegex(ValueError, "SSH_TIMEOUT"):
            self.remote_status(executor=timeout)

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


    def test_server_identity_wrong_even_when_ssh_mock_succeeds(self):
        with self.assertRaisesRegex(ValueError, "HOST_NOT_ALLOWED"):
            self.remote_status("attacker.example", executor=self.fake_exec)

    def test_ssh_config_is_not_inherited(self):
        self.remote_status(executor=self.fake_exec)
        argv = self.executed_args
        self.assertEqual(argv[argv.index("-F") + 1], "/dev/null")
        self.assertIn("ProxyCommand=none", argv)
        self.assertIn("ProxyJump=none", argv)
        self.assertIn("GlobalKnownHostsFile=/dev/null", argv)
        self.assertIn("ControlMaster=no", argv)

    def test_mismatched_known_host_fingerprint_rejected_before_ssh(self):
        self.host_key = base64.b64encode(b"attacker key").decode()
        def must_not_run(argv, **kwargs):
            raise AssertionError("Remote ssh must not run before pin check")
        with self.assertRaisesRegex(ValueError, "SV_HOST_KEY_PIN_MISMATCH"):
            self.remote_status(executor=must_not_run)

    def test_symlink_known_hosts_rejected(self):
        target = self.root / "shadow_hosts"
        target.write_text("fixture", encoding="utf-8")
        self.known_hosts.unlink()
        self.known_hosts.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "KNOWN_HOSTS_SYMLINK_DENIED"):
            self.remote_status()

    def test_missing_known_host_fails_closed(self):
        def missing(argv, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="not present")
        with self.assertRaisesRegex(ValueError, "SV_HOST_KEY_NOT_FOUND"):
            self.remote_status(lookup=missing)

    def test_multiple_conflicting_ed25519_keys_rejected(self):
        def duplicated(argv, **kwargs):
            return SimpleNamespace(returncode=0,
                stdout="host ssh-ed25519 " + self.host_key + "\n" +
                       "host ssh-ed25519 " + base64.b64encode(b"different").decode() + "\n",
                stderr="")
        with self.assertRaisesRegex(ValueError, "SV_HOST_KEY_PIN_MISMATCH"):
            self.remote_status(lookup=duplicated)

    def test_identity_path_is_pinned(self):
        other = self.root / "different-identity"
        other.write_text("fixture", encoding="utf-8")
        other.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "SSH_IDENTITY_PATH_MISMATCH"):
            self.remote_status(identity=other)

    def test_contents_intermediate_symlink_is_rejected(self):
        p = self.root / "system" / "CCBaga-A.app"
        p.mkdir(parents=True)
        external = self.root / "fake_contents"
        external.mkdir()
        (external / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "ai.local.requirement-french"
        }))
        (p / "Contents").symlink_to(external, target_is_directory=True)
        out = m.local_inventory(home=self.root, system_app_dir=self.root / "system")
        self.assertEqual(
            out["applications"]["CCBaga-A.app"]["locations"][0]["state"],
            "UNTRUSTED_PATH",
        )

    def test_symlink_info_plist_is_rejected(self):
        p = self.root / "system" / "CCBaga-A.app" / "Contents"
        p.mkdir(parents=True)
        external = self.root / "external.plist"
        external.write_bytes(plistlib.dumps({"CFBundleIdentifier": "ai.local.requirement-french"}))
        (p / "Info.plist").symlink_to(external)
        out = m.local_inventory(home=self.root, system_app_dir=self.root / "system")
        self.assertEqual(
            out["applications"]["CCBaga-A.app"]["locations"][0]["state"],
            "UNTRUSTED_PATH")

    def test_oversized_plist_is_rejected(self):
        p = self.root / "system" / "CCBaga-A.app" / "Contents"
        p.mkdir(parents=True)
        (p / "Info.plist").write_bytes(b"x" * (1024 * 1024 + 1))
        out = m.local_inventory(home=self.root, system_app_dir=self.root / "system")
        self.assertEqual(out["applications"]["CCBaga-A.app"]["state"], "NEEDS_REVIEW")



if __name__ == "__main__":
    unittest.main()
