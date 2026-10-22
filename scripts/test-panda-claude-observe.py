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
import pwd
import sys
import plistlib
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
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
        self.key = self.root / m.SV_KEY_RELATIVE
        self.key.parent.mkdir(parents=True)
        self.key.write_text("fixture only", encoding="utf-8")
        self.key.chmod(0o600)
        self.known_hosts = self.root / ".ssh" / "known_hosts"
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
        with patch.object(m, "trusted_account_home", return_value=self.root):
            return m.remote_status(
                m.SV_HOST if host is None else host,
                self.key if identity is None else identity,
                executor=self.fake_exec if executor is None else executor,
                known_hosts=self.known_hosts,
                lookup=self.fake_lookup if lookup is None else lookup,
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
        self.assertFalse(out["credential_values_transmitted"])
        self.assertFalse(out["eligibility_verified"])

    def test_invented_auth_status_rejected(self):
        rec = dict(BASE_RESULT, auth="ELIGIBLE_AND_SUBSCRIBED")
        with self.assertRaisesRegex(ValueError, "SV_AUTH_STATE_INVALID"):
            m.safe_remote_result(json.dumps(rec))

    def test_remote_ssh_command_uses_fixed_options_and_no_shell(self):
        out = self.remote_status(executor=self.fake_exec)
        self.assertEqual(out["version"], "2.1.304")
        argv = self.executed_args
        self.assertEqual(argv[0], m.LOCAL_SSH)
        self.assertEqual(argv[-2:], [m.SV_HOST, m.REMOTE_PYTHON + " -"])
        self.assertIn("-F", argv)
        self.assertIn("/dev/null", argv)
        self.assertIn("HostKeyAlgorithms=ssh-ed25519", argv)
        self.assertIn("IdentityAgent=none", argv)
        self.assertIn("UserKnownHostsFile=" + str(self.known_hosts), argv)
        self.assertEqual(self.lookup_args[0], m.LOCAL_SSH_KEYGEN)
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



    def test_caller_path_cannot_select_ssh_or_ssh_keygen(self):
        self.remote_status()
        self.assertEqual(self.executed_args[0], "/usr/bin/ssh")
        self.assertEqual(self.lookup_args[0], "/usr/bin/ssh-keygen")
        self.assertEqual(self.executed_options["env"]["PATH"], "/usr/bin:/bin")
        self.assertNotIn("PYTHONPATH", self.executed_options["env"])

    def test_arbitrary_local_ssh_executable_is_rejected(self):
        rogue = self.root / "ssh"
        rogue.write_text("#!/bin/sh\n", encoding="utf-8")
        rogue.chmod(0o755)
        with patch.object(m, "LOCAL_SSH", str(rogue)):
            with self.assertRaisesRegex(ValueError, "SYSTEM_TOOL_PATH_NOT_PINNED"):
                self.remote_status()

    def test_arbitrary_local_hostkey_executable_is_rejected(self):
        rogue = self.root / "ssh-keygen"
        rogue.write_text("#!/bin/sh\n", encoding="utf-8")
        rogue.chmod(0o755)
        with patch.object(m, "LOCAL_SSH_KEYGEN", str(rogue)):
            with self.assertRaisesRegex(ValueError, "SYSTEM_TOOL_PATH_NOT_PINNED"):
                self.remote_status()

    def test_remote_interpreter_uses_absolute_system_path(self):
        self.remote_status()
        self.assertEqual(self.executed_args[-1], "/usr/bin/python3 -")
        self.assertNotIn("python3 -", self.executed_args)
        self.assertIn("resolved_cli", m.SV_PROBE)
        self.assertIn("version_root", m.SV_PROBE)
        self.assertIn("parent.lstat()", m.SV_PROBE)

    def test_permission_error_is_unknown_not_absent(self):
        with patch.object(m.os, "open", side_effect=PermissionError(13, "denied")):
            result = m.local_inventory(home=self.root, system_app_dir=self.root / "system")
        for bundle in ("CCBaga-A.app", "CCBaga-B.app"):
            self.assertEqual(result["applications"][bundle]["state"], "NEEDS_REVIEW")
            self.assertTrue(all(
                r["state"] == "UNREADABLE_STANDARD_PATH"
                for r in result["applications"][bundle]["locations"]
            ))

    def test_symlink_swap_after_path_lookup_cannot_be_followed(self):
        # Directory lookup is now descriptor-relative with O_NOFOLLOW, so an
        # intermediate symlink is always rejected by the kernel.
        parent = self.root / "system"
        original = parent / "CCBaga-A.app" / "Contents"
        original.mkdir(parents=True)
        other = self.root / "external"
        other.mkdir()
        (other / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "ai.local.requirement-french"
        }))
        original.rmdir()
        original.symlink_to(other, target_is_directory=True)
        state, _ = m._read_bundle_plist(parent, "CCBaga-A.app")
        self.assertEqual(state, "UNTRUSTED_PATH")

    def test_file_descriptor_metadata_read_still_passes_without_path_reopen(self):
        parent = self.root / "system"
        info = parent / "CCBaga-A.app" / "Contents" / "Info.plist"
        info.parent.mkdir(parents=True)
        info.write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "ai.local.requirement-french",
            "CFBundleShortVersionString": "0.2.49"
        }))
        state, data = m._read_bundle_plist(parent, "CCBaga-A.app")
        self.assertEqual(state, "PRESENT")
        self.assertEqual(data["CFBundleIdentifier"], "ai.local.requirement-french")



    def test_embedded_sv_probe_executes_real_offline_fixture(self):
        """Actually execute SV_PROBE locally, using only a fabricated Claude stub.

        This detects missing imports/runtime errors hidden by mocked SSH tests.
        No real /home/ubuntu paths or credentials, network or Anthropic binary.
        """
        base = self.root / "ubuntu"
        ver = base / ".local" / "share" / "claude" / "versions"
        binary = ver / "2.1.304"
        ver.mkdir(parents=True)
        launcher = base / ".local" / "bin" / "claude"
        launcher.parent.mkdir(parents=True)
        binary.write_text(
            "#!/usr/bin/python3\nimport sys\n"
            "if '--version' in sys.argv: print('2.1.304')\n"
            "else: print('not logged in')\n", encoding="utf-8"
        )
        binary.chmod(0o700)
        launcher.symlink_to("../share/claude/versions/2.1.304")
        # Replace only fixed fixture paths and known fake owner constants in
        # an isolated *local* copy of the embedded probe program.
        probe = m.SV_PROBE.replace("/home/ubuntu", str(base))
        probe = probe.replace("1000", str(os.getuid()))
        probe = probe.replace('"ubuntu"', json.dumps(pwd.getpwuid(os.getuid()).pw_name))
        result = subprocess.run([sys.executable, "-c", probe],
            capture_output=True, text=True, timeout=10, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        self.assertEqual(result.returncode, 0, "embedded SV fixture returned nonzero")
        self.assertNotIn("Traceback", result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record["cli"], "PRESENT")
        self.assertEqual(record["version"], "2.1.304")
        self.assertEqual(record["auth"], "NOT_SIGNED_IN")

    def test_remote_status_rejects_malformed_field_types(self):
        for field in ("cli", "auth"):
            for corrupted in ([], {}, {"token": "secret"}, 5, None, False):
                with self.subTest(field=field, data_type=type(corrupted).__name__):
                    payload = dict(BASE_RESULT, **{field: corrupted})
                    with self.assertRaises(ValueError):
                        m.safe_remote_result(json.dumps(payload))

    def test_remote_status_rejects_unhashable_without_raw_traceback(self):
        def corrupted(argv, **kwargs):
            return SimpleNamespace(returncode=0,
                stdout=json.dumps(dict(BASE_RESULT, auth=["not logged in"])),
                stderr="authentication token sensitive")
        with self.assertRaisesRegex(ValueError, "^REMOTE_STATUS_UNVERIFIABLE$"):
            self.remote_status(executor=corrupted)

    def test_environment_HOME_override_does_not_change_account_home(self):
        observed = m.trusted_account_home()
        with patch.dict(os.environ, {"HOME": str(self.root / "attacker")}):
            self.assertEqual(m.trusted_account_home(), observed)

    def test_symlinked_key_parent_is_denied(self):
        other = self.root / "outside"
        other.mkdir()
        key_name = self.key.name
        (other / key_name).write_text("fixture only", encoding="utf-8")
        (other / key_name).chmod(0o600)
        self.key.unlink()
        self.key.parent.rmdir()
        self.key.parent.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "SSH_IDENTITY_ANCESTRY_UNTRUSTED"):
            self.remote_status()

    def test_symlinked_ssh_parent_is_denied(self):
        other = self.root / "outside"
        other.mkdir()
        ssh_dir = self.root / ".ssh"
        self.key.unlink()
        self.key.parent.rmdir()
        self.known_hosts.unlink()
        ssh_dir.rmdir()
        (other / "known_hosts").write_text("# fake", encoding="utf-8")
        ssh_dir.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "SSH_IDENTITY_ANCESTRY_UNTRUSTED"):
            self.remote_status()

    def test_symlinked_known_hosts_parent_is_denied_independently(self):
        alternate = self.root / "elsewhere"
        alternate.mkdir()
        (alternate / "known_hosts").write_text("# fake", encoding="utf-8")
        self.known_hosts.unlink()
        # Key directory remains real and safe; only known_hosts leaf may be
        # replaced in this test, covered by symlink file test elsewhere.
        self.known_hosts.symlink_to(alternate / "known_hosts")
        with self.assertRaisesRegex(ValueError, "KNOWN_HOSTS_SYMLINK_DENIED"):
            self.remote_status()



if __name__ == "__main__":
    unittest.main()
