"""No-network regression tests for browser origin manifest and source parser."""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PATH = ROOT / "verify-browser-source-manifest.py"
SPEC = importlib.util.spec_from_file_location("browser_source_manifest", PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
MANIFEST = json.loads((ROOT / "browser-source-manifest.json").read_text(encoding="utf-8"))
FETCHER = (ROOT / "fetch-browser.py").read_text(encoding="utf-8")


class ManifestTests(unittest.TestCase):
    def validate(self, spec=None, source=None):
        module.validate(MANIFEST if spec is None else spec, FETCHER if source is None else source)

    def test_current_source_is_pinned(self):
        self.validate()

    def test_bad_linux_digest(self):
        altered = FETCHER.replace(MANIFEST["platforms"]["linux-x86_64"]["sha256"], "0" * 64, 1)
        with self.assertRaisesRegex(module.SourceMismatch, "SHA256 diverges"):
            self.validate(source=altered)

    def test_bad_windows_download_url(self):
        altered = FETCHER.replace("adryfish/fingerprint-chromium", "untrusted/fork", 1)
        with self.assertRaisesRegex(module.SourceMismatch, "URL diverges"):
            self.validate(source=altered)

    def test_wrong_mac_digest(self):
        spec = copy.deepcopy(MANIFEST)
        spec["platforms"]["macos-arm64"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(module.SourceMismatch, "SHA256 diverges"):
            self.validate(spec=spec)

    def test_mutable_source_is_not_mislabeled_verified(self):
        spec = copy.deepcopy(MANIFEST)
        spec["source"]["tag_commit_verified_signature"] = True
        with self.assertRaisesRegex(module.SourceMismatch, "Cannot claim"):
            self.validate(spec=spec)

    def test_invalid_release_tag_rejected(self):
        spec = copy.deepcopy(MANIFEST)
        spec["source"]["release_tag"] = "latest"
        with self.assertRaisesRegex(module.SourceMismatch, "Malformed upstream"):
            self.validate(spec=spec)

    def test_missing_commit_binding_rejected(self):
        spec = copy.deepcopy(MANIFEST)
        spec["source"]["tag_commit"] = ""
        with self.assertRaisesRegex(module.SourceMismatch, "Missing fixed"):
            self.validate(spec=spec)

    def test_missing_platform_fails_closed(self):
        spec = copy.deepcopy(MANIFEST)
        del spec["platforms"]["windows-x86_64"]
        with self.assertRaisesRegex(module.SourceMismatch, "Platform set"):
            self.validate(spec=spec)

    def test_path_traversal_in_asset_rejected(self):
        spec = copy.deepcopy(MANIFEST)
        spec["platforms"]["linux-x86_64"]["asset"] = "../bad.tar.xz"
        with self.assertRaisesRegex(module.SourceMismatch, "unsafe asset"):
            self.validate(spec=spec)

    def test_unexpected_python_expression_rejected_without_running_it(self):
        altered = FETCHER.replace(
            "VERSION = '148.0.7778.215'",
            "VERSION = __import__('os').system('false')", 1,
        )
        with self.assertRaises(module.SourceMismatch):
            self.validate(source=altered)

    def test_duplicate_dynamic_version_assignment_rejected(self):
        with self.assertRaisesRegex(module.SourceMismatch, "Expected one assignment"):
            self.validate(source=FETCHER + "\nVERSION = '0.0.0.0'\n")

    def test_absent_source_trust_warning_rejected(self):
        spec = copy.deepcopy(MANIFEST)
        spec["trust_boundary"] = ""
        with self.assertRaisesRegex(module.SourceMismatch, "disclosure missing"):
            self.validate(spec=spec)

    def test_manifest_url_tampering_rejected(self):
        spec = copy.deepcopy(MANIFEST)
        spec["platforms"]["macos-arm64"]["download_url"] = "https://example.test/browser.dmg"
        with self.assertRaisesRegex(module.SourceMismatch, "manifest URL"):
            self.validate(spec=spec)

    def test_version_drift_rejected(self):
        spec = copy.deepcopy(MANIFEST)
        spec["source"]["release_tag"] = "148.0.7778.216"
        with self.assertRaisesRegex(module.SourceMismatch, "manifest URL"):
            self.validate(spec=spec)


if __name__ == "__main__":
    unittest.main()
