#!/usr/bin/env python3
"""Offline verifier for the pinned Fingerprint Chromium fetcher source contract.

This code only parses Python syntax and a JSON file. It never imports, executes
or downloads the browser/fetcher, touches credentials or modifies host settings.
Passing checks establish repository consistency, NOT publisher authenticity.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
EXPECTED_PLATFORMS = {
    "macos-arm64": ("module", "URL", "SHA256", "arm64"),
    "linux-x86_64": ("fetch_linux", "url", "digest", "x86_64"),
    "windows-x86_64": ("fetch_windows", "url", "digest", "x86_64"),
}


class SourceMismatch(ValueError):
    pass


def assigned(tree: ast.AST, name: str) -> ast.AST:
    """Require one simple assignment; fail closed on ambiguous reassignment."""
    found = [
        stmt.value
        for stmt in ast.walk(tree)
        if isinstance(stmt, (ast.Assign, ast.AnnAssign))
        for target in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target])
        if isinstance(target, ast.Name) and target.id == name
    ]
    if len(found) != 1:
        raise SourceMismatch(f"Expected one assignment to {name}, found {len(found)}")
    return found[0]


def constant(value: ast.AST, version: str | None = None) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.JoinedStr):
        parts = []
        for item in value.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                parts.append(item.value)
            elif (isinstance(item, ast.FormattedValue) and version is not None
                  and isinstance(item.value, ast.Name)
                  and item.value.id == "VERSION"
                  and item.format_spec is None and item.conversion == -1):
                parts.append(version)
            else:
                raise SourceMismatch("Unsupported dynamic URL expression")
        return "".join(parts)
    raise SourceMismatch("Expected a static string or VERSION-only f-string")


def extract_fetcher(source: str) -> dict[str, dict[str, str]]:
    tree = ast.parse(source)
    version = constant(assigned(tree, "VERSION"))
    sections = {"module": tree}
    for key in ("fetch_linux", "fetch_windows"):
        matched = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == key]
        if len(matched) != 1:
            raise SourceMismatch(f"Missing or ambiguous function {key}")
        sections[key] = matched[0]
    found = {}
    for platform, (section, url_key, digest_key, arch) in EXPECTED_PLATFORMS.items():
        node = sections[section]
        found[platform] = {
            "version": version,
            "arch": arch,
            "download_url": constant(assigned(node, url_key), version),
            "sha256": constant(assigned(node, digest_key), version),
        }
    return found


def validate(manifest: dict[str, Any], fetcher_source: str) -> None:
    if manifest.get("schema") != "panda.ccbaga.browser-source.v1":
        raise SourceMismatch("Unknown manifest schema")
    source = manifest.get("source")
    if not isinstance(source, dict):
        raise SourceMismatch("Missing upstream source")
    repository = source.get("repository")
    version = source.get("release_tag")
    commit = source.get("tag_commit")
    if repository != "adryfish/fingerprint-chromium":
        raise SourceMismatch("Upstream repository is not the audited name")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", version):
        raise SourceMismatch("Malformed upstream release tag")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SourceMismatch("Missing fixed tag commit")
    if source.get("tag_commit_verified_signature") is not False or source.get("release_immutable") is not False:
        raise SourceMismatch("Cannot claim independently verified signatures or immutable release")
    observed = extract_fetcher(fetcher_source)
    platforms = manifest.get("platforms")
    if not isinstance(platforms, dict) or set(platforms) != set(EXPECTED_PLATFORMS):
        raise SourceMismatch("Platform set changed")
    for name, fields in observed.items():
        asset = platforms[name]
        if not isinstance(asset, dict):
            raise SourceMismatch(f"{name}: invalid platform record")
        filename = asset.get("asset")
        if (not isinstance(filename, str) or filename in {".", ".."}
                or "/" in filename or "\\" in filename or ".." in filename
                or not filename.startswith("ungoogled-chromium")):
            raise SourceMismatch(f"{name}: unsafe asset name")
        url = f"https://github.com/{repository}/releases/download/{version}/{filename}"
        if asset.get("download_url") != url:
            raise SourceMismatch(f"{name}: manifest URL differs from audited upstream")
        if fields["download_url"] != url:
            raise SourceMismatch(f"{name}: fetcher URL diverges from manifest")
        if fields["version"] != version or fields["arch"] != asset.get("arch"):
            raise SourceMismatch(f"{name}: platform version or architecture mismatch")
        digest = asset.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SourceMismatch(f"{name}: SHA256 format invalid")
        if fields["sha256"] != digest:
            raise SourceMismatch(f"{name}: fetcher SHA256 diverges from manifest")
    warning = manifest.get("trust_boundary")
    if not isinstance(warning, str) or "No verified publisher signature" not in warning:
        raise SourceMismatch("Source-trust limitation disclosure missing")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "browser-source-manifest.json")
    parser.add_argument("--fetcher", type=Path, default=ROOT / "fetch-browser.py")
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.manifest.read_text(encoding="utf-8"))
        source = args.fetcher.read_text(encoding="utf-8")
        validate(document, source)
    except (OSError, ValueError, SyntaxError, TypeError) as error:
        print(f"MANIFEST=FAIL reason={type(error).__name__}: {error}")
        return 2
    print("MANIFEST=PASS scope=offline_consistency_only publisher_signature=UNVERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
