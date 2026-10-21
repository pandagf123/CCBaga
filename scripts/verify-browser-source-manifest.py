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


# This reviewed observation is pinned as a second, independent source-code value,
# rather than trusting any 40-digit value copied into the JSON manifest.
# It is not a publisher-signed Git tag or immutable release proof.
AUDITED_UNSIGNED_TAG_COMMIT = "13b89eae304123f0710f2d33fd0816a2f61d7ffc"


def attribute_call(node: ast.AST, owner: str, name: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == name
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == owner
    )


def named(node: ast.AST, identifier: str) -> bool:
    return isinstance(node, ast.Name) and node.id == identifier


def literal(node: ast.AST, value: str | bool) -> bool:
    return isinstance(node, ast.Constant) and node.value == value


def check_call_sites(source: str) -> None:
    """Narrow AST guard for current curl->SHA256->extraction ordering.

    Not a general control-flow or arbitrary-code security proof. Unknown fetcher
    refactors fail closed and need a new independent review.
    """
    tree = ast.parse(source)
    functions: dict[str, ast.FunctionDef] = {}
    for key in ("main", "fetch_linux", "fetch_windows"):
        found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == key]
        if len(found) != 1:
            raise SourceMismatch(f"Call-site contract: expected one {key} function")
        functions[key] = found[0]

    routes = (
        ("macos-arm64", "main", "curl", "URL", "SHA256", "image", "hdiutil"),
        ("linux-x86_64", "fetch_linux", "curl", "url", "digest", "archive", "tarfile"),
        ("windows-x86_64", "fetch_windows", "curl.exe", "url", "digest", "archive", "zipfile"),
    )
    for platform, function, command, url_var, hash_var, archive_var, unpacker in routes:
        node = functions[function]
        downloads = []
        for call in ast.walk(node):
            if (attribute_call(call, "subprocess", "run") and call.args
                    and isinstance(call.args[0], ast.List) and call.args[0].elts
                    and (literal(call.args[0].elts[0], "curl") or literal(call.args[0].elts[0], "curl.exe"))):
                downloads.append(call)
        if len(downloads) != 1:
            raise SourceMismatch(f"{platform}: exactly one audited curl download call required")
        download = downloads[0]
        args = download.args[0].elts
        if not (
            len(args) == 8
            and literal(args[0], command)
            and all(literal(args[i], expected) for i, expected in enumerate(
                ("--fail", "--location", "--retry", "3", "--output"), start=1
            ))
            and isinstance(args[6], ast.Call)
            and named(args[6].func, "str")
            and len(args[6].args) == 1
            and named(args[6].args[0], archive_var)
            and named(args[7], url_var)
            and len(download.keywords) == 1
            and download.keywords[0].arg == "check"
            and literal(download.keywords[0].value, True)
        ):
            raise SourceMismatch(f"{platform}: downloader no longer consumes the pinned URL")

        checks = []
        for block in ast.walk(node):
            if not isinstance(block, ast.With) or len(block.items) != 1:
                continue
            item = block.items[0]
            opened = item.context_expr
            if not (isinstance(opened, ast.Call)
                    and isinstance(opened.func, ast.Attribute)
                    and opened.func.attr == "open"
                    and named(opened.func.value, archive_var)
                    and len(opened.args) == 1
                    and literal(opened.args[0], "rb")
                    and named(item.optional_vars, "stream")
                    and len(block.body) == 1
                    and isinstance(block.body[0], ast.If)):
                continue
            checked = block.body[0]
            compare = checked.test
            canonical = ast.parse("hashlib.file_digest(stream, 'sha256').hexdigest()", mode="eval").body
            if not (isinstance(compare, ast.Compare)
                    and len(compare.ops) == 1 and isinstance(compare.ops[0], ast.NotEq)
                    and len(compare.comparators) == 1
                    and named(compare.comparators[0], hash_var)
                    and ast.dump(compare.left) == ast.dump(canonical)
                    and not checked.orelse
                    and len(checked.body) == 1
                    and isinstance(checked.body[0], ast.Raise)
                    and isinstance(checked.body[0].exc, ast.Call)
                    and named(checked.body[0].exc.func, "SystemExit")):
                continue
            checks.append(checked)
        if len(checks) != 1:
            raise SourceMismatch(f"{platform}: enforced pinned SHA256 mismatch rejection missing")
        checksum = checks[0]

        extractors = []
        for call in ast.walk(node):
            if unpacker == "tarfile" and attribute_call(call, "tarfile", "open"):
                extractors.append(call)
            elif unpacker == "zipfile" and attribute_call(call, "zipfile", "ZipFile"):
                extractors.append(call)
            elif (unpacker == "hdiutil" and attribute_call(call, "subprocess", "check_output")
                  and call.args and isinstance(call.args[0], ast.List)
                  and call.args[0].elts and literal(call.args[0].elts[0], "hdiutil")):
                extractors.append(call)
        if len(extractors) != 1 or not download.lineno < checksum.lineno < extractors[0].lineno:
            raise SourceMismatch(f"{platform}: download/check/extraction order changed")


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
    if commit != AUDITED_UNSIGNED_TAG_COMMIT:
        raise SourceMismatch("Reviewed unsigned tag commit changed")
    if source.get("tag_commit_verified_signature") is not False or source.get("release_immutable") is not False:
        raise SourceMismatch("Cannot claim independently verified signatures or immutable release")
    observed = extract_fetcher(fetcher_source)
    check_call_sites(fetcher_source)
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
