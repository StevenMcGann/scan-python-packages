#!/usr/bin/env python3
"""Build deterministic scanner fixtures for Scan-PythonPackages.ps1 v1.3."""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import json
import random
import shutil
import tarfile
import zipfile
from pathlib import Path


FIXTURE_ROOT = Path(__file__).resolve().parent
CORPUS_ROOT = FIXTURE_ROOT / "corpus"
ARCHIVES_DIR = CORPUS_ROOT / "archives"
LOOSE_DIR = CORPUS_ROOT / "loose"
EMPTY_DIR = CORPUS_ROOT / "empty"
NON_PYTHON_DIR = CORPUS_ROOT / "non-python"
MALFORMED_DIR = CORPUS_ROOT / "malformed"

FIXED_ZIP_DT = (2026, 1, 1, 0, 0, 0)
FIXED_EPOCH = 1767225600
RANDOM_SEED = 13371337


def text_bytes(text: str) -> bytes:
    return text.encode("utf-8")


def seeded_bytes(label: str, length: int) -> bytes:
    rng = random.Random(f"{RANDOM_SEED}:{label}")
    return bytes(rng.randrange(0, 256) for _ in range(length))


def github_token() -> str:
    rng = random.Random(f"{RANDOM_SEED}:github-token")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "ghp_" + "".join(rng.choice(alphabet) for _ in range(36))


def write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def zip_write(zf: zipfile.ZipFile, arcname: str, data: bytes) -> None:
    info = zipfile.ZipInfo(arcname.replace("\\", "/"), FIXED_ZIP_DT)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    zf.writestr(info, data)


def wheel_metadata(name: str, version: str, requires: list[str] | None) -> bytes:
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {name}",
        f"Version: {version}",
        "Summary: Deterministic scanner fixture",
    ]
    for dep in requires or []:
        lines.append(f"Requires-Dist: {dep}")
    return text_bytes("\n".join(lines) + "\n")


def wheel_file() -> bytes:
    return text_bytes(
        "Wheel-Version: 1.0\n"
        "Generator: tests/fixtures/build_fixtures.py\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    )


def record_for(entries: list[tuple[str, bytes]]) -> bytes:
    rows: list[list[str]] = []
    for arcname, data in entries:
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        rows.append([arcname, f"sha256={digest}", str(len(data))])
    rows.append([next(name for name, _ in entries if name.endswith(".dist-info/RECORD")), "", ""])
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerows(rows)
    return text_bytes(stream.getvalue())


def make_wheel(
    filename: str,
    package: str,
    source_files: dict[str, str | bytes],
    requires: list[str] | None = None,
    include_metadata: bool = True,
) -> None:
    dist_info = f"{package}-1.0.dist-info"
    entries: list[tuple[str, bytes]] = []

    for relpath, content in sorted(source_files.items()):
        data = content if isinstance(content, bytes) else text_bytes(content)
        entries.append((relpath, data))

    if include_metadata:
        entries.append((f"{dist_info}/METADATA", wheel_metadata(package, "1.0", requires)))
        entries.append((f"{dist_info}/WHEEL", wheel_file()))
        record_name = f"{dist_info}/RECORD"
        entries.append((record_name, b""))
        record_data = record_for(entries)
        entries[-1] = (record_name, record_data)

    path = ARCHIVES_DIR / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in sorted(entries, key=lambda item: item[0]):
            zip_write(zf, arcname, data)


def make_zip(filename: str, files: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(ARCHIVES_DIR / filename, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, content in sorted(files.items()):
            data = content if isinstance(content, bytes) else text_bytes(content)
            zip_write(zf, arcname, data)


def make_tar(filename: str, files: dict[str, str | bytes]) -> None:
    path = ARCHIVES_DIR / filename
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=FIXED_EPOCH) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
                for arcname, content in sorted(files.items()):
                    data = content if isinstance(content, bytes) else text_bytes(content)
                    info = tarfile.TarInfo(arcname.replace("\\", "/"))
                    info.size = len(data)
                    info.mtime = FIXED_EPOCH
                    info.mode = 0o644
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    tf.addfile(info, io.BytesIO(data))


def finding(tool: str, severity: str, min_count: int = 1, test_id: str | None = None) -> dict[str, object]:
    item: dict[str, object] = {"tool": tool, "severity": severity, "min": min_count}
    if test_id:
        item["testId"] = test_id
    return item


def fixture(
    path: str,
    kind: str,
    purpose: str,
    expected_risk: str,
    expected_findings: list[dict[str, object]] | None = None,
    expects_sbom: bool = False,
    expected_sbom: dict[str, object] | None = None,
    expects_json: bool = True,
) -> dict[str, object]:
    item: dict[str, object] = {
        "path": path,
        "kind": kind,
        "purpose": purpose,
        "expectedRisk": expected_risk,
        "expectedFindings": expected_findings or [],
        "expectsSbom": expects_sbom,
        "expectsJson": expects_json,
    }
    if expected_sbom is not None:
        item["expectedSbom"] = expected_sbom
    return item


def build() -> list[dict[str, object]]:
    if CORPUS_ROOT.exists():
        shutil.rmtree(CORPUS_ROOT)
    for directory in (ARCHIVES_DIR, LOOSE_DIR, EMPTY_DIR, NON_PYTHON_DIR, MALFORMED_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    token = github_token()

    wheel_specs = [
        ("clean_pkg-1.0-py3-none-any.whl", "clean_pkg", {"clean_pkg/__init__.py": "pass\n"}, [], True),
        ("eval_pkg-1.0-py3-none-any.whl", "eval_pkg", {"eval_pkg/__init__.py": 'eval(input("expr: "))\n'}, [], True),
        ("exec_pkg-1.0-py3-none-any.whl", "exec_pkg", {"exec_pkg/__init__.py": 'exec(open("cmd").read())\n'}, [], True),
        ("pickle_pkg-1.0-py3-none-any.whl", "pickle_pkg", {"pickle_pkg/__init__.py": "import pickle\npickle.loads(b'cos\\nsystem\\n.')\n"}, [], True),
        (
            "subprocess_shell_pkg-1.0-py3-none-any.whl",
            "subprocess_shell_pkg",
            {"subprocess_shell_pkg/__init__.py": 'import subprocess\ncmd = input("cmd: ")\nsubprocess.run(cmd, shell=True)\n'},
            [],
            True,
        ),
        ("weak_crypto_pkg-1.0-py3-none-any.whl", "weak_crypto_pkg", {"weak_crypto_pkg/__init__.py": "import hashlib\nhashlib.md5(b'data').hexdigest()\n"}, [], True),
        ("aws_key_pkg-1.0-py3-none-any.whl", "aws_key_pkg", {"aws_key_pkg/__init__.py": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'}, [], True),
        ("github_token_pkg-1.0-py3-none-any.whl", "github_token_pkg", {"github_token_pkg/__init__.py": f'GITHUB_TOKEN = "{token}"\n'}, [], True),
        (
            "vulnerable_deps_pkg-1.0-py3-none-any.whl",
            "vulnerable_deps_pkg",
            {"vulnerable_deps_pkg/__init__.py": ""},
            ["requests==2.19.1", "urllib3==1.24.1"],
            True,
        ),
        (
            "rich_deps_pkg-1.0-py3-none-any.whl",
            "rich_deps_pkg",
            {"rich_deps_pkg/__init__.py": ""},
            ["requests==2.19.1", "urllib3==1.24.1", "six==1.10.0", "click==7.0", "certifi==2020.4.5.1"],
            True,
        ),
        ("native_pyd_pkg-1.0-py3-none-any.whl", "native_pyd_pkg", {"native_pyd_pkg/__init__.py": "pass\n", "native_pyd_pkg/extension.pyd": seeded_bytes("pyd", 64)}, [], True),
        ("native_so_pkg-1.0-py3-none-any.whl", "native_so_pkg", {"native_so_pkg/__init__.py": "pass\n", "native_so_pkg/extension.so": seeded_bytes("so", 64)}, [], True),
        ("native_dll_pkg-1.0-py3-none-any.whl", "native_dll_pkg", {"native_dll_pkg/__init__.py": "pass\n", "native_dll_pkg/helper.dll": seeded_bytes("dll", 64)}, [], True),
        ("no_metadata_pkg-1.0-py3-none-any.whl", "no_metadata_pkg", {"no_metadata_pkg/__init__.py": "pass\n"}, [], False),
        (
            "env_marker_pkg-1.0-py3-none-any.whl",
            "env_marker_pkg",
            {"env_marker_pkg/__init__.py": ""},
            ['requests==2.19.1; python_version >= "3.8"'],
            True,
        ),
        ("weird[name],and&stuff-1.0-py3-none-any.whl", "weird_name_and_stuff", {"weird_name_and_stuff/__init__.py": "pass\n"}, [], True),
    ]
    for spec in wheel_specs:
        make_wheel(*spec)

    make_wheel("clean_pkg-1.0-py3.6.egg", "clean_pkg", {"clean_pkg/__init__.py": "pass\n"})
    make_zip("plain_archive.zip", {"plain_archive/main.py": "pass\n"})
    make_tar("sourcedist_pkg-1.0.tar.gz", {"sourcedist_pkg-1.0/setup.py": "from setuptools import setup\nsetup(name='sourcedist_pkg', version='1.0')\n", "sourcedist_pkg-1.0/sourcedist_pkg/__init__.py": "pass\n"})
    make_tar("oldstyle_pkg-1.0.tgz", {"oldstyle_pkg-1.0/module.py": "pass\n"})

    write_file(MALFORMED_DIR / "truncated_pkg-1.0-py3-none-any.whl", b"PK\x03\x04\x14\x00\x00\x00\x08\x00truncated deterministic wheel bytes")
    write_file(LOOSE_DIR / "clean_module.py", text_bytes("pass\n"))
    write_file(LOOSE_DIR / "bad_eval.py", text_bytes('eval(input("expr: "))\n'))
    write_file(LOOSE_DIR / "with_secret.pyw", text_bytes('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'))
    write_file(NON_PYTHON_DIR / "README.md", text_bytes("# Non-Python fixture\n"))
    write_file(NON_PYTHON_DIR / "data.csv", text_bytes("id,value\n1,fixture\n"))
    write_file(NON_PYTHON_DIR / "photo.jpg", b"\xff\xd8\xff\xe0" + seeded_bytes("jpg", 32) + b"\xff\xd9")

    fixtures = [
        fixture("archives/clean_pkg-1.0-py3-none-any.whl", "archive", "Clean wheel baseline", "CLEAN"),
        fixture("archives/eval_pkg-1.0-py3-none-any.whl", "archive", "Bandit B307 trigger", "MEDIUM", [finding("Bandit", "MEDIUM", test_id="B307")]),
        fixture("archives/exec_pkg-1.0-py3-none-any.whl", "archive", "Bandit B102 trigger", "MEDIUM", [finding("Bandit", "MEDIUM", test_id="B102")]),
        fixture("archives/pickle_pkg-1.0-py3-none-any.whl", "archive", "Bandit B301 trigger", "MEDIUM", [finding("Bandit", "MEDIUM", test_id="B301")]),
        fixture("archives/subprocess_shell_pkg-1.0-py3-none-any.whl", "archive", "Bandit B602 trigger", "HIGH", [finding("Bandit", "HIGH", test_id="B602")]),
        fixture("archives/weak_crypto_pkg-1.0-py3-none-any.whl", "archive", "Bandit weak crypto trigger", "HIGH", [{"tool": "Bandit", "severity": "HIGH", "testIdAny": ["B303", "B324"], "min": 1}]),
        fixture("archives/aws_key_pkg-1.0-py3-none-any.whl", "archive", "detect-secrets AWS key trigger", "HIGH", [finding("detect-secrets", "HIGH")]),
        fixture("archives/github_token_pkg-1.0-py3-none-any.whl", "archive", "detect-secrets GitHub token trigger", "HIGH", [finding("detect-secrets", "HIGH")]),
        fixture("archives/vulnerable_deps_pkg-1.0-py3-none-any.whl", "archive", "pip-audit + SBOM trigger", "HIGH", [finding("pip-audit", "HIGH", 2)], True, {"format": "CycloneDX", "componentsMin": 2, "componentNames": ["requests", "urllib3"]}),
        fixture("archives/rich_deps_pkg-1.0-py3-none-any.whl", "archive", "Multi-dep SBOM shape", "HIGH", [finding("pip-audit", "HIGH", 2)], True, {"format": "CycloneDX", "componentsMin": 5}),
        fixture("archives/native_pyd_pkg-1.0-py3-none-any.whl", "archive", "Native .pyd trigger", "MEDIUM", [finding("NativeBinaryCheck", "MEDIUM", test_id="NATIVE-BINARY")]),
        fixture("archives/native_so_pkg-1.0-py3-none-any.whl", "archive", "Native .so trigger", "MEDIUM", [finding("NativeBinaryCheck", "MEDIUM", test_id="NATIVE-BINARY")]),
        fixture("archives/native_dll_pkg-1.0-py3-none-any.whl", "archive", "Native .dll trigger", "MEDIUM", [finding("NativeBinaryCheck", "MEDIUM", test_id="NATIVE-BINARY")]),
        fixture("archives/clean_pkg-1.0-py3.6.egg", "archive", "Legacy egg format coverage", "CLEAN"),
        fixture("archives/plain_archive.zip", "archive", "Plain zip format coverage", "CLEAN"),
        fixture("archives/sourcedist_pkg-1.0.tar.gz", "archive", "Source distribution tar.gz coverage", "CLEAN"),
        fixture("archives/oldstyle_pkg-1.0.tgz", "archive", "Simple-suffix tarball coverage", "CLEAN"),
        fixture("archives/no_metadata_pkg-1.0-py3-none-any.whl", "archive", "No Requires-Dist - verifies SBOM is skipped", "CLEAN"),
        fixture("archives/env_marker_pkg-1.0-py3-none-any.whl", "archive", "Environment marker stripping for pip-audit", "HIGH", [finding("pip-audit", "HIGH", 1)], True, {"format": "CycloneDX", "componentsMin": 1, "componentNames": ["requests"]}),
        fixture("archives/weird[name],and&stuff-1.0-py3-none-any.whl", "archive", "Stage directory sanitizer coverage", "CLEAN"),
        fixture("malformed/truncated_pkg-1.0-py3-none-any.whl", "malformed-archive", "Extraction failure is logged and run continues", "ERROR", [], False, None, False),
        fixture("loose/clean_module.py", "pyfile", "Clean loose Python source", "CLEAN"),
        fixture("loose/bad_eval.py", "pyfile", "Loose Bandit B307 trigger", "MEDIUM", [finding("Bandit", "MEDIUM", test_id="B307")]),
        fixture("loose/with_secret.pyw", "pyfile", "Loose .pyw detect-secrets trigger", "HIGH", [finding("detect-secrets", "HIGH")]),
        fixture("empty", "directory", "Empty folder early-exit coverage", "CLEAN", [], False, None, False),
        fixture("non-python", "directory", "Non-Python early-exit coverage", "CLEAN", [], False, None, False),
    ]

    manifest = {
        "schemaVersion": "1.3",
        "scannerVersionTarget": "1.3",
        "fixtures": fixtures,
    }
    write_file(CORPUS_ROOT / "manifest.json", text_bytes(json.dumps(manifest, indent=2, sort_keys=True) + "\n"))
    return fixtures


def main() -> None:
    fixtures = build()
    print(f"Generated {len(fixtures)} fixtures into {CORPUS_ROOT}\\")


if __name__ == "__main__":
    main()
