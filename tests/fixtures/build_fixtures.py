#!/usr/bin/env python3
"""Build deterministic scanner fixtures for src/Scan-PythonPackages.ps1 v1.5."""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import json
import random
import shutil
import struct
import tarfile
import zipfile
from pathlib import Path


FIXTURE_ROOT = Path(__file__).resolve().parent
CORPUS_ROOT = FIXTURE_ROOT / "corpus"
ARCHIVES_DIR = CORPUS_ROOT / "archives"
LOOSE_DIR = CORPUS_ROOT / "loose"
EMPTY_DIR = CORPUS_ROOT / "empty"
NON_PYTHON_DIR = CORPUS_ROOT / "non-python"
MIXED_DIR = CORPUS_ROOT / "mixed"
MALFORMED_DIR = CORPUS_ROOT / "malformed"

FIXED_ZIP_DT = (2026, 1, 1, 0, 0, 0)
FIXED_EPOCH = 1767225600
RANDOM_SEED = 13371337


def text_bytes(text: str) -> bytes:
    return text.encode("utf-8")


def seeded_bytes(label: str, length: int) -> bytes:
    rng = random.Random(f"{RANDOM_SEED}:{label}")
    return bytes(rng.randrange(0, 256) for _ in range(length))


def align(value: int, boundary: int) -> int:
    return ((value + boundary - 1) // boundary) * boundary


def make_minimal_pe(imports: dict[str, list[str]] | None = None, sections: list[tuple[str, bytes]] | None = None) -> bytes:
    imports = imports or {}
    section_alignment = 0x1000
    file_alignment = 0x200
    image_base = 0x400000
    header_size = 0x200

    section_defs: list[dict[str, object]] = []
    raw_ptr = header_size
    virtual_addr = 0x1000
    base_sections = sections or [(".text", b"\xC3" + b"\x90" * 63)]

    for name, data in base_sections:
        raw = data.ljust(align(len(data), file_alignment), b"\x00")
        chars = 0x60000020 if name == ".text" else 0x40000040
        section_defs.append({
            "name": name,
            "data": raw,
            "virtual_size": len(data),
            "virtual_addr": virtual_addr,
            "raw_ptr": raw_ptr,
            "chars": chars,
        })
        raw_ptr += len(raw)
        virtual_addr += align(max(len(data), 1), section_alignment)

    import_rva = 0
    import_size = 0
    if imports:
        rdata_rva = virtual_addr
        descriptor_count = len(imports) + 1
        cursor = descriptor_count * 20
        dll_records = []
        rdata = bytearray(b"\x00" * cursor)

        for dll, funcs in sorted(imports.items()):
            cursor = align(cursor, 4)
            ilt_off = cursor
            cursor += 4 * (len(funcs) + 1)
            iat_off = cursor
            cursor += 4 * (len(funcs) + 1)
            name_off = cursor
            dll_bytes = dll.encode("ascii") + b"\x00"
            cursor += len(dll_bytes)
            hint_offsets = []
            for func in funcs:
                cursor = align(cursor, 2)
                hint_offsets.append(cursor)
                cursor += 2 + len(func.encode("ascii")) + 1
            if len(rdata) < cursor:
                rdata.extend(b"\x00" * (cursor - len(rdata)))
            rdata[name_off:name_off + len(dll_bytes)] = dll_bytes
            for index, func in enumerate(funcs):
                hint_name_rva = rdata_rva + hint_offsets[index]
                struct.pack_into("<I", rdata, ilt_off + index * 4, hint_name_rva)
                struct.pack_into("<I", rdata, iat_off + index * 4, hint_name_rva)
                func_bytes = func.encode("ascii") + b"\x00"
                struct.pack_into("<H", rdata, hint_offsets[index], 0)
                start = hint_offsets[index] + 2
                rdata[start:start + len(func_bytes)] = func_bytes
            dll_records.append((rdata_rva + ilt_off, rdata_rva + name_off, rdata_rva + iat_off))

        for index, (ilt_rva, name_rva, iat_rva) in enumerate(dll_records):
            struct.pack_into("<IIIII", rdata, index * 20, ilt_rva, 0, 0, name_rva, iat_rva)

        import_rva = rdata_rva
        import_size = descriptor_count * 20
        rdata_bytes = bytes(rdata)
        section_defs.append({
            "name": ".rdata",
            "data": rdata_bytes.ljust(align(len(rdata_bytes), file_alignment), b"\x00"),
            "virtual_size": len(rdata_bytes),
            "virtual_addr": rdata_rva,
            "raw_ptr": raw_ptr,
            "chars": 0x40000040,
        })
        raw_ptr += align(len(rdata_bytes), file_alignment)
        virtual_addr += align(max(len(rdata_bytes), 1), section_alignment)

    size_of_image = align(virtual_addr, section_alignment)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, len(section_defs), 0, 0, 0, 224, 0x210E)
    optional = bytearray(224)
    struct.pack_into("<HBBIII", optional, 0, 0x10B, 14, 0, 0x200, 0, 0)
    struct.pack_into("<III", optional, 16, 0x1000, 0x1000, 0)
    struct.pack_into("<III", optional, 28, image_base, section_alignment, file_alignment)
    struct.pack_into("<HHHHHH", optional, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", optional, 56, size_of_image)
    struct.pack_into("<I", optional, 60, header_size)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<III", optional, 72, 0x100000, 0x1000, 0x100000)
    struct.pack_into("<II", optional, 84, 0x1000, 0)
    struct.pack_into("<I", optional, 92, 16)
    struct.pack_into("<II", optional, 104, import_rva, import_size)

    section_headers = bytearray()
    for section in section_defs:
        name = str(section["name"]).encode("ascii")[:8].ljust(8, b"\x00")
        data = section["data"]
        section_headers.extend(struct.pack(
            "<8sIIIIIIHHI",
            name,
            int(section["virtual_size"]),
            int(section["virtual_addr"]),
            len(data),
            int(section["raw_ptr"]),
            0,
            0,
            0,
            0,
            int(section["chars"]),
        ))

    headers = (bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + bytes(section_headers)).ljust(header_size, b"\x00")
    image = bytearray(headers)
    for section in section_defs:
        start = int(section["raw_ptr"])
        data = section["data"]
        if len(image) < start:
            image.extend(b"\x00" * (start - len(image)))
        image[start:start + len(data)] = data
    return bytes(image)


def make_packed_pe_section() -> bytes:
    return make_minimal_pe(sections=[(".text", b"\xC3" + b"\x90" * 63), (".packed", seeded_bytes("packed-pe", 1024))])


def make_minimal_elf(needed_libs: list[str] | None = None) -> bytes:
    needed_libs = needed_libs or []
    shstr = b"\x00.text\x00.shstrtab\x00.symtab\x00.strtab\x00"
    shstr_offsets = {"": 0, ".text": 1, ".shstrtab": 7, ".symtab": 17, ".strtab": 25}
    dynstr = b"\x00"
    needed_offsets: list[int] = []
    for lib in needed_libs:
        needed_offsets.append(len(dynstr))
        dynstr += lib.encode("ascii") + b"\x00"
    dynamic = b"".join(struct.pack("<QQ", 1, off) for off in needed_offsets) + struct.pack("<QQ", 0, 0)

    sections: list[dict[str, object]] = [{"name": "", "type": 0, "flags": 0, "data": b"", "align": 0, "entsize": 0, "link": 0}]
    if needed_libs:
        shstr_offsets[".dynstr"] = len(shstr)
        shstr += b".dynstr\x00"
        shstr_offsets[".dynamic"] = len(shstr)
        shstr += b".dynamic\x00"
    sections.append({"name": ".text", "type": 1, "flags": 0x6, "data": b"\xC3", "align": 16, "entsize": 0, "link": 0})
    dynstr_index = 0
    if needed_libs:
        dynstr_index = len(sections)
        sections.append({"name": ".dynstr", "type": 3, "flags": 0x2, "data": dynstr, "align": 1, "entsize": 0, "link": 0})
        sections.append({"name": ".dynamic", "type": 6, "flags": 0x3, "data": dynamic, "align": 8, "entsize": 16, "link": dynstr_index})
    sections.append({"name": ".symtab", "type": 2, "flags": 0, "data": b"\x00" * 24, "align": 8, "entsize": 24, "link": len(sections) + 1})
    sections.append({"name": ".strtab", "type": 3, "flags": 0, "data": b"\x00", "align": 1, "entsize": 0, "link": 0})
    shstr_index = len(sections)
    sections.append({"name": ".shstrtab", "type": 3, "flags": 0, "data": shstr, "align": 1, "entsize": 0, "link": 0})

    offset = 64
    for section in sections[1:]:
        offset = align(offset, int(section["align"]) or 1)
        section["offset"] = offset
        offset += len(section["data"])
    shoff = align(offset, 8)

    header = bytearray(64)
    header[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    struct.pack_into("<HHIQQQIHHHHHH", header, 16, 3, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections), shstr_index)
    image = bytearray(header)
    for section in sections[1:]:
        start = int(section["offset"])
        if len(image) < start:
            image.extend(b"\x00" * (start - len(image)))
        image[start:start + len(section["data"])] = section["data"]
    if len(image) < shoff:
        image.extend(b"\x00" * (shoff - len(image)))
    for section in sections:
        image.extend(struct.pack(
            "<IIQQQQIIQQ",
            shstr_offsets[str(section["name"])],
            int(section["type"]),
            int(section["flags"]),
            0,
            int(section.get("offset", 0)),
            len(section["data"]),
            int(section["link"]),
            0,
            int(section["align"]) or 0,
            int(section["entsize"]),
        ))
    return bytes(image)


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


def make_tar(filename: str, files: dict[str, str | bytes], output_dir: Path = ARCHIVES_DIR) -> None:
    path = output_dir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
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
    expected_unsupported_files: list[str] | None = None,
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
    if expected_unsupported_files is not None:
        item["expectedUnsupportedFiles"] = expected_unsupported_files
    return item


def build() -> list[dict[str, object]]:
    if CORPUS_ROOT.exists():
        shutil.rmtree(CORPUS_ROOT)
    for directory in (ARCHIVES_DIR, LOOSE_DIR, EMPTY_DIR, NON_PYTHON_DIR, MIXED_DIR, MALFORMED_DIR):
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
        ("native_pyd_pkg-1.0-py3-none-any.whl", "native_pyd_pkg", {"native_pyd_pkg/__init__.py": "pass\n", "native_pyd_pkg/extension.pyd": make_minimal_pe()}, [], True),
        ("native_so_pkg-1.0-py3-none-any.whl", "native_so_pkg", {"native_so_pkg/__init__.py": "pass\n", "native_so_pkg/extension.so": make_minimal_elf()}, [], True),
        ("native_dll_pkg-1.0-py3-none-any.whl", "native_dll_pkg", {"native_dll_pkg/__init__.py": "pass\n", "native_dll_pkg/helper.dll": make_minimal_pe(imports={"kernel32.dll": ["GetModuleHandleA"]})}, [], True),
        (
            "suspicious_imports_pkg-1.0-py3-none-any.whl",
            "suspicious_imports_pkg",
            {"suspicious_imports_pkg/__init__.py": "pass\n", "suspicious_imports_pkg/payload.pyd": make_minimal_pe(imports={"kernel32.dll": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"]})},
            [],
            True,
        ),
        (
            "network_native_pkg-1.0-py3-none-any.whl",
            "network_native_pkg",
            {"network_native_pkg/__init__.py": "pass\n", "network_native_pkg/net.pyd": make_minimal_pe(imports={"ws2_32.dll": ["connect", "send", "recv"]})},
            [],
            True,
        ),
        ("packed_native_pkg-1.0-py3-none-any.whl", "packed_native_pkg", {"packed_native_pkg/__init__.py": "pass\n", "packed_native_pkg/packed.pyd": make_packed_pe_section()}, [], True),
        ("fake_native_pkg-1.0-py3-none-any.whl", "fake_native_pkg", {"fake_native_pkg/__init__.py": "pass\n", "fake_native_pkg/fake.pyd": seeded_bytes("fake-pyd", 64)}, [], True),
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
    write_file(MIXED_DIR / "clean_module.py", text_bytes("pass\n"))
    write_file(MIXED_DIR / "README.md", text_bytes("# Mixed fixture\n"))
    write_file(MIXED_DIR / "photo.jpg", b"\xff\xd8\xff\xe0" + seeded_bytes("mixed-jpg", 32) + b"\xff\xd9")
    make_tar("sourcedist_pkg-1.0.tar.gz", {"sourcedist_pkg-1.0/setup.py": "from setuptools import setup\nsetup(name='sourcedist_pkg', version='1.0')\n", "sourcedist_pkg-1.0/sourcedist_pkg/__init__.py": "pass\n"}, MIXED_DIR)

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
        fixture("archives/native_pyd_pkg-1.0-py3-none-any.whl", "archive", "Clean native .pyd baseline", "CLEAN"),
        fixture("archives/native_so_pkg-1.0-py3-none-any.whl", "archive", "Clean native .so baseline", "CLEAN"),
        fixture("archives/native_dll_pkg-1.0-py3-none-any.whl", "archive", "Clean native .dll baseline", "CLEAN"),
        fixture("archives/suspicious_imports_pkg-1.0-py3-none-any.whl", "archive", "PE process injection import trigger", "HIGH", [finding("BinaryInspection", "HIGH", test_id="BINARY-SUSPICIOUS-IMPORT")]),
        fixture("archives/network_native_pkg-1.0-py3-none-any.whl", "archive", "PE network import trigger", "MEDIUM", [finding("BinaryInspection", "MEDIUM", test_id="BINARY-NETWORK-IMPORT")]),
        fixture("archives/packed_native_pkg-1.0-py3-none-any.whl", "archive", "PE high entropy section trigger", "MEDIUM", [finding("BinaryInspection", "MEDIUM", test_id="BINARY-HIGH-ENTROPY")]),
        fixture("archives/fake_native_pkg-1.0-py3-none-any.whl", "archive", "Invalid .pyd format trigger", "HIGH", [finding("BinaryInspection", "HIGH", test_id="BINARY-INVALID-FORMAT")]),
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
        fixture("non-python", "directory", "Unsupported-only folder produces a clean warning report", "CLEAN", [], False, None, True, ["README.md", "data.csv", "photo.jpg"]),
        fixture("mixed", "directory", "Supported and unsupported files mixed", "CLEAN", [], False, None, True, ["README.md", "photo.jpg"]),
    ]

    manifest = {
        "schemaVersion": "1.5",
        "scannerVersionTarget": "1.5.1",
        "fixtures": fixtures,
    }
    write_file(CORPUS_ROOT / "manifest.json", text_bytes(json.dumps(manifest, indent=2, sort_keys=True) + "\n"))
    return fixtures


def main() -> None:
    fixtures = build()
    print(f"Generated {len(fixtures)} fixtures into {CORPUS_ROOT}\\")


if __name__ == "__main__":
    main()
