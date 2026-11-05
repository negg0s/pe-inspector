"""Core PE inspection helpers."""

import datetime
import hashlib
import math
import os
import struct

import pefile

SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "VirtualAllocEx",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "OpenProcess",
    "CreateProcessA",
    "CreateProcessW",
    "ShellExecuteA",
    "ShellExecuteW",
    "WinExec",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    "LdrLoadDll",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyState",
    "CryptEncrypt",
    "CryptDecrypt",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "AdjustTokenPrivileges",
    "OpenProcessToken",
    "LookupPrivilegeValueA",
    "LookupPrivilegeValueW",
    "RegSetValueExA",
    "RegSetValueExW",
    "CreateServiceA",
    "CreateServiceW",
    "StartServiceA",
    "StartServiceW",
}

MACHINE_NAMES = {
    0x014C: "i386",
    0x8664: "AMD64",
    0x0200: "IA64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}

SUBSYSTEM_NAMES = {
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

DLL_CHARACTERISTICS = [
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_SECURITY = 4

SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_WRITE = 0x80000000

DLLCHAR_DYNAMIC_BASE = 0x0040
DLLCHAR_NX_COMPAT = 0x0100

HIGH_ENTROPY_THRESHOLD = 7.0
HIGH_ENTROPY_MIN_SIZE = 512

SCAN_WEIGHTS = {
    "wx_section": 25,
    "high_entropy": 15,
    "suspicious_imports": 25,
    "no_aslr": 8,
    "no_dep": 8,
    "overlay": 8,
}

SCAN_DISCLAIMER = (
    "Heuristic score from static indicators. It is not a malware verdict."
)

CERTIFICATE_TYPES = {
    0x0001: "X509",
    0x0002: "PKCS_SIGNED_DATA",
    0x0003: "RESERVED_1",
    0x0004: "TS_STACK_SIGNED",
}


def load_pe(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    try:
        return pefile.PE(path)
    except pefile.PEFormatError as exc:
        raise ValueError("not a valid PE file: %s" % path) from exc


def _decode(value):
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return value.decode("latin-1", errors="replace")
    return str(value)


def _decode_utf16(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.rstrip("\x00")
    if b"\x00" not in value:
        return value.decode("latin-1", errors="replace").rstrip("\x00")
    return value.decode("utf-16-le", errors="replace").rstrip("\x00")


def _section_name(sec):
    return _decode(sec.Name.split(b"\x00", 1)[0])


def _file_hashes(path):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def _timestamp_utc(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromtimestamp(
            value, datetime.timezone.utc
        ).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _data_directory(pe, index):
    try:
        return pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    except (AttributeError, IndexError):
        return None


def get_info(path):
    pe = load_pe(path)
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    try:
        md5, sha256 = _file_hashes(path)
    except OSError:
        md5 = sha256 = None
    return {
        "file": os.path.abspath(path),
        "size": os.path.getsize(path),
        "machine": MACHINE_NAMES.get(fh.Machine, hex(fh.Machine)),
        "machine_raw": hex(fh.Machine),
        "number_of_sections": fh.NumberOfSections,
        "timestamp": fh.TimeDateStamp,
        "characteristics": hex(fh.Characteristics),
        "entry_point": hex(oh.AddressOfEntryPoint),
        "image_base": hex(oh.ImageBase),
        "subsystem": SUBSYSTEM_NAMES.get(oh.Subsystem, str(oh.Subsystem)),
        "subsystem_raw": oh.Subsystem,
        "size_of_image": hex(oh.SizeOfImage),
        "size_of_headers": hex(oh.SizeOfHeaders),
        "number_of_rva_and_sizes": oh.NumberOfRvaAndSizes,
        "md5": md5,
        "sha256": sha256,
    }


def get_headers(path):
    pe = load_pe(path)
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    dll_flags = [name for bit, name in DLL_CHARACTERISTICS if oh.DllCharacteristics & bit]
    stored = oh.CheckSum
    computed = pe.generate_checksum()
    return {
        "file": os.path.abspath(path),
        "size": os.path.getsize(path),
        "machine": MACHINE_NAMES.get(fh.Machine, hex(fh.Machine)),
        "machine_raw": hex(fh.Machine),
        "is_dll": bool(fh.Characteristics & 0x2000),
        "is_64bit": pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS,
        "subsystem": SUBSYSTEM_NAMES.get(oh.Subsystem, str(oh.Subsystem)),
        "subsystem_raw": oh.Subsystem,
        "dll_characteristics": hex(oh.DllCharacteristics),
        "dll_characteristics_flags": dll_flags,
        "compile_time": fh.TimeDateStamp,
        "compile_time_utc": _timestamp_utc(fh.TimeDateStamp),
        "entry_point": hex(oh.AddressOfEntryPoint),
        "image_base": hex(oh.ImageBase),
        "checksum_stored": hex(stored),
        "checksum_computed": hex(computed),
        "checksum_matches": stored == computed,
        "number_of_sections": fh.NumberOfSections,
        "size_of_image": hex(oh.SizeOfImage),
        "size_of_headers": hex(oh.SizeOfHeaders),
        "section_alignment": hex(oh.SectionAlignment),
        "file_alignment": hex(oh.FileAlignment),
    }


def get_sections(path):
    pe = load_pe(path)
    out = []
    for sec in pe.sections:
        out.append(
            {
                "name": _section_name(sec),
                "virtual_size": sec.Misc_VirtualSize,
                "virtual_address": hex(sec.VirtualAddress),
                "raw_size": sec.SizeOfRawData,
                "raw_offset": sec.PointerToRawData,
                "entropy": round(sec.get_entropy(), 4),
                "characteristics": hex(sec.Characteristics),
                "writable": bool(sec.Characteristics & SCN_MEM_WRITE),
                "executable": bool(sec.Characteristics & SCN_MEM_EXECUTE),
            }
        )
    return out


def get_imports(path, suspicious=False):
    pe = load_pe(path)
    out = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return out
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = _decode(entry.dll)
        for imp in entry.imports:
            if imp.name is not None:
                name = _decode(imp.name)
            else:
                name = "ordinal_%d" % imp.ordinal
            rec = {
                "dll": dll,
                "name": name,
                "address": hex(imp.address) if getattr(imp, "address", None) is not None else None,
                "suspicious": name in SUSPICIOUS_IMPORTS,
            }
            if suspicious and not rec["suspicious"]:
                continue
            out.append(rec)
    return out


def get_exports(path):
    pe = load_pe(path)
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    result = {"dll_name": None, "exports": []}
    if directory is None:
        return result
    result["dll_name"] = _decode(getattr(directory, "name", None))
    for sym in directory.symbols:
        result["exports"].append(
            {
                "name": _decode(sym.name) if sym.name else None,
                "ordinal": sym.ordinal,
                "rva": hex(sym.address),
                "forwarder": _decode(sym.forwarder) if sym.forwarder else None,
            }
        )
    return result


def _count_resource_leaves(entries):
    count = 0
    size = 0
    for entry in entries:
        data = getattr(entry, "data", None)
        if data is not None:
            count += 1
            size += getattr(data.struct, "Size", 0)
        directory = getattr(entry, "directory", None)
        if directory is not None:
            child_count, child_size = _count_resource_leaves(directory.entries)
            count += child_count
            size += child_size
    return count, size


def get_resources(path):
    pe = load_pe(path)
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    result = {"total": 0, "types": []}
    if root is None:
        return result
    total = 0
    for entry in root.entries:
        count = 0
        size = 0
        if getattr(entry, "directory", None) is not None:
            count, size = _count_resource_leaves(entry.directory.entries)
        result["types"].append(
            {
                "id": entry.id,
                "type": pefile.RESOURCE_TYPE.get(entry.id, "UNKNOWN"),
                "count": count,
                "size": size,
            }
        )
        total += count
    result["types"].sort(key=lambda item: item["id"])
    result["total"] = total
    return result


def _version_number(ms, ls):
    return "%d.%d.%d.%d" % (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)


def get_version(path):
    pe = load_pe(path)
    result = {"present": False, "fixed": None, "strings": {}}
    fixed_entries = getattr(pe, "VS_FIXEDFILEINFO", None)
    if fixed_entries:
        fixed = fixed_entries[0]
        result["present"] = True
        result["fixed"] = {
            "file_version": _version_number(fixed.FileVersionMS, fixed.FileVersionLS),
            "product_version": _version_number(fixed.ProductVersionMS, fixed.ProductVersionLS),
            "file_flags": hex(fixed.FileFlags),
            "file_os": hex(fixed.FileOS),
            "file_type": hex(fixed.FileType),
            "file_subtype": hex(fixed.FileSubtype),
        }
    strings = {}
    for group in getattr(pe, "FileInfo", None) or []:
        for info in group:
            for table in getattr(info, "StringTable", None) or []:
                for key, value in getattr(table, "entries", {}).items():
                    strings[_decode_utf16(key)] = _decode_utf16(value)
    if strings:
        result["present"] = True
    result["strings"] = strings
    return result


def _file_entropy(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


def get_entropy(path):
    pe = load_pe(path)
    sections = []
    for sec in pe.sections:
        sections.append(
            {
                "name": _section_name(sec),
                "entropy": round(sec.get_entropy(), 4),
                "raw_size": sec.SizeOfRawData,
            }
        )
    return {
        "file": os.path.abspath(path),
        "file_entropy": _file_entropy(path),
        "sections": sections,
    }


def get_overlay(path):
    pe = load_pe(path)
    offset = pe.get_overlay_data_start_offset()
    size = os.path.getsize(path)
    if offset is None or offset >= size:
        return {
            "present": False,
            "offset": None,
            "size": 0,
            "percent": 0.0,
            "contains_signature": False,
        }
    security = _data_directory(pe, IMAGE_DIRECTORY_ENTRY_SECURITY)
    contains_signature = bool(
        security
        and security.VirtualAddress
        and security.Size
        and offset <= security.VirtualAddress < size
    )
    overlay_size = size - offset
    return {
        "present": True,
        "offset": offset,
        "size": overlay_size,
        "percent": round(overlay_size * 100.0 / size, 2) if size else 0.0,
        "contains_signature": contains_signature,
    }


def get_signature(path):
    pe = load_pe(path)
    result = {
        "present": False,
        "valid": False,
        "validation_performed": False,
        "offset": None,
        "size": 0,
        "certificate_length": None,
        "revision": None,
        "certificate_type": None,
    }
    security = _data_directory(pe, IMAGE_DIRECTORY_ENTRY_SECURITY)
    file_size = os.path.getsize(path)
    if (
        security is None
        or not security.VirtualAddress
        or security.Size < 8
        or security.VirtualAddress > file_size
        or security.Size > file_size - security.VirtualAddress
    ):
        return result
    result["present"] = True
    result["offset"] = security.VirtualAddress
    result["size"] = security.Size
    with open(path, "rb") as fh:
        fh.seek(security.VirtualAddress)
        header = fh.read(8)
    if len(header) == 8:
        length, revision, cert_type = struct.unpack("<IHH", header)
        if length < 8 or length > security.Size:
            result["present"] = False
            result["offset"] = None
            result["size"] = 0
            return result
        result["certificate_length"] = length
        result["revision"] = hex(revision)
        result["certificate_type"] = CERTIFICATE_TYPES.get(cert_type, hex(cert_type))
    return result


def get_mitigations(path):
    pe = load_pe(path)
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER
    dll_chars = getattr(oh, "DllCharacteristics", 0)

    is_64bit = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
    aslr = bool(dll_chars & 0x0040)
    high_entropy_va = bool(dll_chars & 0x0020) if is_64bit else False
    relocs_stripped = bool(fh.Characteristics & 0x0001)

    dep = bool(dll_chars & 0x0100)
    guard_cf = bool(dll_chars & 0x4000)

    cfg_instrumented = False
    cfg_function_table = False
    safeseh_present = False

    load_config = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
    if load_config is not None:
        lc_struct = getattr(load_config, "struct", None)
        if lc_struct:
            guard_flags = getattr(lc_struct, "GuardFlags", 0)
            if guard_flags:
                cfg_instrumented = bool(guard_flags & 0x00000100)
                cfg_function_table = bool(guard_flags & 0x00000400)
            if not is_64bit:
                se_table = getattr(lc_struct, "SEHandlerTable", 0)
                se_count = getattr(lc_struct, "SEHandlerCount", 0)
                if se_table != 0 or se_count != 0:
                    safeseh_present = True

    if not is_64bit:
        if bool(dll_chars & 0x0400):
            safeseh = "no_seh"
        elif safeseh_present:
            safeseh = "present"
        else:
            safeseh = "missing"
    else:
        safeseh = "not_applicable_x64"

    sig = get_signature(path)

    return {
        "file": os.path.abspath(path),
        "is_64bit": is_64bit,
        "aslr": aslr and not relocs_stripped,
        "high_entropy_va": high_entropy_va,
        "dep": dep,
        "cfg": guard_cf or cfg_instrumented,
        "safeseh": safeseh,
        "force_integrity": bool(dll_chars & 0x0080),
        "isolation": not bool(dll_chars & 0x0200),
        "authenticode": sig["present"],
        "appcontainer": bool(dll_chars & 0x1000),
    }


def get_tls(path):
    pe = load_pe(path)
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS") or pe.DIRECTORY_ENTRY_TLS is None:
        return {
            "present": False,
            "start_address": None,
            "end_address": None,
            "callbacks": [],
            "callbacks_count": 0,
        }
    tls = pe.DIRECTORY_ENTRY_TLS
    tls_struct = tls.struct
    raw_callbacks = getattr(tls, "callbacks", None) or []
    callbacks = [hex(cb) for cb in raw_callbacks if cb != 0]
    return {
        "present": True,
        "start_address": hex(tls_struct.StartAddressOfRawData),
        "end_address": hex(tls_struct.EndAddressOfRawData),
        "callbacks": callbacks,
        "callbacks_count": len(callbacks),
    }


def scan(path):
    pe = load_pe(path)
    reasons = []
    sections = get_sections(path)

    wx = [s for s in sections if s["writable"] and s["executable"]]
    for sec in wx[:2]:
        reasons.append(
            {
                "id": "wx_section",
                "weight": SCAN_WEIGHTS["wx_section"],
                "detail": "section %s is writable and executable" % sec["name"],
            }
        )

    dense = [
        s
        for s in sections
        if s["entropy"] >= HIGH_ENTROPY_THRESHOLD
        and s["raw_size"] >= HIGH_ENTROPY_MIN_SIZE
    ]
    for sec in dense[:2]:
        reasons.append(
            {
                "id": "high_entropy",
                "weight": SCAN_WEIGHTS["high_entropy"],
                "detail": "section %s has entropy %.2f" % (sec["name"], sec["entropy"]),
            }
        )

    imports = get_imports(path)
    suspicious = sorted({i["name"] for i in imports if i["suspicious"]})
    if suspicious:
        weight = min(SCAN_WEIGHTS["suspicious_imports"], 3 * len(suspicious))
        reasons.append(
            {
                "id": "suspicious_imports",
                "weight": weight,
                "detail": "%d flagged imports: %s"
                % (len(suspicious), ", ".join(suspicious)),
            }
        )

    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    if not dll_characteristics & DLLCHAR_DYNAMIC_BASE:
        reasons.append(
            {
                "id": "no_aslr",
                "weight": SCAN_WEIGHTS["no_aslr"],
                "detail": "DYNAMIC_BASE is not set, image does not opt into ASLR",
            }
        )
    if not dll_characteristics & DLLCHAR_NX_COMPAT:
        reasons.append(
            {
                "id": "no_dep",
                "weight": SCAN_WEIGHTS["no_dep"],
                "detail": "NX_COMPAT is not set, image does not opt into DEP",
            }
        )

    overlay = get_overlay(path)
    if overlay["present"]:
        reasons.append(
            {
                "id": "overlay",
                "weight": SCAN_WEIGHTS["overlay"],
                "detail": "%d bytes of data after the last section" % overlay["size"],
            }
        )

    reasons.sort(key=lambda item: item["weight"], reverse=True)
    score = min(100, sum(item["weight"] for item in reasons))
    if score >= 60:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "file": os.path.abspath(path),
        "score": score,
        "level": level,
        "reasons": reasons,
        "disclaimer": SCAN_DISCLAIMER,
    }


def generate_report(path, fmt="text"):
    info = get_info(path)
    sections = get_sections(path)
    imports = get_imports(path)
    entropy = get_entropy(path)
    signature = get_signature(path)
    mitigations = get_mitigations(path)
    tls_info = get_tls(path)
    scan_result = scan(path)
    suspicious = [i for i in imports if i["suspicious"]]

    explanations = {
        "wx_section": lambda reason: (
            "Section %s is writable and executable, so it can be changed while "
            "also containing code. Some legitimate programs do this." % reason["detail"].split(" ")[1]
        ),
        "high_entropy": lambda reason: (
            "%s is unusually dense or encoded. Compression and installers can "
            "also cause this." % reason["detail"].split(" ")[1]
        ),
        "suspicious_imports": lambda reason: (
            "The program uses APIs that can be used to inspect or control other "
            "programs. This can also be normal for system tools and debuggers."
        ),
        "no_aslr": lambda reason: (
            "The file does not request ASLR, a Windows feature that randomizes "
            "where program code is loaded. Older software may lack this."
        ),
        "no_dep": lambda reason: (
            "The file does not request DEP, a Windows feature that helps stop "
            "data from being run as code. Older software may lack this."
        ),
        "overlay": lambda reason: (
            "There is extra data after the program's sections. This can be "
            "legitimate, but its purpose is not clear from this check."
        ),
    }
    what_this_means = [explanations[item["id"]](item) for item in scan_result["reasons"]]

    if fmt == "json":
        import json

        payload = {
            "info": info,
            "sections": sections,
            "imports": imports,
            "entropy": entropy,
            "suspicious_imports": suspicious,
            "signature": signature,
            "mitigations": mitigations,
            "tls": tls_info,
            "scan": scan_result,
            "what_this_means": what_this_means,
        }
        return json.dumps(payload, indent=2)

    lines = [
        "EXE check: %s" % os.path.basename(path),
        "=" * 60,
        "What this means",
        "This is a static check. The file was read, not run.",
        "Heuristics are not antivirus and cannot tell you whether a file is safe.",
        "A matching indicator is not proof that a file is malicious.",
        "",
        "Heuristic indicator score: %s/100 (%s)" % (scan_result["score"], scan_result["level"]),
        "This is a count of selected clues, not a probability or safety rating.",
    ]
    if what_this_means:
        lines.extend("- " + explanation for explanation in what_this_means)
    else:
        lines.append("No selected indicators matched. That does not prove the file is safe.")
    architecture = {
        "i386": "x86",
        "AMD64": "x64",
        "ARM": "ARM",
        "ARM64": "ARM64",
    }.get(info["machine"], "unknown architecture")
    bitness = 64 if info["machine"] in ("AMD64", "ARM64") else 32
    lines.extend([
        "",
        "Signature: %s" % ("Present" if signature["present"] else "Not found"),
        "Signature presence does not mean the signature is valid. Signature validity was not checked.",
        "",
        "File details",
        "  Name: %s" % os.path.basename(path),
        "  Size: %s bytes" % info["size"],
        "  Type: %s-bit %s Windows file" % (bitness, architecture),
        "  SHA-256: %s" % info["sha256"],
        "",
        "Technical details",
        "  Sections: %s" % len(sections),
        "  Imported functions: %s" % len(imports),
        "  TLS callbacks: %s" % (len(tls_info["callbacks"]) if tls_info["present"] else "none"),
        "  File entropy: %s" % entropy["file_entropy"],
    ])
    if suspicious:
        lines.append("  Flagged imports: " + ", ".join(sorted({i["name"] for i in suspicious})))
    if fmt == "markdown":
        return "\n".join(["# " + lines[0], ""] + ["## " + line if line in ("What this means", "File details", "Technical details") else line for line in lines[2:]])
    return "\n".join(lines)
