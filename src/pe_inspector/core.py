"""Core PE inspection helpers."""

import hashlib
import math
import os

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


def load_pe(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return pefile.PE(path)


def _section_name(sec):
    return sec.Name.split(b"\x00", 1)[0].decode("latin-1", errors="replace")


def get_info(path):
    pe = load_pe(path)
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    info = {
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
    }
    # checksums
    try:
        info["md5"] = hashlib.md5(open(path, "rb").read()).hexdigest()
        info["sha256"] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    except OSError:
        pass
    return info


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
            }
        )
    return out


def get_imports(path, suspicious=False):
    pe = load_pe(path)
    out = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return out
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("latin-1", errors="replace") if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
        for imp in entry.imports:
            name = None
            if imp.name is not None:
                name = imp.name.decode("latin-1", errors="replace") if isinstance(imp.name, (bytes, bytearray)) else str(imp.name)
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


def _file_entropy(path):
    data = open(path, "rb").read()
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


def generate_report(path, fmt="text"):
    info = get_info(path)
    sections = get_sections(path)
    imports = get_imports(path)
    entropy = get_entropy(path)
    suspicious = [i for i in imports if i["suspicious"]]

    if fmt == "json":
        import json

        payload = {
            "info": info,
            "sections": sections,
            "imports": imports,
            "entropy": entropy,
            "suspicious_imports": suspicious,
        }
        return json.dumps(payload, indent=2)

    if fmt == "markdown":
        lines = []
        lines.append("# PE Report: %s" % os.path.basename(path))
        lines.append("")
        lines.append("## Info")
        for k, v in info.items():
            lines.append("- **%s**: %s" % (k, v))
        lines.append("")
        lines.append("## Sections")
        lines.append("| Name | VirtualSize | RawSize | Entropy |")
        lines.append("|---|---|---|---|")
        for s in sections:
            lines.append("| %s | %s | %s | %s |" % (s["name"], s["virtual_size"], s["raw_size"], s["entropy"]))
        lines.append("")
        lines.append("## Imports (%d)" % len(imports))
        for i in imports:
            flag = " [SUSPICIOUS]" if i["suspicious"] else ""
            lines.append("- %s!%s%s" % (i["dll"], i["name"], flag))
        lines.append("")
        lines.append("## Entropy")
        lines.append("- File entropy: %s" % entropy["file_entropy"])
        for s in entropy["sections"]:
            lines.append("- %s: %s" % (s["name"], s["entropy"]))
        if suspicious:
            lines.append("")
            lines.append("## Suspicious Imports")
            for i in suspicious:
                lines.append("- %s!%s" % (i["dll"], i["name"]))
        return "\n".join(lines)

    # text
    lines = []
    lines.append("PE Report: %s" % path)
    lines.append("=" * 60)
    lines.append("INFO")
    for k, v in info.items():
        lines.append("  %s: %s" % (k, v))
    lines.append("")
    lines.append("SECTIONS")
    for s in sections:
        lines.append("  %-12s VA=%-10s VS=%-8s Raw=%-8s Entropy=%s" % (s["name"], s["virtual_address"], s["virtual_size"], s["raw_size"], s["entropy"]))
    lines.append("")
    lines.append("IMPORTS (%d)" % len(imports))
    for i in imports:
        flag = " [SUSPICIOUS]" if i["suspicious"] else ""
        lines.append("  %s!%s%s" % (i["dll"], i["name"], flag))
    lines.append("")
    lines.append("ENTROPY")
    lines.append("  file: %s" % entropy["file_entropy"])
    for s in entropy["sections"]:
        lines.append("  %s: %s" % (s["name"], s["entropy"]))
    if suspicious:
        lines.append("")
        lines.append("SUSPICIOUS IMPORTS (%d)" % len(suspicious))
        for i in suspicious:
            lines.append("  %s!%s" % (i["dll"], i["name"]))
    return "\n".join(lines)
