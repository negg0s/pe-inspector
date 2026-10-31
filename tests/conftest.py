import os
import struct
import uuid

import pytest

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
EXTRA_RVA = 0x3000

SCN_CODE = 0x00000020
SCN_INITIALIZED_DATA = 0x00000040
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

SCN_TEXT = SCN_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ
SCN_RDATA = SCN_INITIALIZED_DATA | SCN_MEM_READ
SCN_DATA = SCN_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE
SCN_WX = SCN_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ | SCN_MEM_WRITE


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def _u16(value):
    return struct.pack("<H", value)


def _u32(value):
    return struct.pack("<I", value)


class _Blob:
    def __init__(self):
        self.data = bytearray()

    def add(self, raw, align=4):
        while len(self.data) % align:
            self.data.append(0)
        offset = len(self.data)
        self.data += raw
        return offset

    def patch_u32(self, offset, value):
        struct.pack_into("<I", self.data, offset, value)


def _build_imports(blob, imports, rva_base):
    descriptor_offset = blob.add(b"\x00" * (20 * (len(imports) + 1)), 4)
    for index, (dll, functions) in enumerate(imports):
        ilt = blob.add(b"\x00" * (4 * (len(functions) + 1)), 4)
        iat = blob.add(b"\x00" * (4 * (len(functions) + 1)), 4)
        for slot, name in enumerate(functions):
            hint_name = blob.add(_u16(0) + name.encode("ascii") + b"\x00", 2)
            blob.patch_u32(ilt + 4 * slot, rva_base + hint_name)
            blob.patch_u32(iat + 4 * slot, rva_base + hint_name)
        dll_name = blob.add(dll.encode("ascii") + b"\x00", 2)
        base = descriptor_offset + 20 * index
        struct.pack_into(
            "<IIIII",
            blob.data,
            base,
            rva_base + ilt,
            0,
            0,
            rva_base + dll_name,
            rva_base + iat,
        )
    return descriptor_offset


def _build_exports(blob, dll_name, names, function_rva, rva_base):
    directory = blob.add(b"\x00" * 40, 4)
    functions = blob.add(b"".join(_u32(function_rva) for _ in names), 4)
    name_rvas = []
    for name in names:
        offset = blob.add(name.encode("ascii") + b"\x00", 2)
        name_rvas.append(rva_base + offset)
    names_table = blob.add(b"".join(_u32(value) for value in name_rvas), 4)
    ordinals = blob.add(b"".join(_u16(i) for i in range(len(names))), 2)
    module_name = blob.add(dll_name.encode("ascii") + b"\x00", 2)
    struct.pack_into(
        "<IIHHIIIIIII",
        blob.data,
        directory,
        0,
        0,
        0,
        0,
        rva_base + module_name,
        1,
        len(names),
        len(names),
        rva_base + functions,
        rva_base + names_table,
        rva_base + ordinals,
    )
    return directory


def _wstr(text):
    return (text + "\x00").encode("utf-16-le")


def _version_node(key, value=b"", children=(), value_length=None, type_=0):
    if value_length is None:
        value_length = len(value)
    body = bytearray(_wstr(key))
    while (6 + len(body)) % 4:
        body.append(0)
    if value:
        body += value
        while (6 + len(body)) % 4:
            body.append(0)
    for child in children:
        body += child
        while (6 + len(body)) % 4:
            body.append(0)
    return struct.pack("<HHH", 6 + len(body), value_length, type_) + bytes(body)


def _build_version_info(strings):
    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,
        0x00010000,
        (1 << 16) | 2,
        (3 << 16) | 4,
        (1 << 16) | 2,
        (3 << 16) | 4,
        0x3F,
        0,
        0x40004,
        1,
        0,
        0,
        0,
    )
    entries = [
        _version_node(key, value=_wstr(value), value_length=len(value) + 1, type_=1)
        for key, value in strings.items()
    ]
    table = _version_node("040904B0", children=entries, type_=1)
    string_file_info = _version_node("StringFileInfo", children=[table], type_=1)
    return _version_node(
        "VS_VERSION_INFO",
        value=fixed,
        value_length=len(fixed),
        children=[string_file_info],
    )


def _build_resources(types, rva_base):
    offsets = {}
    cursor = 16 + 8 * len(types)
    for type_id, names in types:
        offsets[("type", type_id)] = cursor
        cursor += 16 + 8 * len(names)
    for type_id, names in types:
        for name_id, _ in names:
            offsets[("name", type_id, name_id)] = cursor
            cursor += 24
    data_entries = {}
    for type_id, names in types:
        for name_id, _ in names:
            data_entries[(type_id, name_id)] = cursor
            cursor += 16
    blobs = {}
    for type_id, names in types:
        for name_id, data in names:
            cursor = _align(cursor, 4)
            blobs[(type_id, name_id)] = cursor
            cursor += len(data)

    buffer = bytearray(cursor)

    def write_directory(offset, entries, subdir=True):
        struct.pack_into("<IIHHHH", buffer, offset, 0, 0, 0, 0, 0, len(entries))
        for index, (ident, child) in enumerate(entries):
            target = child | 0x80000000 if subdir else child
            struct.pack_into("<II", buffer, offset + 16 + 8 * index, ident, target)

    write_directory(0, [(type_id, offsets[("type", type_id)]) for type_id, _ in types])
    for type_id, names in types:
        write_directory(offsets[("type", type_id)], [(name_id, offsets[("name", type_id, name_id)]) for name_id, _ in names])
        for name_id, data in names:
            write_directory(offsets[("name", type_id, name_id)], [(1033, data_entries[(type_id, name_id)])], subdir=False)
            struct.pack_into(
                "<IIII",
                buffer,
                data_entries[(type_id, name_id)],
                rva_base + blobs[(type_id, name_id)],
                len(data),
                0,
                0,
            )
            start = blobs[(type_id, name_id)]
            buffer[start : start + len(data)] = data
    return bytes(buffer)


def _pe_checksum(data, checksum_offset):
    copy = bytearray(data)
    struct.pack_into("<I", copy, checksum_offset, 0)
    if len(copy) % 2:
        copy.append(0)
    total = 0
    for index in range(0, len(copy), 2):
        total += struct.unpack_from("<H", copy, index)[0]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total + len(data)


def build_pe(
    path,
    imports=None,
    exports=None,
    version_strings=None,
    resource_types=None,
    dll_characteristics=0x0140,
    extra_sections=None,
    overlay=b"",
    signature=False,
    subsystem=3,
    is_dll=False,
    timestamp=1600000000,
    fix_checksum=True,
):
    imports = imports or []
    exports = exports or []
    extra_sections = extra_sections or []
    resource_types = list(resource_types or [])
    if version_strings:
        resource_types.insert(0, (16, [(1, _build_version_info(version_strings))]))

    rdata = _Blob()
    export_offset = None
    import_offset = None
    resource_blob = b""
    if resource_types:
        resource_blob = _build_resources(resource_types, RDATA_RVA)
        rdata.data += resource_blob
    if exports:
        export_offset = _build_exports(rdata, os.path.basename(path), exports, TEXT_RVA, RDATA_RVA)
    if imports:
        import_offset = _build_imports(rdata, imports, RDATA_RVA)

    sections = [(".text", b"\x90" * 0x200, SCN_TEXT)]
    if rdata.data:
        sections.append((".rdata", bytes(rdata.data), SCN_RDATA))
    sections.extend(extra_sections)

    rva = SECTION_ALIGN
    section_records = []
    for name, content, flags in sections:
        raw_size = _align(max(len(content), 1), FILE_ALIGN)
        virtual_size = _align(max(len(content), 1), SECTION_ALIGN)
        section_records.append(
            {
                "name": name.encode("ascii"),
                "rva": rva,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "content": content,
                "flags": flags,
            }
        )
        rva += _align(virtual_size, SECTION_ALIGN)

    headers_size = _align(0x40 + 4 + 20 + 224 + 40 * len(section_records), FILE_ALIGN)
    size_of_image = rva
    image_base = 0x400000

    security_offset = None
    certificate = b""
    if signature:
        payload = b"\x30\x82" + b"\x00" * 30
        certificate = struct.pack("<IHH", 8 + len(payload), 0x0200, 0x0002) + payload
        end_of_sections = headers_size + sum(s["raw_size"] for s in section_records)
        security_offset = _align(end_of_sections + len(overlay), 8)

    data_directories = [(0, 0)] * 16
    if export_offset is not None:
        data_directories[0] = (RDATA_RVA + export_offset, 40)
    if import_offset is not None:
        data_directories[1] = (RDATA_RVA + import_offset, 20 * (len(imports) + 1))
    if resource_blob:
        data_directories[2] = (RDATA_RVA, len(resource_blob))
    if signature:
        data_directories[4] = (security_offset, len(certificate))

    directories_bytes = b"".join(_u32(rva_) + _u32(size) for rva_, size in data_directories)

    characteristics = 0x0102 | (0x2000 if is_dll else 0)
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        len(section_records),
        timestamp,
        0,
        0,
        224,
        characteristics,
    )
    optional = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        14,
        0,
        sum(s["raw_size"] for s in section_records if s["name"] == b".text"),
        sum(s["raw_size"] for s in section_records if s["name"] != b".text"),
        0,
        TEXT_RVA,
        TEXT_RVA,
        RDATA_RVA,
        image_base,
        SECTION_ALIGN,
        FILE_ALIGN,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        subsystem,
        dll_characteristics,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    ) + directories_bytes

    section_table = b"".join(
        struct.pack(
            "<8sIIIIIIHHI",
            s["name"].ljust(8, b"\x00"),
            s["virtual_size"],
            s["rva"],
            s["raw_size"],
            headers_size + sum(o["raw_size"] for o in section_records[: index]),
            0,
            0,
            0,
            0,
            s["flags"],
        )
        for index, s in enumerate(section_records)
    )

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    header = bytes(dos) + b"PE\x00\x00" + coff + optional + section_table
    header = header.ljust(headers_size, b"\x00")

    body = bytearray(header)
    for record in section_records:
        body += record["content"].ljust(record["raw_size"], b"\x00")
    body += overlay
    if signature:
        body += b"\x00" * (security_offset - len(body))
        body += certificate

    data = bytes(body)
    if fix_checksum:
        checksum_offset = 0x40 + 4 + 20 + 0x40
        value = _pe_checksum(data, checksum_offset)
        data = bytearray(data)
        struct.pack_into("<I", data, checksum_offset, value)
        data = bytes(data)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def _temp_pe(prefix):
    directory = "D:/temp/pe-inspector/tests"
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, "%s_%s.exe" % (prefix, uuid.uuid4().hex))


@pytest.fixture
def minimal_pe():
    path = _temp_pe("minimal")
    build_pe(path)
    yield path
    _remove(path)


@pytest.fixture
def hardened_pe():
    path = _temp_pe("hardened")
    build_pe(path, dll_characteristics=0x0140)
    yield path
    _remove(path)


@pytest.fixture
def imports_pe():
    path = _temp_pe("imports")
    build_pe(
        path,
        imports=[
            ("kernel32.dll", ["LoadLibraryA", "GetProcAddress", "CreateRemoteThread", "VirtualAllocEx"]),
            ("user32.dll", ["MessageBoxA"]),
        ],
    )
    yield path
    _remove(path)


@pytest.fixture
def exports_pe():
    path = _temp_pe("exports")
    build_pe(path, exports=["Alpha", "Beta", "Gamma"])
    yield path
    _remove(path)


@pytest.fixture
def resources_pe():
    path = _temp_pe("resources")
    build_pe(
        path,
        resource_types=[
            (3, [(1, b"icon-one"), (2, b"icon-two")]),
            (10, [(1, b"raw-data")]),
        ],
    )
    yield path
    _remove(path)


@pytest.fixture
def version_pe():
    path = _temp_pe("version")
    build_pe(
        path,
        version_strings={
            "CompanyName": "Acme Tools",
            "FileDescription": "Fixture Binary",
            "FileVersion": "1.2.3.4",
            "ProductName": "Fixture",
        },
    )
    yield path
    _remove(path)


@pytest.fixture
def overlay_pe():
    path = _temp_pe("overlay")
    build_pe(path, overlay=b"OVERLAY" * 64)
    yield path
    _remove(path)


@pytest.fixture
def signature_pe():
    path = _temp_pe("signature")
    build_pe(path, signature=True)
    yield path
    _remove(path)


@pytest.fixture
def risky_pe():
    path = _temp_pe("risky")
    dense = bytes(range(256)) * 8
    build_pe(
        path,
        imports=[
            ("kernel32.dll", ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"]),
            ("wininet.dll", ["InternetOpenA", "HttpSendRequestA"]),
        ],
        dll_characteristics=0,
        extra_sections=[(".wx", dense, SCN_WX)],
        overlay=b"MZ" + b"\x00" * 200,
    )
    yield path
    _remove(path)


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass
