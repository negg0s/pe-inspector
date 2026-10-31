import os
import struct
import uuid

import pytest


def _make_pe(path):
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    pe_sig = b"PE\x00\x00"

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0,
        0,
        0,
        0xE0,
        0x0102,
    )

    fmt = "<HBB" + "I" * 9 + "H" * 6 + "I" + "I" * 3 + "H" * 2 + "I" * 4 + "I" * 2
    opt = struct.pack(
        fmt,
        0x10B,
        0,
        0,
        0,
        0,
        0,
        0x1000,
        0x1000,
        0x2000,
        0x400000,
        0x1000,
        0x200,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        0x3000,
        0x200,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    opt += b"\x00" * (16 * 8)
    assert len(opt) == 224

    sec = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    assert len(sec) == 40

    header = bytes(dos) + pe_sig + coff + opt + sec
    header = header.ljust(0x200, b"\x00")
    data = (header + b"\x90" * 0x200).ljust(0x400, b"\x00")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


@pytest.fixture
def minimal_pe():
    # Keep generated PE under D: temp as required; unique name avoids
    # file-lock conflicts between tests on Windows.
    d = "D:/temp/pe-inspector/tests"
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "minimal_%s.exe" % uuid.uuid4().hex)
    _make_pe(path)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass