"""Build a *harmless* macro-enabled Word document (.docm) with no external tools.

Why hand-roll this? Real macro documents need Microsoft Office to create, and we must not
download malware samples. A ``.docm`` is a ZIP whose ``word/vbaProject.bin`` is an OLE
compound file (CFB) holding VBA source. This module writes the smallest valid structure that
``olevba`` recognises. The only macro is ``AutoOpen -> MsgBox "..."``, which does nothing but
show a dialog (and olevba flags ``AutoOpen`` as an auto-exec trigger, which is what we test).

Spec references: MS-CFB (compound file), MS-OVBA (VBA project storage and compression).
"""

from __future__ import annotations

import io
import struct
import zipfile

SECTOR = 512
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
MIN_STREAM = 4096  # streams smaller than this live in the "mini stream"; we avoid that complexity


def _vba_container(data: bytes) -> bytes:
    """Wrap ``data`` (<= 4096 bytes, padded) in an MS-OVBA compressed container.

    Uses a single *uncompressed* chunk, which the format allows: we get a valid container
    without writing the LZ-style compressor.
    """
    data = data.ljust(4096, b"\x00")[:4096]
    header = (4096 + 2 - 3) | (0b011 << 12)  # chunk size-3, signature 0b011, flag bit15 = 0 (raw)
    return b"\x01" + struct.pack("<H", header) + data


def _rec(rec_id: int, payload: bytes) -> bytes:
    return struct.pack("<HI", rec_id, len(payload)) + payload


def _dir_stream(module: str) -> bytes:
    """MS-OVBA 2.3.4.2 'dir' stream describing one procedural module."""
    name = module.encode("ascii")
    uname = module.encode("utf-16-le")
    out = b""
    out += _rec(0x0001, struct.pack("<I", 1))  # PROJECTSYSKIND: Win32
    out += _rec(0x0002, struct.pack("<I", 0x409))  # PROJECTLCID
    out += _rec(0x0014, struct.pack("<I", 0x409))  # PROJECTLCIDINVOKE
    out += _rec(0x0003, struct.pack("<H", 1252))  # PROJECTCODEPAGE
    out += _rec(0x0004, b"VBAProject")  # PROJECTNAME
    out += _rec(0x0005, b"") + _rec(0x0040, b"")  # PROJECTDOCSTRING (+ unicode)
    out += _rec(0x0006, b"") + _rec(0x003D, b"")  # PROJECTHELPFILEPATH (+ second path)
    out += _rec(0x0007, struct.pack("<I", 0))  # PROJECTHELPCONTEXT
    out += _rec(0x0008, struct.pack("<I", 0))  # PROJECTLIBFLAGS
    out += struct.pack("<HIIH", 0x0009, 4, 1, 0)  # PROJECTVERSION (fixed 4-byte size field)
    out += _rec(0x000C, b"") + _rec(0x003C, b"")  # PROJECTCONSTANTS (+ unicode)
    out += _rec(0x000F, struct.pack("<H", 1))  # PROJECTMODULES count
    out += _rec(0x0013, struct.pack("<H", 0xFFFF))  # PROJECTCOOKIE
    out += _rec(0x0019, name)  # MODULENAME
    out += _rec(0x0047, uname)  # MODULENAMEUNICODE
    out += _rec(0x001A, name) + _rec(0x0032, uname)  # MODULESTREAMNAME (+ unicode)
    out += _rec(0x001C, b"") + _rec(0x0048, b"")  # MODULEDOCSTRING (+ unicode)
    out += _rec(0x0031, struct.pack("<I", 0))  # MODULEOFFSET: source starts at byte 0
    out += _rec(0x001E, struct.pack("<I", 0))  # MODULEHELPCONTEXT
    out += _rec(0x002C, struct.pack("<H", 0xFFFF))  # MODULECOOKIE
    out += _rec(0x0021, b"")  # MODULETYPE: procedural
    out += _rec(0x002B, b"")  # module terminator
    out += _rec(0x0010, b"")  # dir terminator
    return _vba_container(out)


def _dir_entry(
    name: str, kind: int, left: int, right: int, child: int, start: int, size: int
) -> bytes:
    raw = name.encode("utf-16-le")
    return struct.pack(
        "<64sHBBIII16sI8s8sIQ",
        raw.ljust(64, b"\x00"),
        len(raw) + 2 if name else 0,
        kind,
        1,  # colour: black. A valid (if degenerate) tree needs no re-balancing for readers.
        left,
        right,
        child,
        b"\x00" * 16,
        0,
        b"\x00" * 8,
        b"\x00" * 8,
        start,
        size,
    )


def build_vba_project_bin(source: str, module: str = "ThisDocument") -> bytes:
    """Return an OLE compound file containing ``VBA/dir``, ``VBA/<module>`` and ``VBA/_VBA_PROJECT``."""
    code = f'Attribute VB_Name = "{module}"\r\n{source}\r\n'.encode("ascii")
    streams = [
        ("dir", _dir_stream(module)),
        (module, _vba_container(code)),
        ("_VBA_PROJECT", (b"\xcc\x61\xff\xff\x00\x00\x00").ljust(MIN_STREAM, b"\x00")),
        # olevba insists on a root-level PROJECT stream; its text is padded with blank lines.
        (
            "PROJECT",
            f"ID={{00000000-0000-0000-0000-000000000000}}\r\nModule={module}\r\n".encode().ljust(
                MIN_STREAM, b"\n"
            ),
        ),
    ]

    # Sector plan: 0 = FAT, 1..2 = directory (8 entries), then each stream's sectors in order.
    next_sector = 3
    entries = []
    stream_data = b""
    layout = []
    for name, data in streams:
        n = -(-len(data) // SECTOR)
        layout.append((name, next_sector, len(data), n))
        stream_data += data.ljust(n * SECTOR, b"\x00")
        next_sector += n

    fat = [FREESECT] * 128
    fat[0] = FATSECT
    fat[1], fat[2] = 2, ENDOFCHAIN
    for _, start, _, n in layout:
        for i in range(n):
            fat[start + i] = start + i + 1 if i < n - 1 else ENDOFCHAIN
    assert next_sector <= 128, "fixture grew beyond a single FAT sector"

    # Directory tree: Root -> VBA(storage) -> {dir, module, _VBA_PROJECT} chained as right siblings.
    entries.append(_dir_entry("Root Entry", 5, NOSTREAM, NOSTREAM, 1, ENDOFCHAIN, 0))
    entries.append(_dir_entry("VBA", 1, NOSTREAM, 5, 2, 0, 0))
    entries.append(_dir_entry(layout[0][0], 2, NOSTREAM, 3, NOSTREAM, layout[0][1], layout[0][2]))
    entries.append(_dir_entry(layout[1][0], 2, NOSTREAM, 4, NOSTREAM, layout[1][1], layout[1][2]))
    entries.append(
        _dir_entry(layout[2][0], 2, NOSTREAM, NOSTREAM, NOSTREAM, layout[2][1], layout[2][2])
    )
    entries.append(
        _dir_entry(layout[3][0], 2, NOSTREAM, NOSTREAM, NOSTREAM, layout[3][1], layout[3][2])
    )
    while len(entries) < 8:
        entries.append(_dir_entry("", 0, NOSTREAM, NOSTREAM, NOSTREAM, 0, 0))

    difat = [0] + [FREESECT] * 108
    header = struct.pack(
        "<8s16sHHHHH6sIIIIIIIII109I",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"\x00" * 16,
        0x003E,
        0x0003,
        0xFFFE,
        9,
        6,
        b"\x00" * 6,
        0,  # number of directory sectors (must be 0 for v3)
        1,  # number of FAT sectors
        1,  # first directory sector
        0,
        MIN_STREAM,
        ENDOFCHAIN,  # no mini FAT
        0,
        ENDOFCHAIN,  # no DIFAT chain
        0,
        *difat,
    )
    return header + struct.pack("<128I", *fat) + b"".join(entries) + stream_data


_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'
    "</Types>"
)
_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships/officeDocument" Target="word/document.xml"/></Relationships>'
)
_DOC_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/'
    'vbaProject" Target="vbaProject.bin"/></Relationships>'
)
_DOCUMENT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body><w:p><w:r><w:t>Meeting notes (synthetic test document)</w:t></w:r></w:p></w:body>"
    "</w:document>"
)

HARMLESS_MACRO = (
    'Sub AutoOpen()\r\n    MsgBox "Harmless test macro for phishing-analyzer fixtures"\r\nEnd Sub'
)


def build_docm() -> bytes:
    """Return the bytes of a macro-enabled .docm whose only macro is a MsgBox in AutoOpen."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("_rels/.rels", _RELS)
        zf.writestr("word/document.xml", _DOCUMENT)
        zf.writestr("word/_rels/document.xml.rels", _DOC_RELS)
        zf.writestr("word/vbaProject.bin", build_vba_project_bin(HARMLESS_MACRO))
    return buf.getvalue()
