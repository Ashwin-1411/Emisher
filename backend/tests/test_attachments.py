import hashlib
import io
import zipfile

from helpers import load_fixture

from app.attachments import analyze_attachment, detect_type
from app.attachments.analyze import file_extensions
from app.models import AttachmentData
from app.parsing import parse_email


def att(name: str, data: bytes, ctype: str = "application/octet-stream") -> AttachmentData:
    return AttachmentData(filename=name, content_type=ctype, size=len(data), data=data)


def test_hashes_match_hashlib() -> None:
    data = b"hello"
    f = analyze_attachment(att("a.txt", data))
    assert f.sha256 == hashlib.sha256(data).hexdigest()
    assert f.md5 == hashlib.md5(data).hexdigest()  # noqa: S324 - comparing, not securing
    assert f.sha1 == hashlib.sha1(data).hexdigest()  # noqa: S324


def test_eicar_hash_constant() -> None:
    """EICAR is the industry-standard *harmless* antivirus test string. Every AV engine flags it
    on purpose, which makes it the right input for the 'known malicious hash' path. We build it
    in memory (two halves) so the repo never contains a file that antivirus would quarantine."""
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    finding = analyze_attachment(att("eicar.com", eicar))
    assert finding.sha256 == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_detect_type_by_magic_not_extension() -> None:
    assert detect_type(b"MZ\x90\x00")[0] == "pe"
    assert detect_type(b"%PDF-1.7\n")[0] == "pdf"
    assert detect_type(b"\x89PNG\r\n\x1a\n....")[0] == "png"
    assert detect_type(b"<!DOCTYPE html><html>")[0] == "html"
    assert detect_type(b"plain words here")[0] == "text"
    assert detect_type(bytes(range(256)) * 4)[0] == "unknown"


def test_file_extensions_handles_padding_tricks() -> None:
    assert file_extensions("invoice.pdf.exe") == ["pdf", "exe"]
    assert file_extensions("invoice.pdf          .exe") == ["pdf", "exe"]
    assert file_extensions("README") == []


def test_double_extension_and_executable_fixture() -> None:
    email = parse_email(load_fixture("07_double_extension.eml"))
    f = analyze_attachment(email.attachments[0])
    assert f.detected_type == "pe"
    assert {"double_extension", "executable"} <= set(f.flags)


def test_rtl_override_filename() -> None:
    f = analyze_attachment(att("invoice‮gpj.exe", b"MZ" + b"\x00" * 10))
    assert "rtl_override" in f.flags


def test_extension_mismatch() -> None:
    f = analyze_attachment(att("photo.jpg", b"MZ" + b"\x00" * 10))
    assert "type_mismatch" in f.flags and "executable" in f.flags
    ok = analyze_attachment(att("doc.pdf", b"%PDF-1.4 ok"))
    assert "type_mismatch" not in ok.flags
    renamed = analyze_attachment(att("report.pdf", b"<html><body>fake login</body></html>"))
    assert "type_mismatch" in renamed.flags


def test_password_protected_zip() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", "x")
    data = bytearray(buf.getvalue())
    # Set the "encrypted" bit (bit 0 of the general-purpose flag) in both headers.
    for marker in (b"PK\x03\x04", b"PK\x01\x02"):
        i = data.find(marker)
        offset = i + (6 if marker == b"PK\x03\x04" else 8)
        data[offset] |= 0x01
    f = analyze_attachment(att("docs.zip", bytes(data)))
    assert "password_protected" in f.flags
    plain = analyze_attachment(att("docs.zip", buf.getvalue()))
    assert "password_protected" not in plain.flags


def test_macro_document_fixture() -> None:
    email = parse_email(load_fixture("08_macro_doc.eml"))
    f = analyze_attachment(email.attachments[0])
    assert f.detected_type == "docx"
    assert f.macro.has_macros and "AutoOpen" in f.macro.autoexec
    assert {"macros", "macro_autoexec"} <= set(f.flags)
    assert "type_mismatch" not in f.flags  # .docm legitimately is an OOXML zip


def test_clean_office_document_has_no_macros() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    f = analyze_attachment(att("a.docx", buf.getvalue()))
    assert f.detected_type == "docx" and not f.macro.has_macros


def test_corrupt_office_file_does_not_crash() -> None:
    f = analyze_attachment(att("bad.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100))
    assert f.detected_type in ("ole", "doc")
