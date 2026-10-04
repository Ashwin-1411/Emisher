from email.message import EmailMessage

from helpers import load_fixture

from app.parsing import parse_email


def test_headers_keep_wire_order_and_repeats() -> None:
    email = parse_email(load_fixture("01_legit.eml"))
    names = [h.name for h in email.headers]
    assert names[0] == "DKIM-Signature"
    received = email.get_headers("Received")
    assert len(received) == 2
    assert received[0].startswith("from mail.example.com")  # newest hop first, as on the wire


def test_identity_fields() -> None:
    email = parse_email(load_fixture("02_display_name_spoof.eml"))
    assert email.from_ is not None
    assert email.from_.display_name == "PayPal Support"
    assert email.from_.domain == "random-mailer.xyz"
    assert (
        email.return_path is not None and email.return_path.address == "service@random-mailer.xyz"
    )
    assert email.date is not None and email.date.tzinfo is not None
    assert email.message_id == "<a1@random-mailer.xyz>"


def test_rfc2047_subject_and_charsets() -> None:
    raw = (
        b"From: =?utf-8?b?SsO8cmdlbg==?= <j@example.com>\r\n"
        b"Subject: =?iso-8859-1?q?Caf=E9_menu?=\r\n"
        b"Content-Type: text/plain; charset=iso-8859-1\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        b"Caf=E9 au lait\r\n"
    )
    email = parse_email(raw)
    assert email.from_ is not None and email.from_.display_name == "Jürgen"
    assert email.subject == "Café menu"
    assert "Café au lait" in email.text_body


def test_html_and_text_bodies_and_attachment() -> None:
    email = parse_email(load_fixture("08_macro_doc.eml"))
    assert "Notes from today" in email.text_body
    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.filename == "meeting-notes.docm"
    assert att.size == len(att.data) > 0
    assert email.mime_tree is not None and email.mime_tree.content_type == "multipart/mixed"


def test_alternative_bodies() -> None:
    email = parse_email(load_fixture("01_legit.eml"))
    assert email.text_body and email.html_body
    assert "<a href" in email.html_body


def test_nested_rfc822_attachment_is_surfaced() -> None:
    inner = EmailMessage()
    inner["Subject"] = "inner"
    inner.set_content("inner body")
    inner.add_attachment(b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="a.pdf")
    outer = EmailMessage()
    outer["From"] = "a@example.com"
    outer.set_content("see attached")
    outer.add_attachment(inner)
    email = parse_email(outer.as_bytes())
    names = {(a.filename, a.nested_in) for a in email.attachments}
    assert any(a.content_type == "message/rfc822" for a in email.attachments)
    assert ("a.pdf", "inner") in names
    assert "inner body" not in email.text_body  # forwarded body is not the message's own body


def test_malformed_input_never_raises() -> None:
    email = parse_email(load_fixture("09_malformed.eml"))
    assert email.parse_warnings
    assert email.text_body == "Hello world"
    for junk in (b"", b"\x00\x01\x02", b"not an email at all", b"From: \xff\xfe\r\n\r\n\xff"):
        result = parse_email(junk)
        assert result.parse_warnings is not None  # reached without an exception


def test_deeply_nested_multipart_is_bounded() -> None:
    raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
    body = b"--b\r\n" + raw * 1 + b"--b--\r\n"
    assert parse_email(body * 5) is not None
