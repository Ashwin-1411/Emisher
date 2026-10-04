"""Generate the synthetic .eml fixtures and the fake DNS zone used by the tests.

Run from ``backend/``::

    python tests/fixtures/build_fixtures.py

Everything here is invented: reserved or made-up domains, documentation-style text, a
throw-away DKIM key (regenerated on each run, so ``zone.json`` and ``01_legit.eml`` are always
consistent with each other), a stub "executable" that is just the bytes ``MZ`` plus zeros, and
a macro that only shows a message box. No real malware or phishing kit is involved.

The headers (Received, Authentication-Results) are written by hand because that is exactly
the data the analyzer reads; a real mail server would add them in the same positions.
"""

from __future__ import annotations

import base64
import json
from email import policy
from email.message import EmailMessage
from pathlib import Path

import dkim
from build_office import build_docm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).parent
RECIPIENT = "student@example.org"
RECEIVER = "mx.example.org"  # the "final receiving provider" in every fixture


def new_message(headers: list[tuple[str, str]]) -> EmailMessage:
    """Create a message whose headers appear in exactly the given top-to-bottom order."""
    msg = EmailMessage(policy=policy.SMTP)
    for name, value in headers:
        msg[name] = value  # EmailMessage appends, so repeated headers (Received) keep order
    return msg


def received(
    from_host: str, from_ip: str, by: str, when: str, proto: str = "ESMTPS"
) -> tuple[str, str]:
    return (
        "Received",
        f"from {from_host} ({from_host} [{from_ip}]) by {by} with {proto} id 4TfX{abs(hash(when)) % 9999}; {when}",
    )


def auth_results(
    spf: str, dkim_res: str, dmarc: str, mailfrom: str, header_d: str, header_from: str
) -> tuple[str, str]:
    """Authentication-Results as the receiving provider would stamp it."""
    parts = [RECEIVER]
    parts.append(f"spf={spf} smtp.mailfrom={mailfrom}")
    parts.append(f"dkim={dkim_res} header.d={header_d}" if header_d else f"dkim={dkim_res}")
    parts.append(f"dmarc={dmarc} header.from={header_from}")
    return ("Authentication-Results", "; ".join(parts))


def write(name: str, data: bytes) -> None:
    (HERE / name).write_bytes(data)


def build() -> None:
    zone: dict[str, dict[str, list[str]]] = {"TXT": {}, "A": {}, "MX": {}}

    # ---- DKIM key for example.com ---------------------------------------------------------
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    zone["TXT"]["test._domainkey.example.com"] = [
        "v=DKIM1; k=rsa; p=" + base64.b64encode(pub_der).decode()
    ]
    zone["TXT"]["example.com"] = ["v=spf1 ip4:93.184.216.34 -all"]
    zone["TXT"]["_dmarc.example.com"] = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
    zone["TXT"]["spammer-bulk.net"] = ["v=spf1 ip4:45.33.32.156 -all"]
    zone["TXT"]["random-mailer.xyz"] = ["v=spf1 ip4:45.33.32.156 -all"]
    zone["TXT"]["_dmarc.random-mailer.xyz"] = ["v=DMARC1; p=none"]

    # ---- 01 legitimate: everything passes and aligns --------------------------------------
    msg = new_message(
        [
            auth_results(
                "pass", "pass", "pass", "billing@example.com", "example.com", "example.com"
            ),
            received(
                "mail.example.com", "93.184.216.34", RECEIVER, "Tue, 05 Mar 2024 10:00:05 +0000"
            ),
            received(
                "app01.internal.example.com",
                "10.0.0.5",
                "mail.example.com",
                "Tue, 05 Mar 2024 10:00:03 +0000",
                "ESMTP",
            ),
            ("Return-Path", "<billing@example.com>"),
            ("From", "Example Billing <billing@example.com>"),
            ("To", RECIPIENT),
            ("Subject", "Your March statement is ready"),
            ("Date", "Tue, 05 Mar 2024 10:00:00 +0000"),
            ("Message-ID", "<stmt-0305@example.com>"),
        ]
    )
    msg.set_content(
        "Hello,\n\nYour March statement is available at https://www.example.com/statements/2024-03\n"
    )
    msg.add_alternative(
        "<p>Hello,</p><p>Your March statement is available: "
        '<a href="https://www.example.com/statements/2024-03">https://www.example.com/statements/2024-03</a></p>',
        subtype="html",
    )
    raw = msg.as_bytes()
    signature = dkim.sign(
        raw,
        b"test",
        b"example.com",
        pem,
        include_headers=[
            b"From",
            b"To",
            b"Subject",
            b"Date",
            b"Message-ID",
            b"MIME-Version",
            b"Content-Type",
        ],
    )
    write("01_legit.eml", signature + raw)

    # ---- 02 display-name spoof ------------------------------------------------------------
    msg = new_message(
        [
            auth_results(
                "pass", "none", "pass", "service@random-mailer.xyz", "", "random-mailer.xyz"
            ),
            received(
                "smtp.random-mailer.xyz",
                "45.33.32.156",
                RECEIVER,
                "Wed, 06 Mar 2024 08:30:10 +0000",
            ),
            ("Return-Path", "<service@random-mailer.xyz>"),
            ("From", '"PayPal Support" <service@random-mailer.xyz>'),
            ("To", RECIPIENT),
            ("Subject", "Action required: confirm your account"),
            ("Date", "Wed, 06 Mar 2024 08:30:00 +0000"),
            ("Message-ID", "<a1@random-mailer.xyz>"),
        ]
    )
    msg.set_content(
        "Dear customer,\n\nWe noticed unusual activity. Please verify your password immediately "
        "or your account will be suspended within 24 hours.\n"
    )
    write("02_display_name_spoof.eml", msg.as_bytes())

    # ---- 03 lookalike / punycode domain ---------------------------------------------------
    puny = "pаypal.com".encode("idna").decode()  # Cyrillic 'а' (U+0430) in place of Latin 'a'
    msg = new_message(
        [
            auth_results("pass", "none", "none", f"security@{puny}", "", puny),
            received(f"mail.{puny}", "45.33.32.156", RECEIVER, "Wed, 06 Mar 2024 12:00:10 +0000"),
            ("Return-Path", f"<security@{puny}>"),
            ("From", f"Account Security <security@{puny}>"),
            ("To", RECIPIENT),
            ("Subject", "Sign in to review a recent payment"),
            ("Date", "Wed, 06 Mar 2024 12:00:00 +0000"),
            ("Message-ID", f"<b2@{puny}>"),
        ]
    )
    msg.set_content(f"Review the payment here: https://{puny}/signin\n")
    msg.add_alternative(
        f'<p>Review the payment: <a href="https://{puny}/signin">Sign in</a></p>', subtype="html"
    )
    write("03_lookalike_punycode.eml", msg.as_bytes())

    # ---- 04 DMARC alignment failure (SPF passes, but for a different domain) --------------
    msg = new_message(
        [
            auth_results("pass", "none", "fail", "bounce@spammer-bulk.net", "", "example.com"),
            received(
                "bulk1.spammer-bulk.net",
                "45.33.32.156",
                RECEIVER,
                "Thu, 07 Mar 2024 14:00:10 +0000",
            ),
            ("Return-Path", "<bounce@spammer-bulk.net>"),
            ("From", "Example Billing <billing@example.com>"),
            ("To", RECIPIENT),
            ("Subject", "Invoice overdue"),
            ("Date", "Thu, 07 Mar 2024 14:00:00 +0000"),
            ("Message-ID", "<c3@spammer-bulk.net>"),
        ]
    )
    msg.set_content("Your invoice is overdue. See your account at https://www.example.com/pay\n")
    write("04_dmarc_alignment_fail.eml", msg.as_bytes())

    # ---- 05 link text differs from href ---------------------------------------------------
    msg = new_message(
        [
            auth_results("pass", "pass", "pass", "news@example.net", "example.net", "example.net"),
            received(
                "mail.example.net", "151.101.1.69", RECEIVER, "Fri, 08 Mar 2024 09:00:10 +0000"
            ),
            ("From", "Example News <news@example.net>"),
            ("To", RECIPIENT),
            ("Subject", "Please verify your sign-in"),
            ("Date", "Fri, 08 Mar 2024 09:00:00 +0000"),
            ("Message-ID", "<d4@example.net>"),
        ]
    )
    msg.set_content("Verify your sign-in: https://www.example.com/account\n")
    msg.add_alternative(
        '<p>Please <a href="http://login-verify.example.net/session?u=1">https://www.example.com/account</a> '
        "to verify your password.</p>",
        subtype="html",
    )
    write("05_link_text_mismatch.eml", msg.as_bytes())

    # ---- 06 SafeLinks-wrapped URLs ---------------------------------------------------------
    safelink = (
        "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.net%2Fverify%3Fid%3D7"
        "&data=05%7C01%7Cstudent%40example.org%7Cabc&sdata=Zm9v&reserved=0"
    )
    safelink_masked = (
        "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil-login.example.net%2Fo365"
        "&data=05%7C01%7Cstudent%40example.org%7Cabc&sdata=Zm9v&reserved=0"
    )
    msg = new_message(
        [
            auth_results("pass", "pass", "pass", "hr@example.com", "example.com", "example.com"),
            received(
                "mail.example.com", "93.184.216.34", RECEIVER, "Mon, 11 Mar 2024 08:00:10 +0000"
            ),
            ("From", "HR Team <hr@example.com>"),
            ("To", RECIPIENT),
            ("Subject", "Benefits enrolment"),
            ("Date", "Mon, 11 Mar 2024 08:00:00 +0000"),
            ("Message-ID", "<e5@example.com>"),
        ]
    )
    msg.set_content("Enrol here: " + safelink + "\n")
    msg.add_alternative(
        f'<p><a href="{safelink}">Open the benefits portal</a></p>'
        f'<p>Or visit <a href="{safelink_masked}">https://www.example.com/portal</a></p>',
        subtype="html",
    )
    write("06_safelinks.eml", msg.as_bytes())

    # ---- 07 double-extension attachment ----------------------------------------------------
    msg = new_message(
        [
            auth_results("pass", "none", "none", "sales@example.net", "", "example.net"),
            received(
                "mail.example.net", "151.101.1.69", RECEIVER, "Tue, 12 Mar 2024 07:00:10 +0000"
            ),
            ("From", "Sales <sales@example.net>"),
            ("To", RECIPIENT),
            ("Subject", "Invoice attached"),
            ("Date", "Tue, 12 Mar 2024 07:00:00 +0000"),
            ("Message-ID", "<f6@example.net>"),
        ]
    )
    msg.set_content("Please find the invoice attached.\n")
    # Just the DOS 'MZ' magic followed by zeros: it is detected as a PE file but cannot run.
    msg.add_attachment(
        b"MZ" + b"\x00" * 62,
        maintype="application",
        subtype="octet-stream",
        filename="invoice.pdf.exe",
    )
    write("07_double_extension.eml", msg.as_bytes())

    # ---- 08 macro-enabled document ---------------------------------------------------------
    msg = new_message(
        [
            auth_results("pass", "pass", "pass", "pm@example.com", "example.com", "example.com"),
            received(
                "mail.example.com", "93.184.216.34", RECEIVER, "Wed, 13 Mar 2024 15:00:10 +0000"
            ),
            ("From", "Project Office <pm@example.com>"),
            ("To", RECIPIENT),
            ("Subject", "Meeting notes"),
            ("Date", "Wed, 13 Mar 2024 15:00:00 +0000"),
            ("Message-ID", "<g7@example.com>"),
        ]
    )
    msg.set_content("Notes from today's meeting are attached.\n")
    msg.add_attachment(
        build_docm(),
        maintype="application",
        subtype="vnd.ms-word.document.macroEnabled.12",
        filename="meeting-notes.docm",
    )
    write("08_macro_doc.eml", msg.as_bytes())

    # ---- 09 malformed MIME -----------------------------------------------------------------
    broken = (
        "From: Odd Sender <odd@example.net>\r\n"
        "To: student@example.org\r\n"
        "Subject: =?utf-8?B?!!!not-base64!!!?= broken\r\n"
        "Date: not a real date\r\n"
        "this line has no colon so it is a header defect\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n'
        "\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: text/plain; charset=made-up-charset\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "SGVsbG8gd29ybGQ\r\n"
        "--BOUNDARY\r\n"
        'Content-Type: application/octet-stream; name="data.bin"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "@@@@ not base64 @@@@\r\n"
        # note: the closing boundary is deliberately missing
    )
    write("09_malformed.eml", broken.encode())

    # ---- 10 forged Received hops -----------------------------------------------------------
    msg = new_message(
        [
            auth_results("none", "none", "none", "alerts@example.net", "", "example.net"),
            received(
                "relay.example.net", "151.101.1.69", RECEIVER, "Wed, 06 Mar 2024 09:15:12 +0000"
            ),
            # claims to be a Google server but is stamped *after* the hop above it: impossible
            received(
                "mail-yw1-f169.google.com",
                "209.85.128.169",
                "relay.example.net",
                "Wed, 06 Mar 2024 11:40:00 +0000",
            ),
            # a private address at the bottom of the chain, below the trusted boundary
            (
                "Received",
                "from [192.168.1.20] (unknown [192.168.1.20]) by mail-yw1-f169.google.com with SMTP; Wed, 06 Mar 2024 09:14:50 +0000",
            ),
            ("From", "Account Alerts <alerts@example.net>"),
            ("To", RECIPIENT),
            ("Subject", "Your account"),
            ("Date", "Wed, 06 Mar 2024 09:14:00 +0000"),
            ("Message-ID", "<h8@example.net>"),
        ]
    )
    msg.set_content("Your account has a new notice.\n")
    write("10_forged_received.eml", msg.as_bytes())

    (HERE / "zone.json").write_text(json.dumps(zone, indent=2) + "\n")
    print("fixtures written to", HERE)


if __name__ == "__main__":
    build()
