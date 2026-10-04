# Email structure and authentication primer

A standalone introduction for students. Everything here is used by the analyzer; the code is linked at the end of each section.

## 1. Anatomy of an email (RFC 5322)

An email is text: header lines, a blank line, then the body.

```
Return-Path: <bounce@mailer.example.com>          <- envelope sender ("MAIL FROM"), added at delivery
Received: from mail.example.com ([93.184.216.34]) by mx.example.org; Tue, 05 Mar 2024 10:00:05 +0000
From: "Example Billing" <billing@example.com>      <- what the reader sees
To: student@example.org
Subject: Your statement
Date: Tue, 05 Mar 2024 10:00:00 +0000
Message-ID: <abc123@example.com>
```

Two different "senders" exist:
- **Envelope sender** (`MAIL FROM` in the SMTP conversation, saved as `Return-Path`): where bounces go. Checked by SPF.
- **Header From** (`From:`): what the user sees. Nothing in basic SMTP stops anyone from writing any value here - this is why spoofing is easy and why DMARC exists.

## 2. MIME: multiple parts (RFC 2045-2049)

```
Content-Type: multipart/mixed; boundary="b1"
--b1
Content-Type: multipart/alternative; boundary="b2"
--b2
Content-Type: text/plain; charset=utf-8
...
--b2
Content-Type: text/html; charset=utf-8
...
--b2--
--b1
Content-Type: application/pdf; name="invoice.pdf"
Content-Transfer-Encoding: base64
JVBERi0xLjQK...
--b1--
```
- `Content-Transfer-Encoding` (base64, quoted-printable) lets binary or non-ASCII data survive text-only mail systems.
- Non-ASCII in headers uses RFC 2047 "encoded words": `=?utf-8?B?SsO8cmdlbg==?=` = "Jürgen".
- Phishers abuse this: the `text/plain` part can say one thing and the `text/html` another, and HTML link text can differ from its `href`.

## 3. The Received chain

Each server **prepends** a `Received:` header, so you read them **bottom-up** (oldest first):

```
Received: from relay.example.net (relay.example.net [151.101.1.69])    # 3. newest - added by YOUR provider
    by mx.example.org with ESMTPS; Wed, 06 Mar 2024 09:15:12 +0000
Received: from mail-yw1.google.com (mail-yw1.google.com [209.85.128.169])  # 2.
    by relay.example.net with ESMTPS; Wed, 06 Mar 2024 11:40:00 +0000      # <- later than #3?! impossible
Received: from [192.168.1.20] (unknown [192.168.1.20])                  # 1. oldest - claimed by the sender
    by mail-yw1.google.com with SMTP; Wed, 06 Mar 2024 09:14:50 +0000
```
Only the top entries (written by systems you trust) are reliable. Lines below can be pre-planted by the sender. Look for: timestamps going backwards, private addresses after a public hop, a hop that names a big provider but is not consistent with the rest. Fixture `10_forged_received.eml` shows this. (Code: `backend/app/hops`.)

## 4. SPF - "is this IP allowed to send for this domain?" (RFC 7208)

The domain publishes a list in DNS:
```
example.com.  IN TXT "v=spf1 ip4:93.184.216.34 include:_spf.google.com -all"
```
The receiving server takes the **connecting IP** and the **envelope domain** and evaluates the list. Results: `pass`, `fail` (`-all`), `softfail` (`~all`), `neutral`, `none`, `temperror`, `permerror`. SPF says nothing about the visible `From` and breaks when mail is forwarded.

## 5. DKIM - "was this message signed by the domain?" (RFC 6376)

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1;
    h=from:to:subject:date; bh=<hash of body>; b=<signature over the listed headers>
```
The sending server signs the listed headers and a hash of the body with a private key. A verifier fetches the public key from DNS:
```
sel1._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkq..."
```
`d=` is the domain taking responsibility; `s=` selects the key. Change one signed header or the body and verification fails. A signature by *any* domain can verify - the attacker can sign with their own `d=evil.com`.

## 6. DMARC - tying it to the visible From (RFC 7489)

```
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:reports@example.com"
```
DMARC passes if **(SPF passes AND the SPF domain aligns with From)** OR **(DKIM passes AND `d=` aligns with From)**.

Alignment:
| Mode | Rule | `From: example.com` aligns with |
|---|---|---|
| relaxed (default) | same organisational domain | `example.com`, `mail.example.com` |
| strict | identical | `example.com` only |

Policy `p=` tells receivers what to do on failure: `none` (monitor), `quarantine`, `reject`.

**Worked example (fixture 04):**
```
Return-Path: <bounce@spammer-bulk.net>        SPF: pass for spammer-bulk.net (their own list allows their own IP)
From: billing@example.com                      example.com != spammer-bulk.net  -> not aligned
DKIM: none
=> dmarc=fail (p=reject)
```
SPF passed, yet the mail is a forgery of `example.com` - precisely what alignment catches.

## 7. Authentication-Results (RFC 8601)

The receiving provider records its verdicts:
```
Authentication-Results: mx.google.com;
   dkim=pass header.i=@example.com header.s=sel1;
   spf=pass (google.com: domain of billing@example.com designates 93.184.216.34 as permitted sender) smtp.mailfrom=billing@example.com;
   dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
```
It is the best evidence because it reflects DNS **at delivery time**. But anyone can add a header with this name, so only the one whose first token (`mx.google.com`, the *authserv-id*) matches the server that accepted the mail is trusted. Re-checking later against live DNS can disagree legitimately (keys rotated, records edited, domain expired); the analyzer labels such differences instead of treating them as proof. (Code: `backend/app/auth_checks`.)

## 8. What authentication does NOT tell you

- A passing message can still be phishing: attackers register their own domain, set up SPF/DKIM/DMARC correctly and send from `micros0ft-support.com`. That is why lookalike detection exists.
- A compromised real account passes everything.
- Forwarding and mailing lists can break SPF/DKIM for honest mail (ARC, RFC 8617, was designed to help).

## Exercises

1. Run the analyzer on `04_dmarc_alignment_fail.eml` and find the alignment table in the Authentication tab.
2. Change one word in the body of `01_legit.eml` and re-run with `enrich=true`; watch live DKIM fail while the delivery-time header still says pass.
3. In `10_forged_received.eml`, which hop is the forged one and how do you know?
