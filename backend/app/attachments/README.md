# attachments/

## 1. Purpose
Statically inspects each attachment: computes hashes, works out the real file type from its bytes, flags disguises and risky types, and scans Office files for VBA macros. Nothing is ever executed or opened by an application.

## 2. Where it fits
Called by `app/pipeline.py` (in a worker thread, because `olevba` is CPU-bound). Its hashes feed `enrichment/` (VirusTotal hash lookups) and `ioc.py`; its flags become signals for `scoring/`.

## 3. Concepts you need to know
- **Magic bytes.** Most formats start with a signature: `MZ` = Windows executable, `%PDF-` = PDF, `PK\x03\x04` = ZIP. The *filename* is attacker-controlled; the bytes are what an operating system or application will act on.
- **OOXML** (`.docx/.xlsx/.pptx/.docm`) is a ZIP of XML files; a macro lives in `word/vbaProject.bin`. **Legacy Office** (`.doc/.xls`) is an OLE compound file.
- **Double extension**: `invoice.pdf.exe`. Windows hides known extensions by default, so users see `invoice.pdf`. A right-to-left override character (U+202E) can reverse how a name is *displayed*.
- **VBA macros and auto-exec**: macros run code inside Office. `AutoOpen`, `Document_Open`, `Workbook_Open` run automatically on open - the classic malware downloader trigger.
- **Password-protected archives** stop antivirus from looking inside; attackers put the password in the email body.
- **Hashes**: MD5/SHA-1/SHA-256 identify a file exactly; threat-intel services are queried by hash so the file never has to be uploaded.
- **EICAR**: a 68-byte harmless text string that every antivirus intentionally flags. It lets us test the "known malicious hash" path without handling malware. Its SHA-256 is `275a021b...fd0f`. The repo never stores the file (antivirus would quarantine it); tests build it in memory.

## 4. File-by-file walkthrough
- `filetypes.py` - `detect_type(data)` returns `(label, mime)` via an internal signature table, refining ZIP (docx/xlsx/pptx/jar/apk) and OLE (doc/xls/ppt/encrypted) and sniffing text/html/script; `python-magic` is only a fallback for unknown content. Also holds `EXT_TO_TYPES`, `RISKY_EXTENSIONS`, `DOCUMENT_EXTENSIONS`.
- `analyze.py` - `analyze_attachment` computes hashes, flags (`double_extension`, `executable`, `type_mismatch`, `password_protected`, `rtl_override`, `html_attachment`, `macros`, `macro_autoexec`); `scan_macros` runs `olevba.VBA_Parser(filename, data=bytes)`; `analyze_attachments` returns findings + signals.

## 5. Design decisions and why
- **Decision:** Own signature table first, `python-magic` second.
  **Why:** `libmagic` is a native library absent on Windows; results must not depend on the host OS.
  **Alternatives considered:** `python-magic` only; `filetype` package.
  **Trade-off:** We maintain a short table; unusual types show as `unknown`.
- **Decision:** Pass bytes to `olevba` instead of writing temp files.
  **Why:** Satisfies "never write attachments to disk" completely; no cleanup to forget.
  **Alternatives considered:** `TemporaryDirectory` (works, but needless disk exposure).
  **Trade-off:** Skips files over 15 MB.
- **Decision:** Judge extension mismatch only when the content type is positively known.
  **Why:** Plain text has no signature, so "unknown" must not be called suspicious.
  **Alternatives considered:** Flag all unknowns.
  **Trade-off:** Some disguised text-based scripts rely on the extension/`executable` rules.
- **Decision:** Password-protection detected from headers only (ZIP flag bit, OLE `EncryptedPackage`, PDF `/Encrypt`).
  **Why:** Never attempt to decrypt or extract (zip-bomb safe).
  **Alternatives considered:** Try common passwords.
  **Trade-off:** RAR/7z encryption is not detected.

## 6. Edge cases and limitations
- No sandbox/detonation: macros are *detected*, not run. Obfuscated or encrypted macros may need deeper analysis than `olevba` heuristics give.
- Not inspected: PDF JavaScript, RTF exploits, OneNote, ISO/IMG contents, nested archives.
- `.docm` renamed to `.docx` still reports macros because detection is content-based.

## 7. How to test it
`backend/tests/test_attachments.py`
```
cd backend && python -m pytest tests/test_attachments.py -q
```
The macro fixture is built by `tests/fixtures/build_office.py` (a minimal OLE writer; the only macro is a `MsgBox`).

## 8. Further reading
Microsoft MS-OVBA (VBA storage) and MS-CFB (compound files), oletools docs (decalage.info), ZIP APPNOTE (general purpose bit flag), EICAR (eicar.org).
