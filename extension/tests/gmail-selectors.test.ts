import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64 } from "../src/shared/api";
import { toCsv } from "../src/shared/dom";
import {
  accountIndex,
  buildOriginalUrl,
  findIk,
  messageIdFrom,
  parseOriginalResponse,
} from "../src/content/gmail-selectors";

describe("gmail-selectors", () => {
  it("reads the account slot from the path", () => {
    expect(accountIndex("/mail/u/3/")).toBe(3);
    expect(accountIndex("/")).toBe(0);
  });

  it("extracts a decimal message id from either attribute", () => {
    const a = document.createElement("div");
    a.setAttribute("data-message-id", "#msg-f:1785203334578115678");
    expect(messageIdFrom(a)).toBe("1785203334578115678");
    const b = document.createElement("div");
    b.setAttribute("data-legacy-message-id", "ff");
    expect(messageIdFrom(b)).toBe("255");
    expect(messageIdFrom(document.createElement("div"))).toBeNull();
  });

  it("builds the Show-original URL, with and without ik", () => {
    const base = { origin: "https://mail.google.com", account: 1, messageId: "123" };
    expect(buildOriginalUrl({ ...base, ik: "abcdef1234" })).toBe(
      "https://mail.google.com/mail/u/1/?ik=abcdef1234&view=om&permmsgid=msg-f%3A123",
    );
    expect(buildOriginalUrl({ ...base, ik: null })).toContain("view=om");
  });

  it("finds ik in inline scripts", () => {
    document.body.innerHTML = "";
    const s = document.createElement("script");
    s.textContent = 'var x = {"ik":"0123456789ab"};';
    document.body.append(s);
    expect(findIk(document)).toBe("0123456789ab");
  });

  it("parses plain and HTML-wrapped originals", () => {
    const raw = "Delivered-To: a@b.c\nReceived: from x\n\nbody";
    expect(parseOriginalResponse(raw, "text/plain")).toBe(raw);
    const html = `<html><body><pre id="raw_message_text">${raw}</pre></body></html>`;
    expect(parseOriginalResponse(html, "text/html")).toBe(raw);
    expect(parseOriginalResponse("<html>login</html>", "text/html")).toBeNull();
  });
});

describe("shared helpers", () => {
  it("round-trips bytes through base64, including large buffers", () => {
    const bytes = new Uint8Array(100_000).map((_, i) => i % 251);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it("neutralises CSV formula injection", () => {
    expect(toCsv([["=1+1", 'a"b']])).toBe(`"'=1+1","a""b"`);
  });
});
