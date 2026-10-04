// ============================================================================================
// EVERYTHING that depends on Gmail's undocumented internals lives in this one file.
// Gmail changes its DOM and internal URLs without notice. When the banner stops appearing:
//   1. Open a message in Gmail, right-click the message area -> Inspect.
//   2. Check each selector/attribute below against the live DOM and fix it here.
//   3. Open "Show original" from the message's ⋮ menu and compare the URL in the new tab with
//      buildOriginalUrl(); update that function if the query parameters changed.
//   4. Run `npm test` (tests/gmail-selectors.test.ts) and rebuild.
//
// STATUS: these values reflect the Gmail web client as widely documented at the time of writing
// but could NOT be verified against a live account while building this project. Treat step 1-3
// as a required first-run check.
// ============================================================================================

export const SELECTORS = {
  /** One expanded message inside a conversation. Carries the message-id attributes below. */
  messageContainer: "div.adn[data-message-id]",
  /** The block holding the rendered body; the banner is inserted before it. */
  messageBody: "div.ii.gt",
} as const;

export const ATTRS = {
  /** Decimal id, usually prefixed: "#msg-f:1785203334578115678". */
  messageId: "data-message-id",
  /** Same id in hex: "18c2a4b3e4f5a6b7". Used when the decimal attribute is missing. */
  legacyMessageId: "data-legacy-message-id",
} as const;

/** `/mail/u/2/` -> 2 (the signed-in account slot). Defaults to 0. */
export function accountIndex(pathname: string): number {
  const m = /\/mail\/u\/(\d+)/.exec(pathname);
  return m ? Number(m[1]) : 0;
}

/** Decimal message id for a message container element, or null if neither attribute is present. */
export function messageIdFrom(el: Element): string | null {
  const dec = el.getAttribute(ATTRS.messageId);
  if (dec) {
    const m = /(\d{6,})/.exec(dec);
    if (m?.[1]) return m[1];
  }
  const hex = el.getAttribute(ATTRS.legacyMessageId);
  if (hex && /^[0-9a-f]+$/i.test(hex)) return BigInt("0x" + hex).toString();
  return null;
}

/** Gmail's per-account "ik" token, scraped from inline scripts. Returns null if not found. */
export function findIk(doc: Document): string | null {
  for (const script of Array.from(doc.scripts)) {
    const text = script.textContent ?? "";
    if (!text.includes("ik")) continue;
    const m = /["']?(?:GM_ID_KEY|ik)["']?\s*[:=]\s*["']([0-9a-f]{8,})["']/i.exec(text);
    if (m?.[1]) return m[1];
  }
  return null;
}

/** URL of Gmail's "Show original" page for a message (same-origin, uses the session cookie). */
export function buildOriginalUrl(opts: { origin: string; account: number; messageId: string; ik: string | null }): string {
  const q = new URLSearchParams();
  if (opts.ik) q.set("ik", opts.ik);
  q.set("view", "om");
  q.set("permmsgid", `msg-f:${opts.messageId}`);
  return `${opts.origin}/mail/u/${opts.account}/?${q.toString()}`;
}

const RAW_START = /^(?:Delivered-To|Received|Return-Path|X-[\w-]+|From|ARC-[\w-]+|Authentication-Results|MIME-Version|Date|Message-ID):/im;

/**
 * Turn the "Show original" response into raw RFC 5322 text.
 * Handles both a plain-text response and an HTML page wrapping the message in a <pre>.
 */
export function parseOriginalResponse(body: string, contentType: string): string | null {
  if (!contentType.includes("html") && RAW_START.test(body.slice(0, 2000))) return body;
  const doc = new DOMParser().parseFromString(body, "text/html");
  const pre = doc.querySelector("pre#raw_message_text, pre.raw_message_text, pre");
  const text = pre?.textContent ?? "";
  return RAW_START.test(text.slice(0, 2000)) ? text : null;
}
