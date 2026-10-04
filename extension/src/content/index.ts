// Gmail content script: when a message is opened, fetch its raw source through the user's own
// Gmail session, ask the background worker to analyze it, and show a banner above the body.
import { bytesToBase64 } from "../shared/api";
import { send } from "../shared/messaging";
import { DEFAULT_SETTINGS } from "../shared/storage";
import type { Report, Settings } from "../shared/types";
import { errorBanner, loadingBanner, reportBanner } from "./banner";
import { SELECTORS, accountIndex, buildOriginalUrl, findIk, messageIdFrom, parseOriginalResponse } from "./gmail-selectors";

const DONE = "data-pea-done";
const FALLBACK_HINT = "Use ⋮ → Download message in Gmail and drop the .eml into the extension popup instead.";

async function autoScanEnabled(): Promise<boolean> {
  const stored = await chrome.storage.local.get("settings");
  const settings = { ...DEFAULT_SETTINGS, ...(stored["settings"] as Partial<Settings> | undefined) };
  return settings.gmailAutoScan;
}

async function fetchRawSource(messageId: string): Promise<Uint8Array> {
  const url = buildOriginalUrl({
    origin: location.origin,
    account: accountIndex(location.pathname),
    messageId,
    ik: findIk(document),
  });
  const resp = await fetch(url, { credentials: "include" });
  if (!resp.ok) throw new Error(`Gmail returned ${resp.status} for "Show original". The URL format may have changed.`);
  const text = parseOriginalResponse(await resp.text(), resp.headers.get("content-type") ?? "");
  if (!text) throw new Error("Could not read the message source from Gmail's response. The page format may have changed.");
  // Gmail shows LF line endings; the analyzer's parser is lenient, but DKIM needs CRLF.
  return new TextEncoder().encode(text.replace(/\r?\n/g, "\r\n"));
}

async function process(container: Element): Promise<void> {
  const body = container.querySelector(SELECTORS.messageBody);
  const messageId = messageIdFrom(container);
  if (!body || !messageId || container.hasAttribute(DONE)) return;
  container.setAttribute(DONE, "1");

  let banner = loadingBanner();
  body.parentElement?.insertBefore(banner, body);
  const replace = (next: HTMLElement) => {
    banner.replaceWith(next);
    banner = next;
  };
  try {
    const raw = await fetchRawSource(messageId);
    const report = await send<Report>({ type: "analyze", rawB64: bytesToBase64(raw), cacheKey: `gmail:${messageId}` });
    replace(reportBanner(report));
  } catch (err) {
    replace(errorBanner(`${(err as Error).message} ${FALLBACK_HINT}`));
  }
}

let scheduled = false;
function scan(): void {
  if (scheduled) return;
  scheduled = true;
  // Gmail mutates the DOM constantly; debounce so we look once per burst.
  setTimeout(async () => {
    scheduled = false;
    if (!(await autoScanEnabled())) return;
    document.querySelectorAll(SELECTORS.messageContainer).forEach((el) => void process(el));
  }, 400);
}

new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
scan();
