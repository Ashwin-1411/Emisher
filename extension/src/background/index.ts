// Service worker: the ONLY place that talks to the backend. Popup and content script send it
// messages, so the API token never has to be read by a page-injected script.
import { analyze, base64ToBytes, submitAttachment, testConnection } from "../shared/api";
import { loadSettings } from "../shared/storage";
import type { BgRequest, BgResponse, Report } from "../shared/types";

const CACHE_PREFIX = "report:";
const CACHE_MAX = 50;

/** Per-message cache in chrome.storage.session: survives service-worker restarts, is wiped when
 *  the browser closes, and is never written to disk. Holds reports, not email content. */
async function cacheGet(key: string): Promise<Report | undefined> {
  const found = await chrome.storage.session.get(CACHE_PREFIX + key);
  return found[CACHE_PREFIX + key] as Report | undefined;
}

async function cacheSet(key: string, report: Report): Promise<void> {
  await chrome.storage.session.set({ [CACHE_PREFIX + key]: report });
  const all = await chrome.storage.session.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith(CACHE_PREFIX));
  if (keys.length > CACHE_MAX) {
    // Report ids are random, so evict by created_at to drop the oldest.
    const sorted = keys.sort((a, b) => String((all[a] as Report).created_at).localeCompare(String((all[b] as Report).created_at)));
    await chrome.storage.session.remove(sorted.slice(0, keys.length - CACHE_MAX));
  }
}

async function handle(msg: BgRequest): Promise<unknown> {
  if (msg.type === "testConnection") return testConnection(msg.backendUrl);

  const settings = await loadSettings();
  if (!settings.apiToken) throw new Error("No API token set. Open the extension options to configure the backend.");

  if (msg.type === "analyze") {
    if (msg.cacheKey) {
      const hit = await cacheGet(msg.cacheKey);
      if (hit) return hit;
    }
    const report = await analyze(settings, base64ToBytes(msg.rawB64));
    if (msg.cacheKey) await cacheSet(msg.cacheKey, report);
    return report;
  }
  if (msg.type === "submitAttachment") {
    if (!msg.consent) throw new Error("Consent is required to upload a file to VirusTotal");
    return submitAttachment(settings, msg.sha256, base64ToBytes(msg.rawB64));
  }
  throw new Error("Unknown message");
}

chrome.runtime.onMessage.addListener((msg: BgRequest, _sender, sendResponse: (r: BgResponse<unknown>) => void) => {
  handle(msg).then(
    (data) => sendResponse({ ok: true, data }),
    (err: Error) => sendResponse({ ok: false, error: err.message }),
  );
  return true; // keep the channel open for the async response
});
