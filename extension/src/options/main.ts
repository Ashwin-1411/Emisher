import { send } from "../shared/messaging";
import { loadSettings, saveSettings } from "../shared/storage";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const url = $<HTMLInputElement>("url");
const token = $<HTMLInputElement>("token");
const enrich = $<HTMLInputElement>("enrich");
const auto = $<HTMLInputElement>("auto");
const msg = $("msg");

function say(text: string, bad = false): void {
  msg.textContent = text;
  msg.style.color = bad ? "#cf222e" : "inherit";
}

void loadSettings().then((s) => {
  url.value = s.backendUrl;
  token.value = s.apiToken;
  enrich.checked = s.enrich;
  auto.checked = s.gmailAutoScan;
});

/** Ask for access to the backend's origin only (optional_host_permissions), so the extension
 *  holds no broad network permission by default. localhost is already granted in the manifest. */
async function ensureHostPermission(backendUrl: string): Promise<boolean> {
  let origin: string;
  try {
    origin = new URL(backendUrl).origin + "/*";
  } catch {
    say("That is not a valid URL.", true);
    return false;
  }
  if (await chrome.permissions.contains({ origins: [origin] })) return true;
  const granted = await chrome.permissions.request({ origins: [origin] });
  if (!granted) say("Permission to contact that backend was not granted.", true);
  return granted;
}

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const backendUrl = url.value.trim().replace(/\/+$/, "");
  if (!(await ensureHostPermission(backendUrl))) return;
  await saveSettings({ backendUrl, apiToken: token.value.trim(), enrich: enrich.checked, gmailAutoScan: auto.checked });
  say("Saved.");
});

$("test").addEventListener("click", async () => {
  const backendUrl = url.value.trim();
  if (!(await ensureHostPermission(backendUrl))) return;
  try {
    say(await send<string>({ type: "testConnection", backendUrl }));
  } catch (err) {
    say((err as Error).message, true);
  }
});
