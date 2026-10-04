import type { Settings } from "./types";

export const DEFAULT_SETTINGS: Settings = {
  backendUrl: "http://127.0.0.1:8000",
  apiToken: "",
  enrich: true,
  gmailAutoScan: true,
};

/** Settings live in chrome.storage.local: per-install, never synced to the user's Google account. */
export async function loadSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(stored["settings"] as Partial<Settings> | undefined) };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await chrome.storage.local.set({ settings });
}
