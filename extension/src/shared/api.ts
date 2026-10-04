import type { Report, Settings, SubmitResponse } from "./types";

const ANALYZE_TIMEOUT_MS = 90_000; // urlscan polling can take ~30 s on the backend

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000; // avoid call-stack limits of String.fromCharCode(...bigArray)
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export class ApiError extends Error {}

function baseUrl(settings: Pick<Settings, "backendUrl">): string {
  return settings.backendUrl.replace(/\/+$/, "");
}

async function call(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...init, signal: controller.signal });
    if (!resp.ok) {
      let detail = resp.statusText;
      try {
        detail = ((await resp.json()) as { detail?: string }).detail ?? detail;
      } catch {
        /* body was not JSON */
      }
      throw new ApiError(`Backend error ${resp.status}: ${detail}`);
    }
    return resp;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if ((err as Error).name === "AbortError") throw new ApiError("The backend took too long to respond");
    throw new ApiError("Could not reach the backend. Check the URL in the extension options and that it is running.");
  } finally {
    clearTimeout(timer);
  }
}

export async function analyze(settings: Settings, raw: Uint8Array): Promise<Report> {
  const resp = await call(
    `${baseUrl(settings)}/api/v1/analyze?enrich=${settings.enrich}`,
    { method: "POST", headers: { "X-API-Token": settings.apiToken, "Content-Type": "message/rfc822" }, body: new Blob([raw as BlobPart]) },
    ANALYZE_TIMEOUT_MS,
  );
  return (await resp.json()) as Report;
}

/** Upload ONE attachment to VirusTotal. The caller must have obtained explicit user consent. */
export async function submitAttachment(settings: Settings, sha256: string, raw: Uint8Array): Promise<SubmitResponse> {
  const form = new FormData();
  form.append("consent", "true");
  form.append("file", new Blob([raw as BlobPart], { type: "message/rfc822" }), "message.eml");
  const resp = await call(
    `${baseUrl(settings)}/api/v1/attachments/${sha256}/submit`,
    { method: "POST", headers: { "X-API-Token": settings.apiToken }, body: form },
    60_000,
  );
  return (await resp.json()) as SubmitResponse;
}

export async function testConnection(backendUrl: string): Promise<string> {
  const resp = await call(`${baseUrl({ backendUrl })}/health`, { method: "GET" }, 8000);
  const body = (await resp.json()) as { status?: string };
  return body.status === "ok" ? "Backend reachable" : "Unexpected response from backend";
}
