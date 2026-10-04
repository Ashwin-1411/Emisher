// Mirrors backend/app/models/report.py. Keep in sync by hand: only fields the UI reads are listed.

export type Verdict = "SAFE" | "SUSPICIOUS" | "PHISHING";

export interface Reason { rule_id: string; weight: number; text: string }
export interface FiredRule { rule_id: string; category: string; weight: number; description: string; count: number; details: string[] }
export interface IOC { type: string; value: string; defanged: string; context: string }

export interface AuthMethodResult { method: string; result: string; properties: Record<string, string>; comment: string }
export interface Alignment { from_domain: string; authenticated_domain: string; relaxed: boolean; strict: boolean }
export interface AuthReport {
  from_domain: string;
  explanation: string[];
  spf_alignment: Alignment | null;
  dkim_alignment: Alignment[];
  delivery: { header_found: boolean; authserv_id: string; trusted: boolean; results: AuthMethodResult[]; note: string };
  live: {
    performed: boolean; skipped_reason: string; connecting_ip: string; spf_result: string;
    dkim_results: { domain: string; selector: string; result: string }[];
    dmarc_record: string; dmarc_policy: string; dmarc_result: string; disagreements: string[];
  };
}

export interface Hop {
  index: number; from_host: string; from_ip: string; by_host: string; protocol: string;
  timestamp: string | null; delay_seconds: number | null; trusted: boolean; flags: string[]; asn: string; country: string;
}
export interface HopReport { hops: Hop[]; connecting_ip: string; originating_ip: string; originating_ip_trusted: boolean; receiving_host: string }

export interface UrlFinding {
  url: string; defanged: string; domain: string; source: string; display_text: string;
  text_mismatch: boolean; unwrapped_from: string[]; expanded_from: string; is_shortener: boolean; flags: string[];
}
export interface MacroInfo { has_macros: boolean; autoexec: string[]; suspicious: string[] }
export interface AttachmentFinding {
  filename: string; content_type: string; size: number; md5: string; sha1: string; sha256: string;
  detected_type: string; flags: string[]; macro: MacroInfo; nested_in: string | null;
}
export interface VtResult { kind: string; target: string; malicious: number; suspicious: number; harmless: number; undetected: number; found: boolean; permalink: string }
export interface UrlscanResult { url: string; status: string; malicious: boolean; score: number; final_url: string; screenshot_url: string; result_url: string; detail: string }

export interface Report {
  id: string;
  created_at: string;
  verdict: Verdict;
  score: number;
  reasons: Reason[];
  fired_rules: FiredRule[];
  overrides_applied: string[];
  email: { subject: string; from_display: string; from_address: string; date: string | null; message_id: string; attachment_count: number };
  auth: AuthReport;
  hops: HopReport;
  urls: UrlFinding[];
  attachments: AttachmentFinding[];
  heuristics: { lookalikes: Record<string, string>[]; language_matches: string[] };
  enrichment: { enabled: boolean; sources: Record<string, string>; virustotal: VtResult[]; urlscan: UrlscanResult[] };
  iocs: IOC[];
  warnings: string[];
  parse_warnings: string[];
}

export interface SubmitResponse { sha256: string; submitted: boolean; analysis_id: string; permalink: string; message: string }

export interface Settings {
  backendUrl: string;
  apiToken: string;
  enrich: boolean;
  gmailAutoScan: boolean;
}

// ---- messages between popup / content script and the background worker
export type BgRequest =
  | { type: "analyze"; rawB64: string; cacheKey?: string }
  | { type: "submitAttachment"; sha256: string; rawB64: string; consent: boolean }
  | { type: "testConnection"; backendUrl: string };

export type BgResponse<T> = { ok: true; data: T } | { ok: false; error: string };
