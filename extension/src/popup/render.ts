import { bytesToBase64 } from "../shared/api";
import { VERDICT_LABEL, downloadText, h, toCsv } from "../shared/dom";
import { send } from "../shared/messaging";
import type { Report, SubmitResponse } from "../shared/types";

type Table = { head: string[]; rows: (string | Node)[][] };

function table({ head, rows }: Table): HTMLElement {
  if (rows.length === 0) return h("p", { class: "meta" }, "Nothing to show.");
  return h(
    "table",
    {},
    h("thead", {}, h("tr", {}, ...head.map((t) => h("th", {}, t)))),
    h("tbody", {}, ...rows.map((r) => h("tr", {}, ...r.map((c) => h("td", {}, c))))),
  );
}

const flags = (list: string[]) => h("span", {}, ...list.map((f) => h("span", { class: "flag" }, f.replaceAll("_", " "))));
const code = (text: string) => h("code", {}, text);

function authPanel(r: Report): HTMLElement {
  const a = r.auth;
  const parts: Node[] = [];
  if (a.explanation.length) parts.push(h("ul", {}, ...a.explanation.map((l) => h("li", {}, l))));
  parts.push(
    table({
      head: ["Method", "Result (at delivery)", "Details"],
      rows: a.delivery.results.map((x) => [
        x.method.toUpperCase(),
        x.result,
        Object.entries(x.properties).map(([k, v]) => `${k}=${v}`).join(" "),
      ]),
    }),
  );
  parts.push(h("p", { class: "meta" }, a.delivery.trusted ? `Stamped by ${a.delivery.authserv_id} (trusted).` : a.delivery.note));
  const live = a.live;
  parts.push(
    h("p", { class: "meta" }, live.performed
      ? `Live re-check: SPF ${live.spf_result || "n/a"}; DKIM ${live.dkim_results.map((d) => `${d.domain}:${d.result}`).join(", ") || "none"}; DMARC ${live.dmarc_result || "n/a"}${live.dmarc_policy ? ` (policy ${live.dmarc_policy})` : ""}.`
      : `Live re-check not run: ${live.skipped_reason}`),
  );
  return h("div", {}, ...parts);
}

function hopsPanel(r: Report): HTMLElement {
  const head = h("p", { class: "meta" },
    `Connecting IP: ${r.hops.connecting_ip || "unknown"}. Originating IP: ${r.hops.originating_ip || "unknown"}${r.hops.originating_ip && !r.hops.originating_ip_trusted ? " (unverified claim)" : ""}.`);
  return h("div", {}, head, table({
    head: ["#", "From", "By", "Time / delay", "Flags"],
    rows: r.hops.hops.map((x) => [
      `${x.index}${x.trusted ? " ✓" : ""}`,
      `${x.from_host} ${x.from_ip}${x.asn ? ` (${x.asn} ${x.country})` : ""}`,
      x.by_host,
      `${x.timestamp ? new Date(x.timestamp).toISOString().replace("T", " ").slice(0, 19) : "?"}${x.delay_seconds !== null ? ` (+${Math.round(x.delay_seconds)}s)` : ""}`,
      flags(x.flags),
    ]),
  }));
}

function urlsPanel(r: Report): HTMLElement {
  const parts: Node[] = [table({
    head: ["URL (defanged)", "Notes"],
    rows: r.urls.map((u) => [
      code(u.defanged),
      h("span", {}, flags(u.flags), u.text_mismatch ? h("div", { class: "meta" }, `Link text says: "${u.display_text}"`) : null),
    ]),
  })];
  const { virustotal, urlscan, sources } = r.enrichment;
  parts.push(h("p", { class: "meta" }, "Sources: " + (Object.entries(sources).map(([k, v]) => `${k}: ${v}`).join(" · ") || "none")));
  for (const v of virustotal.filter((x) => x.kind === "url")) {
    parts.push(h("p", { class: "meta" }, `VirusTotal ${v.target}: ${v.found ? `${v.malicious} malicious, ${v.suspicious} suspicious` : "not known"}`));
  }
  for (const s of urlscan) {
    parts.push(h("p", { class: "meta" }, `urlscan ${s.url}: ${s.status}${s.status === "done" ? (s.malicious ? " — MALICIOUS" : " — no threat found") : ""}${s.final_url ? ` → ${s.final_url}` : ""}`));
    if (s.screenshot_url) parts.push(h("img", { class: "shot", src: s.screenshot_url, alt: "urlscan screenshot", loading: "lazy" }));
    if (s.result_url) parts.push(h("a", { href: s.result_url, target: "_blank", rel: "noreferrer noopener" }, "Open urlscan result"));
  }
  return h("div", {}, ...parts);
}

function attachmentsPanel(r: Report, raw: Uint8Array | null): HTMLElement {
  const out = h("div", {});
  const status = h("p", { class: "meta" });
  const rows = r.attachments.map((a) => {
    const actions = h("div", {});
    if (raw) {
      const btn = h("button", {}, "Submit to VirusTotal…");
      btn.addEventListener("click", () => {
        btn.disabled = true;
        const box = h("div", { class: "consent" },
          h("strong", {}, "Upload this file to VirusTotal?"),
          h("p", {}, `"${a.filename}" will be uploaded and become visible to VirusTotal and its security partners. Do not upload anything confidential. By default only the hash is looked up, never the file.`));
        const yes = h("button", { class: "primary" }, "Yes, upload it");
        const no = h("button", {}, "Cancel");
        no.addEventListener("click", () => { box.remove(); btn.disabled = false; });
        yes.addEventListener("click", async () => {
          yes.disabled = true;
          try {
            const res = await send<SubmitResponse>({ type: "submitAttachment", sha256: a.sha256, rawB64: bytesToBase64(raw), consent: true });
            box.replaceWith(h("p", { class: "meta" }, res.message + " "), h("a", { href: res.permalink, target: "_blank", rel: "noreferrer noopener" }, "View on VirusTotal"));
          } catch (e) {
            status.textContent = (e as Error).message;
            btn.disabled = false;
            box.remove();
          }
        });
        box.append(h("div", { class: "row" }, yes, no));
        actions.append(box);
      });
      actions.append(btn);
    }
    const vt = r.enrichment.virustotal.find((v) => v.target === a.sha256);
    return [
      h("span", {}, a.filename, h("div", { class: "meta" }, `${a.detected_type}, ${a.size} bytes${a.nested_in ? `, inside ${a.nested_in}` : ""}`)),
      h("span", {}, code(a.sha256), vt ? h("div", { class: "meta" }, vt.found ? `VirusTotal: ${vt.malicious} malicious` : "VirusTotal: unknown hash") : null),
      h("span", {}, flags(a.flags), a.macro.has_macros ? h("div", { class: "meta" }, `Macros; auto-exec: ${a.macro.autoexec.join(", ") || "none"}`) : null, actions),
    ];
  });
  out.append(table({ head: ["File", "SHA-256", "Findings"], rows }), status);
  return out;
}

function iocsPanel(r: Report): HTMLElement {
  const json = h("button", {}, "Export JSON");
  json.addEventListener("click", () => downloadText(`iocs-${r.id.slice(0, 8)}.json`, "application/json", JSON.stringify(r.iocs, null, 2)));
  const csv = h("button", {}, "Export CSV");
  csv.addEventListener("click", () =>
    downloadText(`iocs-${r.id.slice(0, 8)}.csv`, "text/csv", toCsv([["type", "value", "defanged", "context"], ...r.iocs.map((i) => [i.type, i.value, i.defanged, i.context])])));
  return h("div", {}, h("div", { class: "row" }, json, csv), table({
    head: ["Type", "Indicator (defanged)", "Context"],
    rows: r.iocs.map((i) => [i.type, code(i.defanged), i.context]),
  }));
}

export function renderReport(r: Report, raw: Uint8Array | null): HTMLElement {
  const top = r.reasons.slice(0, 3);
  const card = h("section", { class: `verdict ${r.verdict}` },
    h("span", { class: "score" }, `${r.score}/100`),
    h("div", { class: "label" }, VERDICT_LABEL[r.verdict]),
    top.length ? h("ul", {}, ...top.map((x) => h("li", {}, x.text))) : h("p", {}, "No warning signs were found. That does not guarantee the email is safe."),
    h("div", { class: "meta" }, `From: ${r.email.from_display} <${r.email.from_address}> — "${r.email.subject}"`),
  );

  const panels: Record<string, () => HTMLElement> = {
    Authentication: () => authPanel(r),
    Hops: () => hopsPanel(r),
    URLs: () => urlsPanel(r),
    Attachments: () => attachmentsPanel(r, raw),
    IOCs: () => iocsPanel(r),
  };
  const panel = h("div", { class: "panel" });
  const tabs = h("div", { class: "tabs", role: "tablist" });
  const select = (name: string) => {
    for (const b of Array.from(tabs.children)) b.setAttribute("aria-selected", String(b.textContent === name));
    panel.replaceChildren(panels[name]!());
  };
  for (const name of Object.keys(panels)) {
    const b = h("button", { role: "tab", "aria-selected": "false" }, name);
    b.addEventListener("click", () => select(name));
    tabs.append(b);
  }
  select("Authentication");

  const warnings = [...r.warnings, ...r.parse_warnings];
  return h("div", {}, card,
    warnings.length ? h("p", { class: "notes" }, "Notes: " + warnings.join(" · ")) : null,
    h("details", {}, h("summary", {}, "Technical details"), tabs, panel),
  );
}
