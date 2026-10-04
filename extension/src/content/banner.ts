import { VERDICT_LABEL, h } from "../shared/dom";
import type { Report } from "../shared/types";

// The banner lives in a closed shadow root so Gmail's CSS cannot restyle it and a hostile email
// cannot reach into it through the page DOM.
const STYLE = `
:host { all: initial; display: block; margin: 8px 0; }
.b { font: 13px/1.45 system-ui, sans-serif; border-left: 6px solid; border-radius: 6px; padding: 10px 12px; color: #1c2330; }
.SAFE { background: #e6f4ea; border-color: #1a7f37; } .SUSPICIOUS { background: #fff4d1; border-color: #9a6700; }
.PHISHING { background: #ffe5e7; border-color: #cf222e; } .INFO { background: #eef1f5; border-color: #8b95a5; }
.t { font-weight: 700; } ul { margin: 6px 0 0; padding-left: 18px; } .m { font-size: 12px; color: #5b6577; margin-top: 4px; }
button { font: inherit; margin-top: 6px; cursor: pointer; }
`;

function mount(kind: string, ...content: (Node | null)[]): HTMLElement {
  const host = h("div", { "data-pea-banner": "1" });
  const root = host.attachShadow({ mode: "closed" });
  root.append(h("style", {}, STYLE), h("div", { class: `b ${kind}` }, ...content));
  return host;
}

export function loadingBanner(): HTMLElement {
  return mount("INFO", h("div", { class: "t" }, "Phishing Email Analyzer"), h("div", { class: "m" }, "Analyzing this message…"));
}

export function errorBanner(message: string): HTMLElement {
  return mount("INFO", h("div", { class: "t" }, "Phishing Email Analyzer could not check this message"), h("div", { class: "m" }, message));
}

export function reportBanner(r: Report): HTMLElement {
  const reasons = r.reasons.slice(0, 3);
  const list = h("ul", {}, ...reasons.map((x) => h("li", {}, x.text)));
  const more = h("button", {}, "Show all findings");
  const full = h("ul", { style: "display:none" }, ...r.fired_rules.map((x) => h("li", {}, `${x.description} (+${x.weight})`)));
  more.addEventListener("click", () => {
    full.style.display = full.style.display === "none" ? "block" : "none";
  });
  return mount(
    r.verdict,
    h("div", { class: "t" }, `${VERDICT_LABEL[r.verdict]} — risk ${r.score}/100`),
    reasons.length ? list : h("div", { class: "m" }, "No warning signs found. This is not a guarantee of safety."),
    r.fired_rules.length ? more : null,
    full,
    h("div", { class: "m" }, "Phishing Email Analyzer · open the extension popup to export indicators"),
  );
}
