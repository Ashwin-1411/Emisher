import { bytesToBase64 } from "../shared/api";
import { h } from "../shared/dom";
import { send } from "../shared/messaging";
import type { Report } from "../shared/types";
import { renderReport } from "./render";

const app = document.getElementById("app")!;
document.getElementById("open-options")!.addEventListener("click", (e) => {
  e.preventDefault();
  void chrome.runtime.openOptionsPage();
});

const MAX_BYTES = 25 * 1024 * 1024; // matches the backend default upload limit

function showStatus(text: string): HTMLElement {
  const el = h("div", { class: "status" }, text);
  app.querySelector(".status, .error")?.remove();
  app.append(el);
  return el;
}

function showError(text: string): void {
  app.querySelector(".status, .error")?.remove();
  app.append(h("div", { class: "error" }, text));
}

async function analyzeFile(file: File): Promise<void> {
  app.querySelector(".result")?.remove();
  if (file.size > MAX_BYTES) return showError("That file is larger than the 25 MB limit.");
  if (!/\.eml$/i.test(file.name) && file.type !== "message/rfc822") {
    return showError("Please choose a .eml file (in Gmail: ⋮ → Download message).");
  }
  showStatus(`Analyzing ${file.name}… this can take up to a minute when link scans are enabled.`);
  try {
    const raw = new Uint8Array(await file.arrayBuffer());
    const report = await send<Report>({ type: "analyze", rawB64: bytesToBase64(raw) });
    app.querySelector(".status, .error")?.remove();
    const result = renderReport(report, raw);
    result.classList.add("result");
    app.append(result);
  } catch (e) {
    showError((e as Error).message);
  }
}

const input = h("input", { type: "file", accept: ".eml,message/rfc822", hidden: "" });
const pick = h("button", { class: "primary" }, "Choose .eml file");
const drop = h("div", { class: "drop" }, h("div", {}, "Drag and drop a .eml file here"), pick, input);

pick.addEventListener("click", () => input.click());
input.addEventListener("change", () => input.files?.[0] && void analyzeFile(input.files[0]));
for (const ev of ["dragenter", "dragover"]) {
  drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); });
}
for (const ev of ["dragleave", "drop"]) {
  drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); });
}
drop.addEventListener("drop", (e) => {
  const file = (e as DragEvent).dataTransfer?.files[0];
  if (file) void analyzeFile(file);
});

app.append(drop);
