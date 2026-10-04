// Tiny DOM builder. Everything from an email (subjects, URLs, filenames) is attacker-controlled,
// so UI code NEVER uses innerHTML: text always goes through textContent.

type Child = Node | string | null | undefined | false;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<Record<string, string>> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined) continue;
    if (key === "class") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export const VERDICT_LABEL = {
  SAFE: "Looks safe",
  SUSPICIOUS: "Suspicious",
  PHISHING: "Likely phishing",
} as const;

export function downloadText(filename: string, mime: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = h("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** CSV with the same formula-injection guard as the backend export. */
export function toCsv(rows: string[][]): string {
  const cell = (v: string) => {
    const safe = /^[=+\-@\t\r]/.test(v) ? "'" + v : v;
    return `"${safe.replaceAll('"', '""')}"`;
  };
  return rows.map((r) => r.map(cell).join(",")).join("\n");
}
