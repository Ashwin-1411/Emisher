# popup/

## 1. Purpose
The toolbar popup: drag-and-drop or choose a `.eml`, then show the verdict card, top 3 reasons and an expandable "Technical details" section (Authentication, Hops, URLs, Attachments, IOCs).

## 2. Where it fits
Reads the file locally, sends it to `background/` (`analyze`) and renders the returned `Report`. The Attachments tab can request a VirusTotal upload after explicit confirmation.

## 3. Concepts you need to know
Everything shown from a report is attacker-controlled text, so rendering uses `h()` (`shared/dom.ts`) and `textContent`, never `innerHTML`. URLs are shown defanged so nothing is clickable by accident (only the urlscan/VirusTotal result links are real anchors).

## 4. File-by-file walkthrough
- `main.ts` - drop zone, file picker, size/type checks, status and errors.
- `render.ts` - `renderReport(report, raw)`: verdict card, tabs, per-tab tables, urlscan screenshots, IOC export (JSON/CSV generated client-side with formula-injection protection), and the consent box before `submitAttachment`.
- `popup.css` - light/dark theme via CSS variables.

## 5. Design decisions and why
- **Decision:** Consent is a confirmation step naming the file and explaining that VirusTotal's partners can see it.
  **Why:** An upload cannot be taken back.
  **Alternatives considered:** A one-time global setting.
  **Trade-off:** One extra click per upload.
- **Decision:** The popup keeps the `.eml` bytes in memory for the upload.
  **Why:** The backend is stateless and needs the original email again.
  **Alternatives considered:** Server-side attachment retention.
  **Trade-off:** Closing the popup loses the ability to upload; drop the file again.

## 6. Edge cases and limitations
Popups close when focus is lost, which discards the result view; re-run the analysis. 25 MB limit. Screenshots depend on urlscan.io being reachable.

## 7. How to test it
Manual: load unpacked, drop the fixtures from `backend/tests/fixtures`.

## 8. Further reading
Chrome action popup docs; OWASP DOM-based XSS prevention cheat sheet.
