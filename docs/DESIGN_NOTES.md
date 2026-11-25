# ChainGuard design notes

[← Back to README](../README.md)

Moved here from the main README without content changes.

## Redesign (rediseno-pro, Nov 2026)

- **Direction:** "audit report". Warm paper background, near-black ink, one blue accent (`--accent`) for actions and links. Code surfaces (editor, live preview, snippets) use the dark `--code` tokens.
- **Type:** Source Serif 4 for headings, IBM Plex Sans for body, IBM Plex Mono for SWC ids, line numbers, scores and amounts.
- **Fixed colour meaning:** red = High, amber = Medium, ochre = Low, slate = Info, green = no findings. Severity colours never decorate.
- **Verdict:** a High finding outranks the numeric score, so the report never says "secure" with a High issue open.
- **Flow:** before, the scanner sat below two marketing sections and findings were collapsed. Now the scanner comes right after the hero, the first (most severe) finding opens by default, Ctrl/Cmd+Enter runs a scan from the editor, and on mobile the report scrolls into view when a scan starts.
- **States:** skeleton with the report's shape, error with a retry (hero preview and scanner), empty state listing the six rules, "no findings" that says what is out of scope.
- jsPDF is loaded only when someone exports (main bundle 608 kB -> 247 kB).

Phone check (2 min): open the site at 390 px, tap "Scan a contract", tap "Run scan", confirm the report scrolls into view with the High finding open, tap "Export PDF", switch to SafeVault.sol and run again ("No findings").
