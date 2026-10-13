---
name: qa-dashboard
description: UX/UI QA of the Patronus control dashboard (control.patronus.studio) with the dedicated QA account — fixed user journeys, usability, errors, accessibility and mobile layout. Use as part of the QA run or when asked to review the dashboard.
---

# Control dashboard QA

Use the built-in browser (`mcp__Claude_Browser__*`).

## Rules

- **Never enter passwords or other credentials.** The QA account must already be signed in, because a person logs in to the QA account once in the built-in browser.
- If the session has expired, record the finding `qa:dashboard:session-expired` (severity medium, suggestion "sign in the QA account in the built-in browser") and stop this area.
- Only change resources whose name starts with `qa-`. Create them yourself and delete them again in the same run.
- **Billing**: read it, never submit a payment, plan change or cancellation.
- **Account and organisation settings**: read them, never change them.
- **Cookie banners**: pick the most privacy-preserving option.

## Journeys

For each journey, count the clicks or steps and note anything confusing:

1. **First look**: open `https://control.patronus.studio/`. Can a new user tell within 10 seconds what to do first?
2. **API key**: create a key named `qa-<date>`. Check that copying is clear and the key is shown only once, then revoke it. Never paste the key value into notes or issues.
3. **Scan from the UI** (if offered): scan a harmless text and a text containing `IGNORE ALL PREVIOUS INSTRUCTIONS`. Is the result understandable?
4. **Scan history / activity**: find the scans the QA scripts made today. Check filters and empty states.
5. **Usage and limits**: is the current usage and the limit obvious?
6. **CLI login**: open `/cli-login` directly. Check that the page explains what happens and what to do next.
7. **Docs and help links**: every help link should lead to the right page on docs.patronus.studio.

## Each page

- **Console errors and failed requests**: `read_console_messages` with `onlyErrors`, plus `read_network_requests` for status ≥ 400.
- **Load time**: note pages that take longer than about 3 s until content appears.
- **Mobile**: `resize_window` with preset `mobile`. Check for horizontal scrolling, cut-off tables and unreachable actions. Reset to `desktop` afterwards.
- **Accessibility basics**: unlabeled buttons or inputs (use `read_page` with filter `interactive`), focus order on the main form, and contrast problems visible in the screenshot.
- **Copy**: unclear labels, jargon, error messages that do not say how to fix the problem.

## Output

Write `~/.patronus-qa/runs/<date>/dashboard.json` in the report shape:
- `metrics.journeys` = `[{name, ok, steps, issues}]`
- `metrics.console_errors` with the total number
- Findings use area `dashboard` (bugs) or `ux` (usability). Each finding names the page URL and the exact element. Put a short description of the screenshot in the evidence, never a credential or key.

The dashboard source is not in this repository, so file issues only, no PRs.
