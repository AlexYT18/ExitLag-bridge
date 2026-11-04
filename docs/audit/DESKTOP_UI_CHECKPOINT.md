# Desktop UI redesign checkpoint

The user requested continuation after a five-hour pause. Investigation and the
short plan were delivered; **the redesigned UI is not implemented yet**.
Starting revision: `842fb232eebe2a9e01fd8151cf539ea10337396b`, branch `main`,
fork `AlexYT18/ExitLag-bridge`. Check git status before resuming; preserve edits.

## Established facts

- Entry point: `installers/linux/app.py`, Python Tkinter/ttk, no framework change.
- Process picker/editor: `installers/linux/game_picker.py`; process identity and
  image checks in `installers/bridge_setup/process_picker.py` must remain intact.
- Packaging explicitly lists modules in `installers/linux/build.py`; any new
  desktop module must be added to FILES and existing packaging fixture checks.
- Current UI has saved-game sidebar, dashboard/setup pages and separate start/stop.
- `stop_session` currently runs taskkill synchronously (up to 15 seconds); redesign
  must keep Tk responsive and marshal worker results onto the UI thread.
- GUI currently has no authoritative route-confirmation channel. A running helper,
  token metadata, callback log or client launch does not prove a service relay.
  Never display route confirmed without real backend evidence. Do not change the
  networking backend to supply it in this UI-only task.
- Diagnostics must use bounded safe reads and redact secrets and full private
  paths before display/copy. Never read session token contents for diagnostics.

## User scope

Create a compact wide dark desktop inspired by the layout and interaction of
ExitLag v1, using only own materials and the name ExitLag Bridge. No exact visual
reference was available; do not claim pixel-identical reproduction.

Permanent navigation: Home, Games, Statistics, Settings, Diagnostics (Russian UI).
Main game/connection area; persistent status area. Search by name and Steam AppID;
real running process list; game card with executable/PID/prefix when available;
add/edit/remove. Warn about launchers, wineserver and ambiguous process selection.
One primary start/stop action. Distinguish stopped/starting/client started/route
unconfirmed/error and separately show client/backend/route. UDP default-off with
warning. Show only collected metrics; unmeasured ping/loss/jitter/traffic must be
explicitly unavailable, without invented charts. Preserve legitimate client setup,
process verification, lease/privilege boundaries, and all existing mapping scope.
The selected row does not restrict the routing session to one saved game.

## Agreed implementation stages and files

1. New UI-only `installers/linux/desktop_support.py` for state views and bounded,
   redacted diagnostics; `app.py` integration and `build.py` FILES update. Proposed
   API only (not implemented): session_view(...) -> SessionView, redact(text),
   read_log_tail(...), diagnostics_snapshot(state).
2. Dark ttk theme, five pages, game/connection card and unified action in app.py;
   separate presentation, state and long-running session operations as needed.
3. Extend game_picker.py editor and process warning/details. Proposed API only:
   MappingController.replace(index,row), MappingEditor.edit_selected(),
   candidate_warning(candidate,image_count=None), candidate_details(candidate).
   Preserve private atomic save and detection revalidation; mask paths in display.
4. Update docs/game-selection.md and a desktop UI guide; capture real Tk screenshot
   through the already configured preview process. Document actual test results.

Only use existing configured UI/build checks after each logical stage:

```sh
source /workspace/exitlag-validation/env.sh # Cloud tools, if this file exists
python3 tests/test_linux_launcher.py
python3 tests/test_game_picker.py
python3 tests/gui-picker-smoke.py
python3 tests/test_linux_packaging.py
# tests/test_desktop_ui.py expects a real populated program tree and X display.
```

Extend existing test files rather than adding unrelated networking test runs.
`EXL_DASHBOARD_PREVIEW` / `EXL_GUI_PREVIEW` are supported in gui-picker-smoke.py;
inspect the screenshot capture code before adapting it. Use synthetic fixtures
only in tests, never in the product UI. Rebuild/check actual package with the new
module dependency before delivery. No new UI checks were executed at this pause:
there had been no functional edits. Networking and live game tests are out of scope.

Commit small completed stages and push to the user's fork. Report saved functions,
adapted/unsupported reference features, actual UI/build PASS/FAIL/SKIP, and limitations.
