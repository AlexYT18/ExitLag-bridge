# Desktop UI checkpoint

Desktop redesign implemented in `main`, starting from `a5a1edb`; core UI commit
`1f129c9`. Read [the iteration report](DESKTOP_UI_ITERATION.md) and
[the user guide](../desktop-ui.md) for current behavior and tests. The previous
research-only checkpoint is preserved in Git history.

UI-only scope: dark Tk/ttk five-page desktop, unified start/stop, generation-bound
async operations, verified process picker/editor, truthful unconfirmed-route
status, default-off UDP, safe diagnostics/clipboard. Backend and routing are
unchanged. Network/live compatibility remains unverified.

Before future edits inspect git status and preserve user work. Use existing
UI/build checks only for UI changes. Actual Arch desktop, Wayland/DPI and official
ExitLag/PEAK runtime remain the next host-dependent validation steps.
