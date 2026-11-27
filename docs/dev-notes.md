# Developer Notes

- `ref_id` warnings are VS Code extension false positives (github/vscode-github-actions#452, #61); workflows run correctly on GitHub. Suppressed via `yamllint disable-line`.
- `task-1509` cancelled: `AppData\Roaming\Microsoft\Installer` is owned by `TrustedInstaller`; `icacls /grant` cannot modify it without SYSTEM-level ownership. Not related to `siftsec`.
