+++
title = "EdgeShot"
chapter = false
weight = 5
+++

## Overview

EdgeShot is a **Chromium (Manifest V3) browser-extension agent** for Mythic. It is
a native port of the standalone EdgeShot extension into a Mythic payload type: it
installs like any third-party agent, builds a deployable ZIP from the UI, and
reports callbacks through the standard `http` C2 profile.

The agent is a single `background.js` service worker (~2,000 lines) that encrypts
its own traffic in the native Mythic format (`AES-256-CBC` + `HMAC-SHA256`,
`mythic_encrypts = true`), schedules tasking via `chrome.alarms` (~6 seconds), and
exposes **29 commands**. Three deployment modes are supported: `zip` (plain
packaged extension), `stomp` (forge the browser's *Secure Preferences* to
auto-load the extension) and `gap` (two-phase ghost-anchor persistence).

**Author:** [@Fir3n0x](https://github.com/Fir3n0x)

### C2 Workflow

{{<mermaid>}}
sequenceDiagram
    participant A as EdgeShot (MV3 SW)
    participant H as http profile
    participant M as Mythic
    A->>+H: GET ?q= (tasking, ~6s via chrome.alarms)
    H->>+M: forward request
    M-->>-H: reply with tasking
    H-->>-A: reply with tasking
    A->>+H: POST response (checkin / output / download)
    H->>+M: forward response
{{< /mermaid >}}

All requests hit a single endpoint; the body is `base64(UUID + IV + ciphertext +
HMAC)`.

## OPSEC

- **Single endpoint** — tasking and exfiltration share one URI; no separate exfil
  routes.
- **Encrypted traffic** — the agent encrypts its own messages; the `http` profile
  is a plain transport.
- **No ECDH key exchange** — a static AES key is baked at build time; keep
  *Perform Key Exchange* **off** or the checkin will not match.
- **Static string obfuscation (optional)** — the `obfuscate` build parameter
  XOR-encodes string literals in `background.js` to reduce static string IOCs.
  It is CSP-safe (no `eval`/`new Function`) but does **not** rename identifiers
  or flatten control flow.
- **`content.js` is empty** — for GAP compatibility, all content-script logic is
  inlined into `background.js`.
- **Callback cadence** — a fixed ~6-second `chrome.alarms` schedule; the `http`
  profile's `sleep`/`jitter` are **ignored**, so beaconing analytics are uniform.
- **Passive collection is buffered** — keylogs/clipboard/cookies/LLM activity are
  held in `chrome.storage.local` and drained with `get_buffer` rather than
  streamed immediately.

## Commands

### Lifecycle & status
`heartbeat`, `exit`, `kill`, `get_status`, `get_capabilities`

### Browser reconnaissance
`get_active_tab`, `get_tabs`, `get_screenshot`, `get_dom`, `get_history`,
`get_bookmarks`, `network_recon`

### File operations
`get_file`, `upload_file`, `execute_file`

### Passive collection
`get_buffer`, `start_keylogger`, `stop_keylogger`

### Interaction & notification lures
`alert`, `open_tab`, `get_notification`, `set_notification`, `send_notification`,
`send_notification_v2`

### Proxy (declarativeNetRequest)
`proxy_set_rules`, `enable_proxy`, `disable_proxy`

### Native RCE (build with `enable_rce = true`)
`check_rce`, `execute_cmd`

## Development

Each command is one Python module under `agent_functions/`, following the
canonical pattern:

- a `<Cmd>Arguments(TaskArguments)` class with `self._args` and `parse_arguments()`;
- a `<Cmd>Command(CommandBase)` class with `argument_class`, `attributes` and
  `create_go_tasking()`.

The agent-side handlers live in `agent_code/background.js`; build-time
placeholders (`{{UUID}}`, `{{AESPSK}}`, `{{GET_URL}}`, `{{POST_URL}}`,
`{{QUERY_PARAM}}`, `{{ENABLE_RCE}}`) are substituted by `builder.py`.

To add a command: create the module, import it in
`Payload_Type/edgeshot/edgeshot/__init__.py`, add the matching case to
`background.js`, and list it in `CAPABILITIES`.

## C2 Profiles

EdgeShot uses the **built-in `http` profile** (Go v1.1.x). Only four options are
relevant:

| Option | Value |
|--------|-------|
| `callback_host` | your C2 host |
| `callback_port` | your C2 port |
| **Encryption Type (`AESPSK`)** | **`aes256_hmac`** |
| **Perform Key Exchange** | **`false`** |

All other `http` options are ignored by the agent.
