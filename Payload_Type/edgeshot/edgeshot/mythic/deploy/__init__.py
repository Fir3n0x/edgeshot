"""EdgeShot deployment helpers (stomp / GAP).

Ported from the standalone `stomp` and `GAP` tools: Secure Preferences forging
(HMAC-SHA256), CRX3 public-key extraction / extension-ID derivation, and the
on-target injection scripts.

Kept dependency-light on purpose: only `browser_config`, `crypto`, `manifest`,
`prefs` and `inject` are imported on demand by the payload builder.
"""
