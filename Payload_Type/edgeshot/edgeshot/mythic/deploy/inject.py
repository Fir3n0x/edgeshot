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

    return content


def script_name(platform: str) -> str:
    """Script filename inside the ZIP for a target platform."""
    return "inject.sh" if platform != "windows" else "inject.bat"


def render_stomp_script(cfg, target_dir: str, platform: str) -> str | None:
    """Render the single-phase stomp injection script."""
    template = _STOMP_TEMPLATES.get(platform)
    if not template:
        return None
    return _render(template, cfg, {"BROWSER_TARGET_DIR": target_dir})


def render_gap_script(cfg, target_dir: str, malicious_name: str, benign_name: str, platform: str) -> str | None:
    """Render the two-phase GAP injection script."""
    template = _GAP_TEMPLATES.get(platform)
    if not template:
        return None
    return _render(template, cfg, {
        "BROWSER_TARGET_DIR": target_dir,
        "MALICIOUS_NAME": malicious_name,
        "BENIGN_NAME": benign_name,
    })
