"""
obfuscate.py - XOR string-literal obfuscation for background.js.

The original EdgeShot hides its sensitive literals by XOR-encoding them (key
0x42) and decoding at runtime. We port the same idea to the MV3 service worker:
every single-/double-quoted string literal is XOR-encoded with key 0x42 and
rewritten as ``_x("base64")``, with a tiny self-contained decoder prepended.

MV3's Content-Security-Policy forbids ``eval()`` / ``new Function()``, so the
decode is done by a plain helper function (no eval). String *values* are encoded
- i.e. JS escape sequences are resolved at build time - so the decoder
reconstructs the exact runtime string, including multi-byte UTF-8 (TextDecoder).
"""

import base64

XOR_KEY = 0x42

# A '/' after any of these characters begins a regular expression (not division).
_REGEX_PRECEDING = set("([{:;,=!?&|+-*%<>^~")

# Keywords after which a '/' also begins a regular expression.
_REGEX_KEYWORDS = {
    "return", "typeof", "case", "delete", "void", "throw", "new",
    "in", "of", "instanceof", "yield", "await", "else", "do",
}

_DECODER = (
    "/* XOR string decoder (obfuscation, key 0x42). CSP-safe: no eval. */\n"
    "function _x(s){var b=atob(s),u=new Uint8Array(b.length);"
    "for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i)^66;"
    "return new TextDecoder(\"utf-8\").decode(u);}\n"
)


def _js_unescape(raw):
    """Resolve JS escape sequences in a raw string literal to its runtime value."""
    out = []
    i = 0
    n = len(raw)
    simple = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
    while i < n:
        c = raw[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            out.append("\\")
            break
        e = raw[i]
        if e in simple:
            out.append(simple[e])
            i += 1
        elif e == "x":
            if i + 2 < n:
                try:
                    out.append(chr(int(raw[i + 1:i + 3], 16)))
                    i += 3
                except ValueError:
                    out.append("x")
                    i += 1
            else:
                out.append("x")
                i += 1
        elif e == "u":
            if i + 1 < n and raw[i + 1] == "{":
                j = raw.find("}", i + 2)
                if j != -1:
                    try:
                        out.append(chr(int(raw[i + 2:j], 16)))
                        i = j + 1
                    except ValueError:
                        out.append("u")
                        i += 1
                else:
                    out.append("u")
                    i += 1
            elif i + 4 < n:
                try:
                    out.append(chr(int(raw[i + 1:i + 5], 16)))
                    i += 5
                except ValueError:
                    out.append("u")
                    i += 1
            else:
                out.append("u")
                i += 1
        else:
            # Escaped punctuation (\" \' \/ \`) or an unknown escape (\d -> d).
            out.append(e)
            i += 1
    return "".join(out)


def _encode(value, key=XOR_KEY):
    """XOR-encode a string value and return its base64 representation."""
    xored = bytes(b ^ key for b in value.encode("utf-8"))
    return base64.b64encode(xored).decode("ascii")


def obfuscate_js(js_code, key=XOR_KEY):
    """Rewrite js_code so every '...' / "..." literal is XOR-encoded.

    Template literals (backticks), comments and regex literals are left intact.
    Returns the transformed source with the decoder prepended.
    """
    out = []
    i = 0
    n = len(js_code)
    prev = ""  # last significant char (used for regex-vs-division)

    while i < n:
        c = js_code[i]

        # line comment -> stripped (the newline is kept, so lines don't merge)
        if c == "/" and i + 1 < n and js_code[i + 1] == "/":
            j = js_code.find("\n", i)
            j = n if j == -1 else j
            i = j
            continue

        # block comment -> stripped (a space keeps adjacent tokens from merging)
        if c == "/" and i + 1 < n and js_code[i + 1] == "*":
            j = js_code.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(" ")
            i = j
            continue

        # regex literal (as opposed to division)
        if c == "/":
            is_regex = prev in _REGEX_PRECEDING
            if prev and (prev.isalnum() or prev in "_$"):
                k = i - 1
                while k >= 0 and (js_code[k].isalnum() or js_code[k] in "_$"):
                    k -= 1
                is_regex = js_code[k + 1:i] in _REGEX_KEYWORDS
            if is_regex:
                j = i + 1
                in_class = False
                while j < n:
                    ch = js_code[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "[":
                        in_class = True
                    elif ch == "]":
                        in_class = False
                    elif ch == "/" and not in_class:
                        j += 1
                        break
                    elif ch == "\n":
                        break
                    j += 1
                while j < n and js_code[j].isalpha():
                    j += 1
                out.append(js_code[i:j])
                i = j
                prev = ""
                continue

        # string literal (single or double quoted)
        if c == '"' or c == "'":
            quote = c
            j = i + 1
            raw_chars = []
            while j < n:
                ch = js_code[j]
                if ch == "\\":
                    raw_chars.append(ch)
                    if j + 1 < n:
                        raw_chars.append(js_code[j + 1])
                        j += 2
                    else:
                        j += 1
                    continue
                if ch == quote:
                    j += 1
                    break
                if ch == "\n":
                    break
                raw_chars.append(ch)
                j += 1

            # A string literal immediately followed by ':' is a property KEY
            # ({"host": handler}), a switch case label (case "x":) or a ternary
            # branch (cond ? "a" : "b"). Rewriting an object KEY into `_x("...")`
            # is invalid property syntax (V8: "Unexpected string"), so leave such
            # literals untouched. Obfuscating keys buys nothing anyway — they are
            # structural, not secret string *values*.
            k = j
            while k < n:
                chk = js_code[k]
                if chk.isspace():
                    k += 1
                elif chk == "/" and k + 1 < n and js_code[k + 1] == "/":
                    nl = js_code.find("\n", k)
                    k = n if nl == -1 else nl + 1
                elif chk == "/" and k + 1 < n and js_code[k + 1] == "*":
                    end = js_code.find("*/", k + 2)
                    k = n if end == -1 else end + 2
                else:
                    break
            if k < n and js_code[k] == ":":
                out.append(js_code[i:j])  # keep the literal exactly as-is
            else:
                value = _js_unescape("".join(raw_chars))
                out.append('_x("' + _encode(value, key) + '")')
            i = j
            prev = '"'
            continue

        # template literal: leave untouched
        if c == "`":
            j = i + 1
            while j < n:
                ch = js_code[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "`":
                    j += 1
                    break
                j += 1
            out.append(js_code[i:j])
            i = j
            prev = "`"
            continue

        out.append(c)
        if not c.isspace():
            prev = c
        i += 1

    return _DECODER + "".join(out)
