import base64
import codecs
import binascii
import zlib
import bz2
import re
import urllib.parse
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.json.ensure_ascii = False


def looks_readable(text, threshold=0.80):
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
    return printable / len(text) >= threshold


def try_decode_bytes(raw: bytes):
    for enc in ('utf-8', 'latin-1', 'cp1252'):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode('utf-8', errors='replace')


def auto_detect_and_decode(text: str):
    text_stripped = text.strip()

    # ── 1. XOR + Base64 (key variable present) ─────────────────────────────
    # Accept any short string variable as the key (handles obfuscated var names too)
    key_match = re.search(r'\b\w+\s*=\s*["\']([^"\']{1,64})["\']', text_stripped)
    b64_match = re.search(
        r'(?:base64\.b64decode|onfr64\.o64qrpbqr)\([b]?["\']([A-Za-z0-9+/=\r\n]{20,})',
        text_stripped
    )
    if key_match and b64_match:
        key = key_match.group(1)
        b64_data = re.sub(r'[\r\n\s"\')\s]', '', b64_match.group(1))
        # Add padding in case the string was truncated
        b64_data += '=' * (-len(b64_data) % 4)
        try:
            encrypted = base64.b64decode(b64_data)
            decrypted = bytes(b ^ ord(key[i % len(key)]) for i, b in enumerate(encrypted))
            result = try_decode_bytes(decrypted)
            if looks_readable(result, 0.70):
                return result, 'XOR + Base64', f'Key: "{key}"'
            # Try decompressing the XOR result (may be compressed)
            try:
                result2 = try_decode_bytes(zlib.decompress(decrypted))
                if looks_readable(result2, 0.65):
                    return result2, 'XOR + Base64 + Zlib', f'Key: "{key}"'
            except Exception:
                pass
            try:
                result2 = try_decode_bytes(bz2.decompress(decrypted))
                if looks_readable(result2, 0.65):
                    return result2, 'XOR + Base64 + Bzip2', f'Key: "{key}"'
            except Exception:
                pass
        except Exception:
            pass

    # ── 2. exec(base64.b64decode(b'...')) obfuscated Python ────────────────
    patterns = [
        r"base64\.b64decode\(b['\"]([A-Za-z0-9+/=]+)['\"]",
        r"base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]",
    ]
    for pat in patterns:
        m = re.search(pat, text_stripped)
        if m:
            try:
                result = try_decode_bytes(base64.b64decode(m.group(1)))
                if looks_readable(result, 0.65):
                    return result, 'Obfuscated Python', 'exec(base64.b64decode(...))'
            except Exception:
                pass

    # ── 3. URL encoded (%XX) ────────────────────────────────────────────────
    if '%' in text_stripped and re.search(r'%[0-9A-Fa-f]{2}', text_stripped):
        try:
            result = urllib.parse.unquote_plus(text_stripped)
            if result != text_stripped and looks_readable(result):
                return result, 'URL Encoding', '%XX percent-encoded'
        except Exception:
            pass

    # ── 4. Pure Hex string ──────────────────────────────────────────────────
    # Support: plain hex, \xXX sequences, 0xXX sequences, space-separated bytes
    hex_clean = re.sub(r'(?:0x|\\x|\s)', '', text_stripped)
    if re.fullmatch(r'[0-9A-Fa-f]+', hex_clean) and len(hex_clean) % 2 == 0 and len(hex_clean) >= 4:
        try:
            result = try_decode_bytes(bytes.fromhex(hex_clean))
            if looks_readable(result):
                return result, 'Hexadecimal', 'Hex-encoded bytes'
        except Exception:
            pass

    # ── 5. Plain Base64 ─────────────────────────────────────────────────────
    b64_clean = re.sub(r'[\r\n\s]', '', text_stripped)
    if re.fullmatch(r'[A-Za-z0-9+/=]+', b64_clean) and len(b64_clean) >= 4:
        try:
            decoded_bytes = base64.b64decode(b64_clean)
            result = try_decode_bytes(decoded_bytes)
            if looks_readable(result):
                return result, 'Base64', 'Standard Base64'
            # even if not readable text, maybe it decompresses
        except Exception:
            pass

    # ── 6. Base64 → Zlib ────────────────────────────────────────────────────
    try:
        decoded_bytes = base64.b64decode(b64_clean)
        result = try_decode_bytes(zlib.decompress(decoded_bytes))
        if looks_readable(result):
            return result, 'Base64 + Zlib', 'Zlib-compressed, Base64-encoded'
    except Exception:
        pass

    # Also try raw zlib (no base64 wrapper)
    try:
        result = try_decode_bytes(zlib.decompress(text_stripped.encode('latin-1')))
        if looks_readable(result):
            return result, 'Zlib', 'Raw Zlib stream'
    except Exception:
        pass

    # ── 7. Base64 → Bzip2 ───────────────────────────────────────────────────
    try:
        decoded_bytes = base64.b64decode(b64_clean)
        result = try_decode_bytes(bz2.decompress(decoded_bytes))
        if looks_readable(result):
            return result, 'Base64 + Bzip2', 'Bzip2-compressed, Base64-encoded'
    except Exception:
        pass

    # Also try raw bzip2
    try:
        result = try_decode_bytes(bz2.decompress(text_stripped.encode('latin-1')))
        if looks_readable(result):
            return result, 'Bzip2', 'Raw Bzip2 stream'
    except Exception:
        pass

    # ── 8. ROT13 ────────────────────────────────────────────────────────────
    try:
        result = codecs.decode(text_stripped, 'rot_13')
        if looks_readable(result) and result != text_stripped:
            # Heuristic: ROT13 result should have reasonable word-like content
            if re.search(r'\b[a-zA-Z]{3,}\b', result):
                return result, 'ROT13', 'Caesar rotation (13)'
    except Exception:
        pass

    # ── 9. Unicode escape (\uXXXX or \xXX mixed) ───────────────────────────
    if r'\u' in text_stripped or r'\x' in text_stripped:
        try:
            result = text_stripped.encode('raw_unicode_escape').decode('unicode_escape')
            if looks_readable(result) and result != text_stripped:
                return result, 'Unicode Escape', r'\uXXXX / \xXX escape sequences'
        except Exception:
            pass

    # ── 10. ANSI escape sequences (\033[...m / \x1b[...m) ───────────────────
    if '\033[' in text_stripped or '\x1b[' in text_stripped or r'\033[' in text_stripped or r'\x1b[' in text_stripped:
        ansi_re = re.compile(r'(?:\\033|\\x1b|\x1b|\033)\[([0-9;]*)m')
        codes_found = ansi_re.findall(text_stripped)
        if codes_found:
            def ansi_describe(code_str):
                parts = [p for p in code_str.split(';') if p]
                descriptions = []
                i = 0
                while i < len(parts):
                    c = parts[i]
                    if c == '0' or c == '': descriptions.append('Reset')
                    elif c == '1': descriptions.append('Bold')
                    elif c == '2': descriptions.append('Dim')
                    elif c == '3': descriptions.append('Italic')
                    elif c == '4': descriptions.append('Underline')
                    elif c == '30': descriptions.append('Black text')
                    elif c == '31': descriptions.append('Red text')
                    elif c == '32': descriptions.append('Green text')
                    elif c == '33': descriptions.append('Yellow text')
                    elif c == '34': descriptions.append('Blue text')
                    elif c == '35': descriptions.append('Magenta text')
                    elif c == '36': descriptions.append('Cyan text')
                    elif c == '37': descriptions.append('White text')
                    elif c == '38' and i + 2 < len(parts) and parts[i+1] == '5':
                        descriptions.append(f'256-color text #{parts[i+2]}')
                        i += 2
                    elif c == '38' and i + 4 < len(parts) and parts[i+1] == '2':
                        descriptions.append(f'RGB text ({parts[i+2]},{parts[i+3]},{parts[i+4]})')
                        i += 4
                    elif c == '40': descriptions.append('Black bg')
                    elif c == '41': descriptions.append('Red bg')
                    elif c == '42': descriptions.append('Green bg')
                    elif c == '43': descriptions.append('Yellow bg')
                    elif c == '44': descriptions.append('Blue bg')
                    elif c == '90': descriptions.append('Bright Black text')
                    elif c == '91': descriptions.append('Bright Red text')
                    elif c == '92': descriptions.append('Bright Green text')
                    elif c == '93': descriptions.append('Bright Yellow text')
                    elif c == '94': descriptions.append('Bright Blue text')
                    elif c == '95': descriptions.append('Bright Magenta text')
                    elif c == '96': descriptions.append('Bright Cyan text')
                    elif c == '97': descriptions.append('Bright White text')
                    else: descriptions.append(f'Code {c}')
                    i += 1
                return ' + '.join(descriptions) if descriptions else 'Reset'
            lines = []
            for raw in ansi_re.finditer(text_stripped):
                seq = raw.group(0)
                desc = ansi_describe(raw.group(1))
                lines.append(f'{seq}  →  [{desc}]')
            result = '\n'.join(lines)
            if result and result != text_stripped:
                return result, 'ANSI Escape Codes', f'{len(codes_found)} escape sequence(s) decoded'

    # ── 11. Last resort: try base64 even if not perfectly clean ─────────────
    try:
        aggressive_clean = re.sub(r'[^A-Za-z0-9+/=]', '', text_stripped)
        if len(aggressive_clean) >= 8:
            result = try_decode_bytes(base64.b64decode(aggressive_clean + '=='))
            if looks_readable(result, 0.65):
                return result, 'Base64', 'Base64 (cleaned input)'
    except Exception:
        pass

    return None, None, None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/decode", methods=["POST"])
def decode():
    data = request.get_json()
    text = data.get("input", "").strip()

    if not text:
        return jsonify({"error": "No input provided"}), 400

    try:
        layers = []
        current = text
        max_layers = 6
        seen = set()

        for _ in range(max_layers):
            if current in seen:
                break
            seen.add(current)
            result, detected_type, detected_detail = auto_detect_and_decode(current)
            if result is None:
                break
            layers.append({
                "result": result,
                "detected_type": detected_type,
                "detected_detail": detected_detail,
            })
            current = result

        if not layers:
            return jsonify({"error": "Could not detect encoding type. Input may be custom-encrypted or unknown format."}), 400

        final = layers[-1]
        return jsonify({
            "result": final["result"],
            "detected_type": final["detected_type"],
            "detected_detail": final["detected_detail"],
            "layers": layers,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
