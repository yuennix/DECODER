import ast
import base64
import codecs
import binascii
import zlib
import bz2
import lzma
import zipfile
import io
import struct
import marshal
import dis
import re
import urllib.parse
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.json.ensure_ascii = False


_BASE91_ALPHABET = [
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','!','#','$',
    '%','&','(',')','*','+',',','.','/',':',';','<','=',
    '>','?','@','[',']','^','_','`','{','|','}','~','"',
]
_BASE91_DECODE_MAP = {c: i for i, c in enumerate(_BASE91_ALPHABET)}


def base91_decode(data: str) -> bytes:
    v = -1
    b = 0
    n = 0
    out = bytearray()
    for ch in data:
        c = _BASE91_DECODE_MAP.get(ch, -1)
        if c == -1:
            continue
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while True:
                out += struct.pack('B', b & 255)
                b >>= 8
                n -= 8
                if not n > 7:
                    break
            v = -1
    if v + 1:
        out += struct.pack('B', (b | v << n) & 255)
    return bytes(out)


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


def _check_truncation(decoded_text: str, was_padded: bool) -> str | None:
    """Return a warning string if the decoded output appears to be cut off."""
    if not was_padded:
        return None
    try:
        ast.parse(decoded_text)
        return None
    except SyntaxError as e:
        msg = str(e).lower()
        if any(k in msg for k in ('unterminated', 'unexpected eof', 'eof while', 'was never closed')):
            return (
                "⚠️  INPUT TRUNCATED — The encoded data was cut off mid-paste. "
                "The decoded output is INCOMPLETE. "
                "Upload the file instead of copy-pasting to get the full result."
            )
    return None


def _disassemble_code(code_obj) -> str:
    """Return readable output from a marshal code object: string constants + disassembly."""
    consts = []
    def collect(obj):
        if hasattr(obj, 'co_consts'):
            for c in obj.co_consts:
                if isinstance(c, str) and len(c) > 4:
                    consts.append(repr(c[:300]))
                elif hasattr(c, 'co_consts'):
                    collect(c)
    collect(code_obj)
    buf = io.StringIO()
    try:
        dis.dis(code_obj, file=buf)
    except Exception:
        pass
    asm = buf.getvalue()
    parts = []
    if consts:
        parts.append('# ── String constants extracted ──')
        parts.extend(consts[:30])
        parts.append('')
    if asm:
        parts.append('# ── Bytecode disassembly ──')
        parts.append(asm)
    return '\n'.join(parts) if parts else '# (empty code object)'


def _decode_lyrox(payload: str):
    """Decode a Lyrox-encoded payload: base91 → lzma → zip → __main__.py.
    Returns (decoded_text, label) or (None, None) on failure."""
    raw = base91_decode(payload)
    decompressed = lzma.decompress(raw)
    if decompressed[:2] == b'PK':
        try:
            zf = zipfile.ZipFile(io.BytesIO(decompressed))
            names = zf.namelist()
            if '__main__.py' in names:
                code = zf.read('__main__.py').decode('utf-8', errors='replace')
                return code, 'base91 + LZMA + ZIP → __main__.py'
            py_files = [n for n in names if n.endswith('.py')]
            if py_files:
                code = zf.read(py_files[0]).decode('utf-8', errors='replace')
                return code, f'base91 + LZMA + ZIP → {py_files[0]}'
        except Exception:
            pass
    text_result = try_decode_bytes(decompressed)
    if looks_readable(text_result, 0.60):
        return text_result, 'base91 + LZMA → plaintext'
    return None, None


def auto_detect_and_decode(text: str):
    """Returns (result, detected_type, detected_detail, truncation_warning)."""
    text_stripped = text.strip()

    # ── 0. Lyrox obfuscator (base91 + lzma + zip) ──────────────────────────
    # Pattern: VIP='LyroxPy' / import Lyrox / var='<payload>' / Lyrox.Py(var)
    lyrox_call = re.search(r'Lyrox\.Py\((\S+?)\)', text_stripped)
    if lyrox_call:
        var_name = re.escape(lyrox_call.group(1))
        payload_match = re.search(var_name + r"""\s*=\s*'([^']{20,})'""", text_stripped)
        if not payload_match:
            payload_match = re.search(var_name + r'\s*=\s*"([^"]{20,})"', text_stripped)
        if payload_match:
            try:
                result, label = _decode_lyrox(payload_match.group(1))
                if result:
                    return result, 'Lyrox Obfuscator', label, None
            except Exception:
                pass

    # ── 0b. Botpalys obfuscator (reversed Base64) ──────────────────────────
    # Pattern: _ = lambda __ : base64.b64decode(__[::-1]); exec((_)(b'...'))
    botpalys_match = re.search(
        r"b64decode\(__\[::-1\]\).*?exec\(.*?\(b['\"]([A-Za-z0-9+/=\r\n]{20,})['\"]",
        text_stripped, re.DOTALL
    )
    if botpalys_match:
        try:
            payload = re.sub(r'[\r\n\s]', '', botpalys_match.group(1))
            result = try_decode_bytes(base64.b64decode(payload[::-1]))
            if looks_readable(result, 0.60):
                return result, 'Botpalys Obfuscator', 'reversed Base64 → plaintext Python', None
        except Exception:
            pass

    # ── 0c. Marshal-based obfuscation ──────────────────────────────────────
    # Patterns: exec(marshal.loads(...)), exec(compile(marshal.loads(...)))
    if 'marshal' in text_stripped and 'loads' in text_stripped:
        for pat in [
            r"b64decode\(b?['\"]([A-Za-z0-9+/=\r\n]{20,})['\"]",
            r"base64\.b64decode\(b?['\"]([A-Za-z0-9+/=\r\n]{20,})['\"]",
        ]:
            m = re.search(pat, text_stripped)
            if m:
                try:
                    raw = base64.b64decode(re.sub(r'[\r\n\s]', '', m.group(1)))
                    for decomp in [zlib.decompress, bz2.decompress, lzma.decompress, lambda x: x]:
                        try:
                            code_obj = marshal.loads(decomp(raw))
                            result = _disassemble_code(code_obj)
                            if result:
                                return result, 'Marshal Obfuscator', 'base64 + marshal → bytecode', None
                        except Exception:
                            pass
                except Exception:
                    pass

    # ── 0d. exec('...'[::-1]) — reversed string ─────────────────────────────
    rev_exec = re.search(
        r"""exec\(\s*(?:b?['\"])((?:[^'\"\\]|\\.){20,})(?:['\"])\s*\[::-1\]""",
        text_stripped
    )
    if rev_exec:
        try:
            result = try_decode_bytes(rev_exec.group(1)[::-1].encode('latin-1'))
            if looks_readable(result, 0.60):
                return result, 'String Reversal', "exec(string[::-1]) → plaintext Python", None
        except Exception:
            pass

    # ── 0e. exec(bytes([N,N,...]).decode()) — byte array literal ────────────
    bytes_lit = re.search(r'(?:bytes|bytearray)\(\s*\[([0-9,\s]{8,})\]\s*\)', text_stripped)
    if bytes_lit:
        try:
            nums = [int(x.strip()) for x in bytes_lit.group(1).split(',') if x.strip().isdigit()]
            if nums:
                result = bytes(nums).decode('utf-8', errors='replace')
                if looks_readable(result, 0.60):
                    return result, 'Byte Array Literal', 'bytes([N,N,...]) → plaintext', None
        except Exception:
            pass

    # ── 0f. exec(__import__('zlib').decompress(__import__('base64').b64decode(...))) ──
    inline_zlib_b64 = re.search(
        r"__import__\(['\"]zlib['\"]\)\.decompress\s*\(\s*__import__\(['\"]base64['\"]\)\.b64decode\s*\(b?['\"]([A-Za-z0-9+/=\r\n]{20,})['\"]",
        text_stripped
    )
    if inline_zlib_b64:
        try:
            raw = base64.b64decode(re.sub(r'[\r\n\s]', '', inline_zlib_b64.group(1)))
            result = try_decode_bytes(zlib.decompress(raw))
            if looks_readable(result, 0.60):
                return result, 'Inline Import Obfuscator', '__import__(zlib+base64) → plaintext', None
        except Exception:
            pass
    inline_b64_zlib = re.search(
        r"__import__\(['\"]base64['\"]\)\.b64decode\s*\(\s*__import__\(['\"]zlib['\"]\)\.decompress\s*\(b?['\"]([^'\"]{20,})['\"]",
        text_stripped
    )
    if inline_b64_zlib:
        try:
            raw = base64.b64decode(re.sub(r'[\r\n\s]', '', inline_b64_zlib.group(1)))
            result = try_decode_bytes(zlib.decompress(raw))
            if looks_readable(result, 0.60):
                return result, 'Inline Import Obfuscator', '__import__(base64+zlib) → plaintext', None
        except Exception:
            pass

    # ── 1. XOR + Base64 (key variable present) ─────────────────────────────
    key_match = re.search(r'\b\w+\s*=\s*["\']([^"\']{1,64})["\']', text_stripped)
    b64_match = re.search(
        r'(?:base64\.b64decode|onfr64\.o64qrpbqr)\([b]?["\']([A-Za-z0-9+/=\r\n]{20,})',
        text_stripped
    )
    if key_match and b64_match:
        key = key_match.group(1)
        b64_data = re.sub(r'[\r\n\s"\')\s]', '', b64_match.group(1))
        padding_needed = (-len(b64_data)) % 4
        was_truncated = padding_needed > 0
        b64_data += '=' * padding_needed
        try:
            encrypted = base64.b64decode(b64_data)
            decrypted = bytes(b ^ ord(key[i % len(key)]) for i, b in enumerate(encrypted))
            result = try_decode_bytes(decrypted)
            if looks_readable(result, 0.70):
                warn = _check_truncation(result, was_truncated)
                return result, 'XOR + Base64', f'Key: "{key}"', warn
            try:
                result2 = try_decode_bytes(zlib.decompress(decrypted))
                if looks_readable(result2, 0.65):
                    warn = _check_truncation(result2, was_truncated)
                    return result2, 'XOR + Base64 + Zlib', f'Key: "{key}"', warn
            except Exception:
                pass
            try:
                result2 = try_decode_bytes(bz2.decompress(decrypted))
                if looks_readable(result2, 0.65):
                    warn = _check_truncation(result2, was_truncated)
                    return result2, 'XOR + Base64 + Bzip2', f'Key: "{key}"', warn
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
                    return result, 'Obfuscated Python', 'exec(base64.b64decode(...))', None
            except Exception:
                pass

    # ── 2b. exec(bytes.fromhex('...').decode()) ─────────────────────────────
    fromhex_m = re.search(r"bytes\.fromhex\(['\"]([0-9A-Fa-f\s]{8,})['\"]", text_stripped)
    if fromhex_m:
        try:
            result = try_decode_bytes(bytes.fromhex(re.sub(r'\s', '', fromhex_m.group(1))))
            if looks_readable(result, 0.60):
                return result, 'Hex Exec', 'bytes.fromhex() → plaintext Python', None
        except Exception:
            pass

    # ── 2c. Base64 URL-safe ──────────────────────────────────────────────────
    urlsafe_m = re.search(r"urlsafe_b64decode\(b?['\"]([A-Za-z0-9_\-=\r\n]{8,})['\"]", text_stripped)
    if urlsafe_m:
        try:
            result = try_decode_bytes(base64.urlsafe_b64decode(urlsafe_m.group(1) + '=='))
            if looks_readable(result, 0.60):
                return result, 'Base64 URL-safe', 'urlsafe_b64decode → plaintext', None
        except Exception:
            pass
    if '_' in b64_clean or '-' in b64_clean:
        if re.fullmatch(r'[A-Za-z0-9_\-=]+', b64_clean) and len(b64_clean) >= 8:
            try:
                result = try_decode_bytes(base64.urlsafe_b64decode(b64_clean + '=='))
                if looks_readable(result):
                    return result, 'Base64 URL-safe', 'URL-safe Base64', None
            except Exception:
                pass

    # ── 2d. Base32 ───────────────────────────────────────────────────────────
    b32_m = re.search(r"b32decode\(b?['\"]([A-Z2-7=\r\n\s]{8,})['\"]", text_stripped)
    if b32_m:
        try:
            padded = re.sub(r'[\r\n\s]', '', b32_m.group(1))
            padded += '=' * ((-len(padded)) % 8)
            result = try_decode_bytes(base64.b32decode(padded))
            if looks_readable(result, 0.60):
                return result, 'Base32', 'b32decode → plaintext', None
        except Exception:
            pass
    b32_clean = re.sub(r'[\r\n\s=]', '', text_stripped).upper()
    if re.fullmatch(r'[A-Z2-7]+', b32_clean) and len(b32_clean) >= 8:
        try:
            padded = b32_clean + '=' * ((-len(b32_clean)) % 8)
            result = try_decode_bytes(base64.b32decode(padded))
            if looks_readable(result):
                return result, 'Base32', 'Standard Base32', None
        except Exception:
            pass

    # ── 2e. Base85 / ASCII85 ─────────────────────────────────────────────────
    b85_m = re.search(r"b85decode\(b?['\"]([!-u]{8,})['\"]", text_stripped)
    if b85_m:
        try:
            result = try_decode_bytes(base64.b85decode(b85_m.group(1)))
            if looks_readable(result, 0.60):
                return result, 'Base85', 'b85decode → plaintext', None
        except Exception:
            pass
    a85_m = re.search(r"a85decode\(b?['\"](.{8,})['\"]", text_stripped)
    if a85_m:
        try:
            result = try_decode_bytes(base64.a85decode(a85_m.group(1).encode()))
            if looks_readable(result, 0.60):
                return result, 'ASCII85', 'a85decode → plaintext', None
        except Exception:
            pass

    # ── 3. URL encoded (%XX) ────────────────────────────────────────────────
    if '%' in text_stripped and re.search(r'%[0-9A-Fa-f]{2}', text_stripped):
        try:
            result = urllib.parse.unquote_plus(text_stripped)
            if result != text_stripped and looks_readable(result):
                return result, 'URL Encoding', '%XX percent-encoded', None
        except Exception:
            pass

    # ── 4. Pure Hex string ──────────────────────────────────────────────────
    hex_clean = re.sub(r'(?:0x|\\x|\s)', '', text_stripped)
    if re.fullmatch(r'[0-9A-Fa-f]+', hex_clean) and len(hex_clean) % 2 == 0 and len(hex_clean) >= 4:
        try:
            result = try_decode_bytes(bytes.fromhex(hex_clean))
            if looks_readable(result):
                return result, 'Hexadecimal', 'Hex-encoded bytes', None
        except Exception:
            pass

    # ── 5. Plain Base64 ─────────────────────────────────────────────────────
    b64_clean = re.sub(r'[\r\n\s]', '', text_stripped)
    if re.fullmatch(r'[A-Za-z0-9+/=]+', b64_clean) and len(b64_clean) >= 4:
        try:
            decoded_bytes = base64.b64decode(b64_clean)
            result = try_decode_bytes(decoded_bytes)
            if looks_readable(result):
                return result, 'Base64', 'Standard Base64', None
        except Exception:
            pass

    # ── 6. Base64 → Zlib ────────────────────────────────────────────────────
    try:
        decoded_bytes = base64.b64decode(b64_clean)
        result = try_decode_bytes(zlib.decompress(decoded_bytes))
        if looks_readable(result):
            return result, 'Base64 + Zlib', 'Zlib-compressed, Base64-encoded', None
    except Exception:
        pass

    try:
        result = try_decode_bytes(zlib.decompress(text_stripped.encode('latin-1')))
        if looks_readable(result):
            return result, 'Zlib', 'Raw Zlib stream', None
    except Exception:
        pass

    # ── 7. Base64 → Bzip2 ───────────────────────────────────────────────────
    try:
        decoded_bytes = base64.b64decode(b64_clean)
        result = try_decode_bytes(bz2.decompress(decoded_bytes))
        if looks_readable(result):
            return result, 'Base64 + Bzip2', 'Bzip2-compressed, Base64-encoded', None
    except Exception:
        pass

    try:
        result = try_decode_bytes(bz2.decompress(text_stripped.encode('latin-1')))
        if looks_readable(result):
            return result, 'Bzip2', 'Raw Bzip2 stream', None
    except Exception:
        pass

    # ── 8. ROT13 ────────────────────────────────────────────────────────────
    try:
        result = codecs.decode(text_stripped, 'rot_13')
        if looks_readable(result) and result != text_stripped:
            if re.search(r'\b[a-zA-Z]{3,}\b', result):
                return result, 'ROT13', 'Caesar rotation (13)', None
    except Exception:
        pass

    # ── 8b. ROT47 ────────────────────────────────────────────────────────────
    # Rotates all printable ASCII characters (33–126) by 47
    try:
        rot47 = ''.join(
            chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
            for c in text_stripped
        )
        if rot47 != text_stripped and looks_readable(rot47):
            if re.search(r'\b(?:import|def |class |print|exec|eval|if |for |while |return)\b', rot47):
                return rot47, 'ROT47', 'Printable ASCII rotation (47)', None
    except Exception:
        pass

    # ── 8c. Caesar cipher — brute-force shifts 1–25 ──────────────────────────
    if re.fullmatch(r'[A-Za-z\s\.,!?\'";\:\-\(\)]+', text_stripped) and len(text_stripped) >= 20:
        common = set('etaoinshrdlucmfywgpbvkxjqz')
        best_result, best_score, best_shift = None, 0, 0
        for shift in range(1, 26):
            candidate = ''.join(
                chr((ord(c) - (65 if c.isupper() else 97) + shift) % 26 + (65 if c.isupper() else 97))
                if c.isalpha() else c
                for c in text_stripped
            )
            words = re.findall(r'[a-z]{2,}', candidate.lower())
            score = sum(1 for w in words for l in w[:3] if l in common) / max(len(words) * 3, 1)
            if score > best_score:
                best_score, best_result, best_shift = score, candidate, shift
        if best_score > 0.55 and best_result:
            return best_result, 'Caesar Cipher', f'Shift: {best_shift}', None

    # ── 9. Unicode escape (\uXXXX or \xXX mixed) ───────────────────────────
    if r'\u' in text_stripped or r'\x' in text_stripped:
        try:
            result = text_stripped.encode('raw_unicode_escape').decode('unicode_escape')
            if looks_readable(result) and result != text_stripped:
                return result, 'Unicode Escape', r'\\uXXXX / \xXX escape sequences', None
        except Exception:
            pass

    # ── 9b. Binary string (space/newline-separated 8-bit groups) ────────────
    bin_tokens = re.findall(r'[01]{8}', re.sub(r'[,\s_]+', ' ', text_stripped))
    if len(bin_tokens) >= 4 and len(bin_tokens) * 8 >= len(re.sub(r'\s', '', text_stripped)) * 0.7:
        try:
            result = ''.join(chr(int(t, 2)) for t in bin_tokens)
            if looks_readable(result, 0.60):
                return result, 'Binary', '8-bit binary groups → text', None
        except Exception:
            pass

    # ── 9c. Codecs zlib_codec / bz2_codec exec wrappers ─────────────────────
    codecs_zlib = re.search(
        r"codecs\.decode\(b?['\"]([^'\"]{10,})['\"],\s*['\"](?:zlib_codec|zip)['\"]",
        text_stripped
    )
    if codecs_zlib:
        try:
            result = try_decode_bytes(zlib.decompress(codecs_zlib.group(1).encode('latin-1')))
            if looks_readable(result, 0.60):
                return result, 'Codecs Zlib', 'codecs.decode(zlib_codec) → plaintext', None
        except Exception:
            pass
    codecs_bz2 = re.search(
        r"codecs\.decode\(b?['\"]([^'\"]{10,})['\"],\s*['\"]bz2_codec['\"]",
        text_stripped
    )
    if codecs_bz2:
        try:
            result = try_decode_bytes(bz2.decompress(codecs_bz2.group(1).encode('latin-1')))
            if looks_readable(result, 0.60):
                return result, 'Codecs Bzip2', 'codecs.decode(bz2_codec) → plaintext', None
        except Exception:
            pass

    # ── 9d. Octal escape sequences (\NNN) ───────────────────────────────────
    if re.search(r'\\[0-7]{3}', text_stripped):
        try:
            result = bytes(text_stripped, 'utf-8').decode('unicode_escape')
            if looks_readable(result) and result != text_stripped:
                return result, 'Octal Escape', r'\NNN octal sequences → text', None
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
                return result, 'ANSI Escape Codes', f'{len(codes_found)} escape sequence(s) decoded', None

    # ── 11. Last resort: try base64 even if not perfectly clean ─────────────
    try:
        aggressive_clean = re.sub(r'[^A-Za-z0-9+/=]', '', text_stripped)
        if len(aggressive_clean) >= 8:
            result = try_decode_bytes(base64.b64decode(aggressive_clean + '=='))
            if looks_readable(result, 0.65):
                return result, 'Base64', 'Base64 (cleaned input)', None
    except Exception:
        pass

    return None, None, None, None


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
            result, detected_type, detected_detail, truncation_warning = auto_detect_and_decode(current)
            if result is None:
                break
            layers.append({
                "result": result,
                "detected_type": detected_type,
                "detected_detail": detected_detail,
                "truncation_warning": truncation_warning,
            })
            current = result

        if not layers:
            return jsonify({"error": "Could not detect encoding type. Input may be custom-encrypted or unknown format."}), 400

        final = layers[-1]
        return jsonify({
            "result": final["result"],
            "detected_type": final["detected_type"],
            "detected_detail": final["detected_detail"],
            "truncation_warning": final.get("truncation_warning"),
            "layers": layers,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
