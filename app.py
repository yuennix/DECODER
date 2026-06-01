import base64
import codecs
import binascii
import zlib
import bz2
import re
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.json.ensure_ascii = False

def extract_b64_from_obfuscated(text):
    patterns = [
        r"base64\.b64decode\(b['\"]([A-Za-z0-9+/=]+)['\"]",
        r"base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/decode", methods=["POST"])
def decode():
    data = request.get_json()
    decode_type = data.get("type", "")
    encoded = data.get("input", "").strip()
    auto_extracted = False

    try:
        if decode_type == "base64":
            extracted = extract_b64_from_obfuscated(encoded)
            if extracted:
                encoded = extracted
                auto_extracted = True
            decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")

        elif decode_type == "url":
            decoded = codecs.decode(encoded.replace("+", " "), "unicode_escape")

        elif decode_type == "hex":
            decoded = binascii.unhexlify(encoded).decode("utf-8", errors="replace")

        elif decode_type == "zlib":
            decoded = zlib.decompress(base64.b64decode(encoded)).decode("utf-8", errors="replace")

        elif decode_type == "bzip2":
            decoded = bz2.decompress(base64.b64decode(encoded)).decode("utf-8", errors="replace")

        else:
            return jsonify({"error": "Invalid decode type"}), 400

        return jsonify({"result": decoded, "auto_extracted": auto_extracted})

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
