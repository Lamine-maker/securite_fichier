# app.py
from flask import Flask, request, send_file, jsonify, render_template, send_from_directory, make_response
from flask_cors import CORS
from io import BytesIO
import os
import des_crypto
import aes
import logging

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

MAGIC = b"CRYP"

ALGOS = {
    "aes": 0x01,
    "des": 0x02
}

MODES = {
    "ECB": 0x01,
    "CFB": 0x02
}

ALGOS_REV = {v: k for k, v in ALGOS.items()}
MODES_REV = {v: k for k, v in MODES.items()}

# Logging to console
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

def _prepare_file_response(data_bytes: bytes, download_name: str):
    bio = BytesIO(data_bytes)
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=download_name, mimetype="application/octet-stream")

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/process", methods=["POST"])
def process():
    action = request.form.get("action")
    algo = request.form.get("algo")
    mode = request.form.get("mode")
    password = request.form.get("password", "").encode()
    uploaded_file = request.files.get("file")

    if not uploaded_file:
        return "Aucun fichier", 400

    if action == "encrypt":
        data = uploaded_file.read()
        filename = uploaded_file.filename.encode()

        # --- CHIFFREMENT ---
        if algo == "aes":
            ciphertext, iv = aes.encrypt_data(data, password, mode)
        else:
            ciphertext, iv = des_crypto.encrypt_data(data, password, mode)

        header = (
            MAGIC +
            struct.pack(
                "!BBB",
                ALGOS[algo],
                MODES[mode],
                len(iv)
            ) +
            iv +
            struct.pack("!H", len(filename)) +
            filename
        )

        out = header + ciphertext

        return send_file(
            BytesIO(out),
            as_attachment=True,
            download_name=uploaded_file.filename + ".bin",
            mimetype="application/octet-stream"
        )

    # --- DECHIFFREMENT ---
    raw = uploaded_file.read()

    if raw[:4] != MAGIC:
        return "Fichier non valide", 400

    algo_id, mode_id, iv_len = struct.unpack("!BBB", raw[4:7])
    pos = 7

    iv = raw[pos:pos + iv_len]
    pos += iv_len

    name_len = struct.unpack("!H", raw[pos:pos + 2])[0]
    pos += 2

    filename = raw[pos:pos + name_len].decode()
    pos += name_len

    ciphertext = raw[pos:]

    algo = ALGOS_REV[algo_id]
    mode = MODES_REV[mode_id]

    if algo == "aes":
        plaintext = aes.decrypt_data(ciphertext, password, mode, iv)
    else:
        plaintext = des_crypto.decrypt_data(ciphertext, password, mode, iv)

    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream"
    )


# serve static
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=True)
