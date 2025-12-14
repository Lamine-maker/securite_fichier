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

@app.route("/api/encrypt", methods=["POST"])
def encrypt_file():
    try:
        uploaded_file = request.files.get("file")
        algo = (request.form.get("algo") or "des").lower()
        mode = (request.form.get("mode") or "ECB").upper()
        key_text = request.form.get("key", "")
        key = key_text.encode()

        if not uploaded_file:
            return jsonify({"error": "Aucun fichier envoyé"}), 400

        data = uploaded_file.read()
        logging.debug(f"Encrypt {algo} {mode} key_len={len(key)} file_len={len(data)}")

        if algo == "des":
            if len(key) != 8:
                return jsonify({"error": "Clé DES doit être 8 caractères"}), 400
            ciphertext = des_crypto.encrypt_data(data, key, mode)
        elif algo == "aes":
            if len(key) not in (16, 24, 32):
                return jsonify({"error": "Clé AES doit être 16, 24 ou 32 caractères"}), 400
            ciphertext = aes.encrypt_data(data, key, mode)
        else:
            return jsonify({"error": "Algorithme invalide"}), 400

        ext = f"_{algo}_encrypted.bin"
        download_name = os.path.splitext(uploaded_file.filename)[0] + ext
        return _prepare_file_response(ciphertext, download_name)

    except Exception as e:
        logging.exception("Encryption failed")
        return jsonify({"error": str(e)}), 500

@app.route("/api/decrypt", methods=["POST"])
def decrypt_file():
    try:
        uploaded_file = request.files.get("file")
        algo = (request.form.get("algo") or "des").lower()
        mode = (request.form.get("mode") or "ECB").upper()
        key_text = request.form.get("key", "")
        key = key_text.encode()

        if not uploaded_file:
            return jsonify({"error": "Aucun fichier envoyé"}), 400

        data = uploaded_file.read()
        logging.debug(f"Decrypt {algo} {mode} key_len={len(key)} file_len={len(data)}")

        if algo == "des":
            if len(key) != 8:
                return jsonify({"error": "Clé DES doit être 8 caractères"}), 400
            plaintext = des_crypto.decrypt_data(data, key, mode)
        elif algo == "aes":
            if len(key) not in (16, 24, 32):
                return jsonify({"error": "Clé AES doit être 16, 24 ou 32 caractères"}), 400
            plaintext = aes.decrypt_data(data, key, mode)
        else:
            return jsonify({"error": "Algorithme invalide"}), 400

        ext = f"_{algo}_decrypted.bin"
        download_name = os.path.splitext(uploaded_file.filename)[0] + ext
        return _prepare_file_response(plaintext, download_name)

    except Exception as e:
        logging.exception("Decryption failed")
        return jsonify({"error": str(e)}), 500

# serve static
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=True)
