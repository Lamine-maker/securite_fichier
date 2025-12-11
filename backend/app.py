# app.py
from flask import Flask, request, send_file, jsonify, render_template, send_from_directory
from flask_cors import CORS
from io import BytesIO
import os

# Import both moteurs
import des_crypto
import aes

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# === FRONT ===
@app.route('/')
def index():
    return render_template('index.html')

# === API ===
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

        # Validate algo & mode & key
        if algo not in ("des", "aes"):
            return jsonify({"error": "Algo invalide (des ou aes attendu)"}), 400
        if mode not in ("ECB", "CFB"):
            return jsonify({"error": "Mode invalide (ECB ou CFB attendu)"}), 400

        data = uploaded_file.read()

        # Perform encryption
        if algo == "des":
            if len(key) != 8:
                return jsonify({"error": "La clé DES doit contenir exactement 8 caractères (8 octets)."}), 400
            # DES: ECB returns raw ciphertext; CFB returns IV||ciphertext
            encrypted_data = des_crypto.encrypt_data(data, key, mode=mode)
            ext = "_encrypted_des.bin"
        else:  # aes
            if len(key) not in (16, 24, 32):
                return jsonify({"error": "La clé AES doit contenir 16, 24 ou 32 caractères."}), 400
            encrypted_data = aes.encrypt_data(data, key, mode=mode)
            ext = "_encrypted_aes.bin"

        output = BytesIO(encrypted_data)
        original_name = os.path.splitext(uploaded_file.filename)[0]
        output_filename = f"{original_name}{ext}"

        return send_file(
            output,
            as_attachment=True,
            download_name=output_filename,
            mimetype="application/octet-stream"
        )

    except Exception as e:
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

        if algo not in ("des", "aes"):
            return jsonify({"error": "Algo invalide (des ou aes attendu)"}), 400
        if mode not in ("ECB", "CFB"):
            return jsonify({"error": "Mode invalide (ECB ou CFB attendu)"}), 400

        data = uploaded_file.read()

        if algo == "des":
            if len(key) != 8:
                return jsonify({"error": "La clé DES doit contenir exactement 8 caractères (8 octets)."}), 400
            decrypted = des_crypto.decrypt_data(data, key, mode=mode)
            # Name: keep generic .bin or try to guess .docx if you prefer
            ext = "_decrypted.bin"
        else:
            if len(key) not in (16, 24, 32):
                return jsonify({"error": "La clé AES doit contenir 16, 24 ou 32 caractères."}), 400
            decrypted = aes.decrypt_data(data, key, mode=mode)
            ext = "_decrypted.bin"

        output = BytesIO(decrypted)
        original_name = os.path.splitext(uploaded_file.filename)[0]
        output_filename = f"{original_name}{ext}"

        return send_file(
            output,
            as_attachment=True,
            download_name=output_filename,
            mimetype="application/octet-stream"
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Static files route
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
