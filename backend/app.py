from flask import Flask, request, send_file, jsonify, render_template, send_from_directory
from flask_cors import CORS
from des_crypto import encrypt_data, decrypt_data
from io import BytesIO
import os

# Initialisation de l'app Flask
app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# === ROUTE FRONTEND ===
@app.route('/')
def index():
    """Affiche la page d'accueil (frontend)."""
    return render_template('index.html')

# === ROUTES BACKEND (API) ===
@app.route("/api/encrypt", methods=["POST"])
def encrypt_file():
    try:
        uploaded_file = request.files.get("file")
        key = request.form.get("key", "").encode()

        if not uploaded_file:
            return jsonify({"error": "Aucun fichier envoyé"}), 400
        if len(key) != 8:
            return jsonify({"error": "La clé doit contenir exactement 8 octets"}), 400

        data = uploaded_file.read()
        encrypted_data = encrypt_data(data, key)

        output = BytesIO(encrypted_data)
        output_filename = f"{os.path.splitext(uploaded_file.filename)[0]}_encrypted.bin"

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
        key = request.form.get("key", "").encode()

        if not uploaded_file:
            return jsonify({"error": "Aucun fichier envoyé"}), 400
        if len(key) != 8:
            return jsonify({"error": "La clé doit contenir exactement 8 octets"}), 400

        data = uploaded_file.read()
        decrypted_data = decrypt_data(data, key)

        output = BytesIO(decrypted_data)
        output_filename = f"{os.path.splitext(uploaded_file.filename)[0]}_decrypted.docx"

        return send_file(
            output,
            as_attachment=True,
            download_name=output_filename,
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# === ROUTE DE SECOURS POUR SERVIR LES FICHIERS STATIQUES ===
@app.route('/<path:filename>')
def serve_static(filename):
    """Permet de servir style.css, script.js, etc."""
    return send_from_directory(app.static_folder, filename)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
