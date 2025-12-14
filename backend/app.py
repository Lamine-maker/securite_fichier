# app.py corrigé
from flask import Flask, request, send_file, render_template
from flask_cors import CORS
from io import BytesIO
import os
import logging

from aes import aes_encrypt, aes_decrypt
from des import des_encrypt, des_decrypt

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# Configuration du dossier d’upload
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Logging vers la console
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/process", methods=["POST"])
def process():
    uploaded_file = request.files.get("file")
    action = request.form.get("action")      # encrypt / decrypt
    algorithm = request.form.get("algorithm")  # AES / DES
    mode = request.form.get("mode")          # ECB / CFB / etc.
    key = request.form.get("key").encode()

    if not uploaded_file:
        return "Aucun fichier envoyé", 400

    file_data = uploaded_file.read()

    # Chiffrement/Déchiffrement en mémoire
    if algorithm == "AES":
        if action == "encrypt":
            result_bytes = aes_encrypt(file_data, key, mode)
        else:
            result_bytes = aes_decrypt(file_data, key, mode)

    elif algorithm == "DES":
        if action == "encrypt":
            result_bytes = des_encrypt(file_data, key, mode)
        else:
            result_bytes = des_decrypt(file_data, key, mode)
    else:
        return "Algorithme inconnu", 400

    # Retourne le fichier directement depuis la mémoire
    return send_file(
        BytesIO(result_bytes),
        as_attachment=True,
        download_name=uploaded_file.filename + ".out",
        mimetype="application/octet-stream"
    )

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=True)
