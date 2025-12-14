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

# --- CONFIGURATION UPLOAD ---
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

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
    file = request.files.get("file")
    action = request.form.get("action")
    algorithm = request.form.get("algorithm")
    mode = request.form.get("mode")
    key = request.form.get("key").encode()

    if not file:
        return "Aucun fichier envoyé", 400

    input_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)

    # Déterminer le nom de sortie selon l'action
    if action == "encrypt":
        output_filename = file.filename + ".out"
    else:  # decrypt
        if file.filename.endswith(".out"):
            output_filename = file.filename[:-4]  # enlever .out
        else:
            output_filename = "decrypted_" + file.filename

    output_path = os.path.join(app.config["UPLOAD_FOLDER"], output_filename)

    file.save(input_path)

    # Lecture des données
    with open(input_path, "rb") as f:
        file_data = f.read()

    # Traitement AES ou DES
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

    # Écriture du résultat dans le fichier de sortie
    with open(output_path, "wb") as f:
        f.write(result_bytes)

    return send_file(output_path, as_attachment=True)

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=True)
