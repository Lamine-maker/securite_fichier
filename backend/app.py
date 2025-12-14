# app.py
import struct
from flask import Flask, request, send_file, jsonify, render_template, send_from_directory, make_response
from flask_cors import CORS
from io import BytesIO
import os
from aes import aes_encrypt, aes_decrypt
from des import des_encrypt, des_decrypt
import logging

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# Configuration du dossier d’upload
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

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
    file = request.files.get("file")
    action = request.form.get("action")
    algorithm = request.form.get("algorithm")
    mode = request.form.get("mode")
    key = request.form.get("key").encode()

    input_path = os.path.join(UPLOAD_FOLDER, file.filename)
    output_path = input_path + ".out"

    file.save(input_path)

    if algorithm == "AES":
        if action == "encrypt":
            aes_encrypt(input_path, output_path, key, mode)
        else:
            aes_decrypt(input_path, output_path, key, mode)

    elif algorithm == "DES":
        if action == "encrypt":
            des_encrypt(input_path, output_path, key, mode)
        else:
            des_decrypt(input_path, output_path, key, mode)

    return send_file(output_path, as_attachment=True)


# serve static
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    app.run(host=host, port=port, debug=True)
