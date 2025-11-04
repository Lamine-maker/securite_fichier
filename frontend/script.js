const API_BASE = "http://127.0.0.1:5000";

const fileInput = document.getElementById("fileInput");
const keyInput = document.getElementById("keyInput");
const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");
const statusEl = document.getElementById("status");
const downloadLink = document.getElementById("downloadLink");
const downloadSection = document.getElementById("downloadSection");

function sendFile(endpoint) {
    const file = fileInput.files[0];
    const key = keyInput.value;

    if (!file) {
        statusEl.textContent = "Veuillez choisir un fichier.";
        return;
    }
    if (key.length !== 8) {
        statusEl.textContent = "La clé doit contenir exactement 8 caractères.";
        return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("key", key);

    statusEl.textContent = "Envoi du fichier...";
    fetch(`${API_BASE}/${endpoint}`, {
        method: "POST",
        body: formData
    })
        .then((res) => {
            if (!res.ok) throw new Error("Erreur du serveur");
                return res.blob();
        })
        .then((blob) => {
            const url = URL.createObjectURL(blob);
            downloadLink.href = url;
            downloadLink.download = endpoint === "encrypt" ? "fichier_chiffre.bin" : "fichier_dechiffre.docx";
            downloadSection.classList.remove("hidden");
            statusEl.textContent = "Succès ! Téléchargez le fichier ci-dessous.";
        })
    .catch((err) => {
        statusEl.textContent = "Erreur : " + err.message;
    });
}

encryptBtn.addEventListener("click", () => sendFile("encrypt"));
decryptBtn.addEventListener("click", () => sendFile("decrypt"));
