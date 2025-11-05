// 🔧 Détection automatique : local ou hébergé sur Render
const API_BASE =
    window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost"
        ? "http://127.0.0.1:5000/api"
        : `${window.location.origin}/api`;

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

    // 🧩 Vérifications utilisateur
    if (!file) {
        statusEl.textContent = "⚠️ Veuillez choisir un fichier à chiffrer ou déchiffrer.";
        return;
    }
    if (key.length !== 8) {
        statusEl.textContent = "⚠️ La clé doit contenir exactement 8 caractères.";
        return;
    }

    // 📨 Préparation des données à envoyer
    const formData = new FormData();
    formData.append("file", file);
    formData.append("key", key);

    statusEl.textContent = "⏳ Envoi du fichier au serveur...";
    downloadSection.classList.add("hidden");

    // 🔥 Envoi vers l'API Flask
    fetch(`${API_BASE}/${endpoint}`, {
        method: "POST",
        body: formData,
    })
        .then((res) => {
            if (!res.ok) throw new Error("Erreur du serveur (" + res.status + ")");
            return res.blob();
        })
        .then((blob) => {
            const url = URL.createObjectURL(blob);

            // 🔽 Prépare le lien de téléchargement
            const originalName = file.name.split(".")[0];
            const fileName =
                endpoint === "encrypt"
                    ? `${originalName}_encrypted.bin`
                    : `${originalName}_decrypted.docx`;

            downloadLink.href = url;
            downloadLink.download = fileName;
            downloadSection.classList.remove("hidden");

            statusEl.textContent = "✅ Succès ! Téléchargez le fichier ci-dessous.";
        })
        .catch((err) => {
            console.error(err);
            statusEl.textContent = "❌ Erreur : " + err.message;
        });
}

// 🎯 Boutons d’action
encryptBtn.addEventListener("click", () => sendFile("encrypt"));
decryptBtn.addEventListener("click", () => sendFile("decrypt"));
