const fileInput = document.getElementById("file");
const passwordInput = document.getElementById("password");
const algoSelect = document.getElementById("algo");
const modeSelect = document.getElementById("mode");

function showError(msg) {
    alert("❌ " + msg);
}

function showSuccess(msg) {
    alert("✅ " + msg);
}

async function send(action) {
    const file = fileInput.files[0];
    const password = passwordInput.value.trim();
    const algo = algoSelect.value;
    const mode = modeSelect.value;

    // 🔎 Vérifications côté client
    if (!file) {
        showError("Veuillez sélectionner un fichier");
        return;
    }

    if (!password) {
        showError("Le mot de passe est obligatoire");
        return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("password", password);
    formData.append("algo", algo);
    formData.append("mode", mode);
    formData.append("action", action);

    try {
        const response = await fetch("/process", {
            method: "POST",
            body: formData
        });

        // 🚨 Erreur serveur
        if (!response.ok) {
            const text = await response.text();
            throw new Error(text || "Erreur serveur");
        }

        const blob = await response.blob();

        // 📥 Téléchargement
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;

        // Nom de fichier logique
        if (action === "encrypt") {
            a.download = file.name + ".bin";
        } else {
            a.download = file.name.replace(/\.bin$/, "");
        }

        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);

        showSuccess(action === "encrypt"
            ? "Fichier chiffré avec succès"
            : "Fichier déchiffré avec succès");

    } catch (err) {
        showError(err.message);
    }
}
