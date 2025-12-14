document.addEventListener("DOMContentLoaded", function () {

    const form = document.querySelector("form");
    const algorithm = document.querySelector("select[name='algorithm']");
    const keyInput = document.querySelector("input[name='key']");
    const progressBar = document.querySelector("#progressBar span");
    const status = document.querySelector("#status");
    const downloadLink = document.querySelector("#downloadLink");
    const historyList = document.querySelector("#historyList");
    const fileInput = document.getElementById("fileInput");
    const fileLabel = document.getElementById("fileLabel");

    // Historique en mémoire
    let history = [];

    // Validation du formulaire
    form.addEventListener("submit", function (event) {
        event.preventDefault();

        if (fileInput.files.length === 0) {
            alert("Veuillez sélectionner un fichier.");
            return;
        }

        if (algorithm.value === "AES" && keyInput.value.length < 16) {
            alert("La clé AES doit contenir au moins 16 caractères.");
            return;
        }

        if (algorithm.value === "DES" && keyInput.value.length < 8) {
            alert("La clé DES doit contenir au moins 8 caractères.");
            return;
        }

        // Préparation des données
        const formData = new FormData(form);
        const fileName = fileInput.files[0].name;
        const action = form.querySelector("select[name='action']").value;

        // Réinitialiser barre de progression
        progressBar.style.width = "0%";
        status.textContent = `${action === "encrypt" ? "Chiffrement" : "Déchiffrement"} en cours...`;
        downloadLink.classList.add("hidden");

        // Simulation barre de progression (pour feedback instantané)
        let progress = 0;
        const interval = setInterval(() => {
            if (progress < 90) {
                progress += Math.random() * 10; // augmente aléatoirement
                progressBar.style.width = progress + "%";
            }
        }, 200);

        // Envoi AJAX
        fetch("/process", {
            method: "POST",
            body: formData
        })
        .then(response => {
            clearInterval(interval);
            progressBar.style.width = "100%";
            status.textContent = "Terminé !";

            return response.blob();
        })
        .then(blob => {
            // Création du lien de téléchargement
            const url = URL.createObjectURL(blob);
            downloadLink.href = url;

            // Détection du nom original
            const originalFileName = fileName.endsWith(".out") && form.querySelector("select[name='action']").value === "decrypt"
                ? fileName.slice(0, -4)
                : (form.querySelector("select[name='action']").value === "encrypt" ? fileName + ".out" : fileName);

            downloadLink.download = originalFileName;
            downloadLink.textContent = `Télécharger ${originalFileName}`;
            downloadLink.classList.remove("hidden");

            // Ajouter à l'historique
            history.push({
                name: originalFileName,
                action: form.querySelector("select[name='action']").value
            });

            renderHistory();
        })
        .catch(err => {
            clearInterval(interval);
            progressBar.style.width = "0%";
            status.textContent = "Erreur lors du traitement.";
            console.error(err);
        });
    });

    // Changement de placeholder selon l'algorithme
    algorithm.addEventListener("change", function () {
        if (this.value === "AES") {
            keyInput.placeholder = "Clé AES (≥ 16 caractères)";
        } else {
            keyInput.placeholder = "Clé DES (≥ 8 caractères)";
        }
    });

    // Affichage de l'historique
    function renderHistory() {
        historyList.innerHTML = "";
        history.slice().reverse().forEach(entry => {
            const li = document.createElement("li");
            li.textContent = `${entry.action === "encrypt" ? "Chiffré" : "Déchiffré"} : ${entry.name}`;
            historyList.appendChild(li);
        });
    }

    fileInput.addEventListener("change", function () {
        if (this.files && this.files.length > 0) {
            fileLabel.textContent = this.files[0].name;
        } else {
            fileLabel.textContent = "Choisir un fichier";
        }
    });

});
