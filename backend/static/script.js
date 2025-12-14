document.addEventListener("DOMContentLoaded", function () {

    const form = document.querySelector("form");
    const algorithm = document.querySelector("select[name='algorithm']");
    const keyInput = document.querySelector("input[name='key']");
    const fileInput = document.querySelector("input[type='file']");

    form.addEventListener("submit", function (event) {

        if (fileInput.files.length === 0) {
            alert("Veuillez sélectionner un fichier.");
            event.preventDefault();
            return;
        }

        if (algorithm.value === "AES" && keyInput.value.length < 16) {
            alert("La clé AES doit contenir au moins 16 caractères.");
            event.preventDefault();
            return;
        }

        if (algorithm.value === "DES" && keyInput.value.length < 8) {
            alert("La clé DES doit contenir au moins 8 caractères.");
            event.preventDefault();
            return;
        }
    });

    algorithm.addEventListener("change", function () {
        if (this.value === "AES") {
            keyInput.placeholder = "Clé AES (≥ 16 caractères)";
        } else {
            keyInput.placeholder = "Clé DES (≥ 8 caractères)";
        }
    });
});
