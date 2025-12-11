// static/script.js
// Assumes the index.html you validated (mode radio, ivDisplay, progress bar, history list)
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
const ivSection = document.getElementById("ivSection");
const ivDisplay = document.getElementById("ivDisplay");
const progressContainer = document.getElementById("progressContainer");
const progressBar = document.querySelector("#progressBar span");
const historyList = document.getElementById("historyList");
const resultInfo = document.getElementById("resultInfo");

// helper to get selected mode (radio)
function getSelectedMode() {
    const radios = document.getElementsByName("mode");
    for (const r of radios) if (r.checked) return r.value;
    return "ECB";
}

// show/hide iv display depending on mode
function updateIvUI() {
    const mode = getSelectedMode();
    if (mode === "CFB") {
        ivSection.classList.remove("hidden");
    } else {
        ivSection.classList.add("hidden");
        ivDisplay.value = "";
    }
}
document.querySelectorAll('input[name="mode"]').forEach(r => r.addEventListener('change', updateIvUI));
updateIvUI();

// progress visual (fake while uploading, improves UX)
function setProgress(pct) {
    progressContainer.classList.remove("hidden");
    progressBar.style.width = pct + "%";
}

// append to history
function addHistory(entry) {
    const li = document.createElement("li");
    li.textContent = entry;
    historyList.insertBefore(li, historyList.firstChild);
}

// send file (encrypt or decrypt)
async function sendFile(endpoint) {
    const file = fileInput.files[0];
    const key = keyInput.value;
    const mode = getSelectedMode();
    const algo = "des"; // current UI uses DES; server accepts 'algo' if you want to expand later

    if (!file) {
        statusEl.textContent = "⚠️ Veuillez choisir un fichier.";
        return;
    }
    if (algo === "des" && key.length !== 8) {
        statusEl.textContent = "⚠️ La clé DES doit contenir exactement 8 caractères.";
        return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("key", key);
    formData.append("mode", mode);
    formData.append("algo", algo);

    statusEl.textContent = "⏳ Envoi du fichier au serveur...";
    downloadSection.classList.add("hidden");
    resultInfo.innerHTML = "";
    setProgress(10);

    try {
        // fetch with progress - browsers don't expose upload progress via fetch easily,
        // so we fake a few steps to show progress to user, then finalize when done.
        setProgress(30);
        const res = await fetch(`${API_BASE}/${endpoint}`, {
            method: "POST",
            body: formData
        });
        setProgress(60);
        if (!res.ok) {
            const txt = await res.json().catch(()=>null);
            throw new Error(txt && txt.error ? txt.error : ("Erreur du serveur (" + res.status + ")"));
        }

        // read headers for metadata
        const modeHeader = res.headers.get("X-Mode") || mode;
        const ivHex = res.headers.get("X-IV") || "";
        const algoHeader = res.headers.get("X-Algorithm") || algo.toUpperCase();
        const sizeHeader = res.headers.get("X-Size") || "";

        const blob = await res.blob();
        setProgress(90);

        const url = URL.createObjectURL(blob);
        const originalName = file.name.split(".")[0];
        let filename;
        if (endpoint === "encrypt") {
            filename = `${originalName}_${algo}_encrypted.bin`;
        } else {
            filename = `${originalName}_${algo}_decrypted.bin`;
        }

        downloadLink.href = url;
        downloadLink.download = filename;
        downloadSection.classList.remove("hidden");

        statusEl.textContent = "✅ Succès ! Téléchargez le fichier ci-dessous.";
        setProgress(100);
        setTimeout(()=> {
            progressContainer.classList.add("hidden");
            progressBar.style.width = "0%";
        }, 800);

        // show result info
        let infoHtml = `<strong>Algorithme:</strong> ${algoHeader} <br>`;
        infoHtml += `<strong>Mode:</strong> ${modeHeader} <br>`;
        if (ivHex) {
            // format IV as spaced hex
            const ivSpaced = ivHex.match(/.{1,2}/g)?.join(" ") || ivHex;
            infoHtml += `<strong>IV:</strong> ${ivSpaced} <br>`;
            ivDisplay.value = ivSpaced;
        } else {
            ivDisplay.value = "";
        }
        if (sizeHeader) infoHtml += `<strong>Taille (octets):</strong> ${sizeHeader} <br>`;
        resultInfo.innerHTML = infoHtml;

        // add to history
        const hist = `${filename} — ${modeHeader} — ${new Date().toLocaleString()}`;
        addHistory(hist);

    } catch (err) {
        console.error(err);
        statusEl.textContent = "❌ Erreur : " + err.message;
        progressContainer.classList.add("hidden");
        progressBar.style.width = "0%";
    }
}

encryptBtn.addEventListener("click", () => sendFile("encrypt"));
decryptBtn.addEventListener("click", () => sendFile("decrypt"));
