const fileInput = document.getElementById("fileInput");
const keyInput = document.getElementById("keyInput");
const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");
const algoSelect = document.getElementById("algoSelect");
const statusEl = document.getElementById("status");
const downloadLink = document.getElementById("downloadLink");
const downloadSection = document.getElementById("downloadSection");

async function sendFile(endpoint){
    const file = fileInput.files[0];
    const key = keyInput.value;
    const algo = algoSelect.value;
    const mode = document.querySelector('input[name="mode"]:checked').value;

    if(!file){ statusEl.textContent="Choisir un fichier"; return; }

    if(algo==="des" && key.length!==8){ statusEl.textContent="Clé DES: 8 caractères"; return; }
    if(algo==="aes" && ![16,24,32].includes(key.length)){ statusEl.textContent="Clé AES: 16,24,32 caractères"; return; }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("key", key);
    formData.append("algo", algo);
    formData.append("mode", mode);

    statusEl.textContent="Envoi en cours...";

    try{
        const res = await fetch(`/api/${endpoint}`, {method:"POST", body:formData});
        if(!res.ok){ 
            const txt = await res.json().catch(()=>null);
            throw new Error(txt?.error||`Erreur ${res.status}`);
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        downloadLink.href = url;
        downloadLink.download = file.name.split(".")[0] + `_${algo}_${endpoint}.bin`;
        downloadSection.style.display="block";
        statusEl.textContent="Succès !";
    }catch(err){
        statusEl.textContent="Erreur: "+err.message;
        downloadSection.style.display="none";
    }
}

encryptBtn.addEventListener("click", ()=>sendFile("encrypt"));
decryptBtn.addEventListener("click", ()=>sendFile("decrypt"));
