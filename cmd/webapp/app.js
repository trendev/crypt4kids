const plaintext = document.querySelector("#plaintext");
const output = document.querySelector("#cipher-output");
const missionStatus = document.querySelector("#mission-status");
const algorithmReadout = document.querySelector("#algorithm-readout");
const lockMeter = document.querySelector("#lock-meter");
const vaultMeter = document.querySelector("#vault-meter");
const cartridges = Array.from(document.querySelectorAll(".cartridge"));
const encryptButton = document.querySelector("#encrypt-button");
const copyButton = document.querySelector("#copy-button");
const clearButton = document.querySelector("#clear-button");

let activeAlgorithm = "rot13";
let lastCiphertext = "";

const algorithmLabels = {
  rot13: "ROT13",
  atbash: "ATBASH",
  atbashrot13: "ATBASH + ROT13",
  rot13atbash: "ROT13 + ATBASH",
};

function setStatus(message) {
  missionStatus.textContent = message;
}

function setAlgorithm(algorithm) {
  activeAlgorithm = algorithm;
  cartridges.forEach((button) => {
    button.classList.toggle("active", button.dataset.algorithm === algorithm);
  });
  algorithmReadout.textContent = `${algorithmLabels[algorithm] || "ROT13"} CARTRIDGE`;
  output.textContent = "READY_";
  lastCiphertext = "";
  lockMeter.style.width = `${38 + algorithm.length * 4}%`;
  vaultMeter.style.width = `${52 + algorithm.length * 3}%`;
  setStatus(`CARTRIDGE LOADED: ${algorithmLabels[algorithm] || "ROT13"}`);
}

async function encryptText() {
  const text = plaintext.value;
  if (!text) {
    output.textContent = "NO PLAINTEXT_";
    setStatus("BUFFER EMPTY");
    return;
  }

  encryptButton.disabled = true;
  setStatus("CIPHER WHEEL SPINNING");

  try {
    const response = await fetch("/api/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ algorithm: activeAlgorithm, text }),
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    lastCiphertext = payload.ciphertext;
    output.textContent = `${payload.ciphertext}_`;
    lockMeter.style.width = "92%";
    vaultMeter.style.width = "88%";
    setStatus("CIPHER BURST COMPLETE");
  } catch {
    output.textContent = "LINK ERROR_";
    setStatus("LOCAL LINK INTERRUPTED");
  } finally {
    encryptButton.disabled = false;
  }
}

async function copyCiphertext() {
  if (!lastCiphertext) {
    setStatus("NO CIPHER OUTPUT");
    return;
  }

  try {
    await navigator.clipboard.writeText(lastCiphertext);
    setStatus("CIPHER COPIED");
  } catch {
    setStatus("COPY UNAVAILABLE");
  }
}

function clearTerminal() {
  plaintext.value = "";
  output.textContent = "READY_";
  lastCiphertext = "";
  lockMeter.style.width = "30%";
  vaultMeter.style.width = "44%";
  setStatus("BUFFER PURGED");
  plaintext.focus();
}

cartridges.forEach((button) => {
  button.addEventListener("click", () => setAlgorithm(button.dataset.algorithm));
});

encryptButton.addEventListener("click", encryptText);
copyButton.addEventListener("click", copyCiphertext);
clearButton.addEventListener("click", clearTerminal);

plaintext.addEventListener("input", () => {
  lastCiphertext = "";
  output.textContent = "READY_";
  setStatus("PLAINTEXT BUFFER ACTIVE");
});

setAlgorithm(activeAlgorithm);

const canvas = document.querySelector("#wire-canvas");
const ctx = canvas.getContext("2d", { alpha: true });
let width = 0;
let height = 0;
let pixelRatio = 1;

function resizeCanvas() {
  pixelRatio = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
  width = Math.floor(window.innerWidth);
  height = Math.floor(window.innerHeight);
  canvas.width = Math.floor(width * pixelRatio);
  canvas.height = Math.floor(height * pixelRatio);
  ctx.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
  ctx.imageSmoothingEnabled = false;
}

function drawGrid(time) {
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#050509";
  ctx.fillRect(0, 0, width, height);

  const horizon = height * 0.54;
  const center = width / 2;
  const pulse = Math.floor((time / 90) % 28);

  ctx.lineWidth = 2;
  ctx.strokeStyle = "rgba(53, 243, 255, 0.42)";
  for (let x = -width; x <= width * 2; x += 56) {
    ctx.beginPath();
    ctx.moveTo(center, horizon);
    ctx.lineTo(x + pulse, height);
    ctx.stroke();
  }

  for (let i = 0; i < 18; i += 1) {
    const y = horizon + i * i * 3.2 + pulse;
    if (y > height) continue;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  drawWireVault(center, horizon - 46, time);
  drawSecurityStars(time);
}

function drawWireVault(x, y, time) {
  const size = Math.max(74, Math.min(140, width * 0.09));
  const wobble = Math.sin(time / 380) * 5;

  ctx.save();
  ctx.translate(x, y + wobble);
  ctx.strokeStyle = "rgba(255, 212, 92, 0.75)";
  ctx.lineWidth = 3;

  for (let ring = 0; ring < 4; ring += 1) {
    const radius = size - ring * 20;
    ctx.beginPath();
    for (let side = 0; side <= 8; side += 1) {
      const angle = (Math.PI * 2 * side) / 8 + time / 1800;
      const px = Math.cos(angle) * radius;
      const py = Math.sin(angle) * radius * 0.62;
      if (side === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.stroke();
  }

  ctx.strokeStyle = "rgba(255, 79, 196, 0.7)";
  for (let side = 0; side < 8; side += 1) {
    const angle = (Math.PI * 2 * side) / 8 + time / 1800;
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(Math.cos(angle) * size, Math.sin(angle) * size * 0.62);
    ctx.stroke();
  }

  ctx.restore();
}

function drawSecurityStars(time) {
  const dots = 36;
  for (let i = 0; i < dots; i += 1) {
    const x = (i * 97 + Math.floor(time / 24)) % width;
    const y = (i * 53) % Math.max(1, height * 0.48);
    const color = i % 3 === 0 ? "#4dff91" : i % 3 === 1 ? "#35f3ff" : "#ff4fc4";
    ctx.fillStyle = color;
    ctx.fillRect(Math.floor(x), Math.floor(y), 3, 3);
  }
}

function loop(time) {
  drawGrid(time);
  requestAnimationFrame(loop);
}

window.addEventListener("resize", resizeCanvas);
resizeCanvas();
requestAnimationFrame(loop);
