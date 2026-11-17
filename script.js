// Encryptor: password-based AES-256-GCM using the browser's built-in Web Crypto API.
//
// Output format (base64): salt (16 bytes) | iv (12 bytes) | ciphertext + auth tag
// The key is derived from the password with PBKDF2-SHA256 (250,000 rounds) and a
// random salt, so the same message and password give a different result every time.

const PBKDF2_ROUNDS = 250000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ROUNDS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function toBase64(bytes) {
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function fromBase64(text) {
  const binary = atob(text.replace(/\s+/g, ""));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function encrypt(message, password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(password, salt);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(message)));

  const packed = new Uint8Array(salt.length + iv.length + cipher.length);
  packed.set(salt, 0);
  packed.set(iv, salt.length);
  packed.set(cipher, salt.length + iv.length);
  return toBase64(packed);
}

async function decrypt(payload, password) {
  let packed;
  try {
    packed = fromBase64(payload.trim());
  } catch {
    throw new Error("That doesn't look like encrypted text from this app.");
  }
  if (packed.length <= SALT_BYTES + IV_BYTES) {
    throw new Error("That encrypted text is too short or incomplete.");
  }
  const salt = packed.slice(0, SALT_BYTES);
  const iv = packed.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const cipher = packed.slice(SALT_BYTES + IV_BYTES);
  const key = await deriveKey(password, salt);
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
    return decoder.decode(plain);
  } catch {
    throw new Error("Wrong password, or the text was changed.");
  }
}

function passwordStrength(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (!pw) return { label: "", level: 0 };
  if (score <= 2) return { label: "Weak password", level: 1 };
  if (score <= 3) return { label: "Okay password", level: 2 };
  return { label: "Strong password", level: 3 };
}

// ---------- UI wiring (skipped when loaded outside a browser page) ----------

if (typeof document !== "undefined" && document.getElementById("run")) {
  const $ = (id) => document.getElementById(id);
  let mode = "encrypt";

  function setStatus(text, kind = "") {
    $("status").textContent = text;
    $("status").className = `status ${kind}`;
  }

  function setMode(next) {
    mode = next;
    document.querySelectorAll(".tab").forEach((tab) => {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active);
    });
    const enc = mode === "encrypt";
    $("message-label").textContent = enc ? "Message" : "Encrypted text";
    $("message").placeholder = enc ? "Type a secret message..." : "Paste the encrypted text here...";
    $("password").placeholder = enc ? "Choose a strong password" : "Enter the password it was locked with";
    $("run").textContent = enc ? "🔒 Encrypt" : "🔓 Decrypt";
    $("strength").style.display = enc ? "block" : "none";
    $("output-card").classList.add("hidden");
    setStatus("");
  }

  document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));

  $("toggle-password").addEventListener("click", () => {
    const field = $("password");
    field.type = field.type === "password" ? "text" : "password";
  });

  $("password").addEventListener("input", (e) => {
    const { label, level } = passwordStrength(e.target.value);
    $("strength").textContent = label;
    $("strength").dataset.level = level;
  });

  $("run").addEventListener("click", async () => {
    const message = $("message").value;
    const password = $("password").value;
    if (!message.trim()) return setStatus(mode === "encrypt" ? "Type a message first." : "Paste the encrypted text first.", "error");
    if (!password) return setStatus("Enter a password.", "error");

    $("run").disabled = true;
    setStatus(mode === "encrypt" ? "Encrypting..." : "Decrypting...");
    try {
      const result = mode === "encrypt" ? await encrypt(message, password) : await decrypt(message, password);
      $("output-label").textContent = mode === "encrypt" ? "Encrypted text (share this)" : "Decrypted message";
      $("output").textContent = result;
      $("output-card").classList.remove("hidden");
      setStatus(mode === "encrypt" ? "Done. Send the text and share the password separately." : "Unlocked.", "ok");
    } catch (err) {
      $("output-card").classList.add("hidden");
      setStatus(err.message, "error");
    } finally {
      $("run").disabled = false;
    }
  });

  $("copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("output").textContent);
      setStatus("Copied to clipboard.", "ok");
    } catch {
      setStatus("Couldn't copy. Select the text and copy it manually.", "error");
    }
  });
}

// Export for tests in Node
if (typeof module !== "undefined") {
  module.exports = { encrypt, decrypt, passwordStrength };
}
