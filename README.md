# 🔐 Encryptor

Lock a message with a password. Only someone with the same password can read it.

**Live demo:** https://abuka920.github.io/aes-encryptor/

## What it does

- Encrypts any text with **AES-256-GCM**, the same standard banks and governments use
- Turns your password into a key with **PBKDF2-SHA256 (250,000 rounds)** and a random salt
- Same message plus same password gives a different result every time
- Detects a wrong password or tampered text and tells you
- Shows password strength while you type
- One-click copy

Everything runs in your browser through the built-in Web Crypto API. Nothing is sent to a server.

## Stack

`JavaScript` `Web Crypto API` `HTML` `CSS`

No frameworks, no backend, no dependencies.

## Run it

Open `index.html` in any modern browser. That's it.

## How it works

```
password + random salt  →  PBKDF2 (250k rounds)  →  256-bit AES key
message + key + random IV  →  AES-GCM  →  ciphertext + auth tag
output = base64( salt | IV | ciphertext )
```

The salt and IV are stored with the ciphertext, so the password is the only thing you need to decrypt. The GCM auth tag is why a wrong password or an edited message fails cleanly instead of returning garbage.

## Security notes

- Your security is only as strong as your password. Use a long one.
- Share the encrypted text and the password through different channels.
- This is a portfolio project. For serious secrets, use an audited tool like Signal or age.

---

Built by **Kalif Abu** · [LinkedIn](https://linkedin.com/in/kalif-abu-262430264)
