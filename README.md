🔐 HDE Simulator

A GUI-based Hybrid Data Encryption tool using AES-256-GCM & RSA-2048

📖 Overview

The HDE Simulator demonstrates modern hybrid cryptography using:

AES-256-GCM → Fast symmetric encryption for file contents.

RSA-2048 (hybrid) → Asymmetric encryption to securely exchange AES keys.

It provides a Tkinter GUI (hde_frontend.py) for user interaction and a backend module (hde_backend.py) implementing the cryptographic operations.

This project is suitable for learning, simulation, and demonstrating encryption concepts (not production-level security).


⚙️ Features

✅ AES-256-GCM file encryption/decryption
✅ RSA-2048 hybrid encryption (AES key wrapped with RSA)
✅ Key management (generate, save, load AES & RSA keys)
✅ User-friendly Tkinter GUI
✅ Status logs to track operations


📂 Project Structure
HDE-Simulator/
│
├── hde_backend.py   # Core cryptographic functions (AES & RSA hybrid)
├── hde_frontend.py  # GUI application using Tkinter
└── README.md        # Project documentation


🔑 Cryptographic Design
🔹 AES-256-GCM

Key size: 256 bits (32 bytes)
Mode: GCM (provides encryption + authentication tag)
File format:
[nonce (12 bytes)] [tag (16 bytes)] [ciphertext]


🔹 RSA-2048 (Hybrid Encryption)
Key size: 2048 bits
Used for: Encrypting the AES session key
File format:
[2-byte length][RSA_encrypted_AES_key][nonce][tag][ciphertext]

🔹 Why Hybrid?
AES → efficient for large data encryption
RSA → secure key exchange

⚠️ Disclaimer

This project is for educational/demo purposes only.
Do not use it in production for sensitive data.
Together → best of both worlds (speed + security)
