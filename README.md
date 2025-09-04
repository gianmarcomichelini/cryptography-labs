# `Cryptography Playground`

This repository brings together two complementary projects for learning, experimenting, and practicing **cryptography** and **CTF-style challenges**:

- 🐍 **Python CTFs** — a structured set of Python-based cryptographic challenges and exercises.
- ⚙️ **OpenSSL Labs** — a modular C project built on **OpenSSL**, focused on implementing and testing crypto primitives.

Together, they provide a **hands-on environment** for exploring both theoretical and applied aspects of cryptography.

---

## 📂 Projects Overview

### 🐍 Python CTFs
A collection of **Python-based Capture The Flag (CTF) challenges**.  
Covers cryptography fundamentals, practical attacks, and challenge servers.

- **Python Basics** → Utilities for hex/bin encoding, randomness, and helpers.
- **Hash Functions** → Collisions, equality checks, and length extension attacks.
- **HMAC** → Implementations with multiple libraries and forgery challenges.
- **Symmetric Crypto** → CBC experiments, cookie forgery, padding, and oracle attacks.
- **CTF Challenges** → Hash, RSA, and Symmetric-based problems in progressive difficulty.

👉 [See detailed README](./Python/README.md)

---

### ⚙️ OpenSSL Labs
A **C-based cryptography project** using **OpenSSL**, designed around modular components.

- **Symmetric Encryption** → AES-based routines for files and memory.
- **Asymmetric Encryption** → Public-key foundations with OpenSSL.
- **Hashing & HMAC** → Integrity checks and message authentication.
- **Random Number Generation** → Secure RNG and PRNG seeding.
- **Utilities & Testing** → Helper functions and unit test coverage.
  
👉 [See detailed README](./OpenSSL/README.md)
