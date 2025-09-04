# `OpenSSL labs`

A modular C-based cryptography project built on top of **OpenSSL**.  
It provides a structured set of components for experimenting with modern cryptographic techniques.

---

## 🔑 Main Modules

- **Symmetric Encryption**  
  AES-based encryption/decryption routines with support for both file-oriented and memory-based workflows.

- **Asymmetric Encryption**  
  Foundations for public-key cryptography, leveraging OpenSSL primitives.  

- **Hashing & HMAC**  
  Support for cryptographic hashing and message authentication codes.  
  Includes verification and integrity-check mechanisms.

- **Random Number Generation**  
  Secure random byte generation and PRNG seeding, powered by OpenSSL’s randomness utilities.

- **Utilities**  
  Common helper functions for cryptographic workflows, error handling, and data manipulation.

- **Testing**  
  A suite of unit tests to validate encryption, hashing, and randomness behavior.


## 🔧 Compilation

```bash, aiignore
mkdir build
cd build
cmake ..
make
```


This will generate an executable called `openssl_lab_runner`.

---

## ▶️ Running the Project

```bash, aiignore
./openssl_lab_runner
```

