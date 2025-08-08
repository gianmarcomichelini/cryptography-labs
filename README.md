# Crypto Labs Runner

This project is a simple C program that allows users to select and "run" predefined lab challenges related to cryptography using OpenSSL. It acts as a launcher and validator for available lab names.

## 🧩 Available Labs

- **openssl-sym**:
  - `guess-algo`
  - `firstdecryption`
  - `in-the-name-of-the-cipher`
  - `padding`
- **openssl-asym**:
  - `guess-what`
- **openssl-hmac**:
  - `firsthmac`
- **openssl-dgst**:
  - `changedgst`
  - `keyed-digest`
- **openssl-rand**:
  - `bytewise-operations`

---

## 🛠️ Requirements

- CMake (>= 3.10)
- GCC or compatible C compiler
- Unix-like shell (Linux/macOS/WSL)
- OpenSSL

---

## 🔧 Compilation

```bash, aiignore
mkdir build
cd build
cmake ..
make
```


This will generate an executable called `lab-runner`.

---

## ▶️ Running the Project

```bash, aiignore
./lab-runner
```

You will be prompted to enter the name of a lab (must match exactly one of the listed names). Example:

```text, aiignore
enter a lab (full sub-challenge name): guess-algo
running: guess-algo
```

If the input is not recognized:

```text, aiignore
unknown lab: something-else
```