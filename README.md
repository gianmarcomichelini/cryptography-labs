## Project Structure
### Folder Descriptions

- **`CMakeLists.txt`**  
  Defines the build system. Lists source files, headers, and targets.

- **`include/`**  
  Public header files shared across modules. Contains function declarations, macros, and data types.

- **`src/`**  
  C source files and their private headers. Each cryptographic lab or attack is modularized (e.g., `rsa_attack.c`, `xor_decrypt.c`).  
  The `main.c` serves as the main entry point for executing labs.

- **`tests/`**  
  Unit or functional tests for source modules. Example: `test_rsa.c` validates `rsa_attack.c`.

- **`data/`**  
  Input files used in labs (e.g., encrypted messages, keys). Organized per challenge.  
  Contains no build artifacts or outputs.

- **`examples/`**  
  Scripts or usage examples for running modules. Useful for demonstrating expected input/output.

- **`docs/`**  
  Documentation, lab writeups, algorithm explanations. Markdown format preferred.

