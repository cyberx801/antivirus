README.md (ilk sürüm)
# C Antivirus Project (Core Version)

A simple command-line antivirus prototype written in C.
It scans files, calculates SHA-256 hashes, and compares them with known malware signatures.

## Build
```bash
mkdir build && cd build
cmake ..
make

Usage
./antivirus scan ./downloads
./antivirus compare ./data/test.txt

Project Structure
src/        → source files (.c)
include/    → header files (.h)
data/       → signature database (signatures.json)