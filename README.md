# Chameleos

<img width="1024" height="572" alt="banner" src="https://github.com/user-attachments/assets/fa72df3d-0a8f-4c35-b568-834f234b79b8" />


![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Arch](https://img.shields.io/badge/arch-x86%20%7C%20x64-green)
![Compression](https://img.shields.io/badge/compression-LZ4-orange)
![Cipher](https://img.shields.io/badge/cipher-SUB%2BROL3-blueviolet)
![License](https://img.shields.io/badge/license-MIT-yellow)

> A native PE packer for x86 and x64 Windows executables — LZ4 compression, rolling SUB cipher, and a metamorphic runtime stub that reshapes on every build.

Chameleos takes a standard 32- or 64-bit PE file, compresses its code and data, encrypts the payload, mutates a small runtime stub into a randomly named section, and rewrites the entry point so the stub executes first. Every run produces a structurally distinct binary that behaves identically to the original.

---

## Features

- **x64 + x86** — AMD64 and i386 executables, GUI and console subsystems.
- **LZ4 compression** — pure C implementation, no external libraries.
- **Rolling SUB + ROL3 cipher** — per-build 32-byte key, applied in-place over the compressed stream.
- **Metamorphic stub** — the runtime stub's prologue is randomised per build; a fixed-size junk system preserves every jump target.
- **Per-build randomness** — random section name (from a linker-plausible list), random OEP sled length (16–496 bytes), fresh 32-byte key, fresh junk marker layout.
- **Loader-friendly PE shape** — non-zero `SizeOfRawData` on every section, recomputed `CheckSum`, normalised `DllCharacteristics` (NX_COMPAT retained, `DYNAMIC_BASE`/CFG/CET cleared).
- **Zero runtime dependencies** — the stub is self-contained assembly.
- **~66% of original size** on typical `putty.exe` / `notepad.exe`.

---

## Supported targets

| Architecture | `FileHeader.Machine` | PE OptionalHeader | Subsystem |
|---|---|---|---|
| **x64** | `0x8664` | `IMAGE_NT_OPTIONAL_HDR64_MAGIC` | GUI / CUI |
| **x86** | `0x014c` | `IMAGE_NT_OPTIONAL_HDR32_MAGIC` | GUI / CUI |

DLLs are rejected (`IMAGE_FILE_DLL` bit must be clear). Already-packed binaries (UPX, Themida, VMProtect, Enigma) are not supported — their section layout violates the assumptions Chameleos makes.

---
## Usage

```bash
chameleos.exe <input.exe> <output.exe>
```

**Example output:**

```text
chameleos.exe in.exe out64.exe
  .text    rva=00001000 raw=  971776 ->   653078 (67%)
  .data    rva=00132000 raw=    4096 ->      995 (24%)
  .00cfg   rva=0013F000 raw=     512 ->       37 (7%)
  .gxfg    rva=00140000 raw=   11264 ->     6322 (56%)
  _RDATA   rva=00144000 raw=     512 ->      355 (69%)
mutated: 4 var + 12 fix, stub 435 -> 430 bytes
section: .rdata2  sled=106  oep=001A506A
input  :  1706136   packed :  1355776 (79%)
```

## Build

### Requirements

- **NASM** — only if you want to reassemble the stubs. Pre-built `stub64.bin` / `stub32.bin` are shipped in this repository, so this is optional for the packer itself.
- **GCC** (MinGW-w64) — to compile `packer.c`.


## Disclaimer

Chameleos is a legitimate executable-protection tool. It compresses, encrypts, and restructures standard Windows PE executables to make them smaller and structurally distinct. It contains **no malicious payload**, **no anti-debug tricks**, **no persistence mechanism**, and **no side effects** on the host system beyond the output EXE you ask it to produce.

The author (**Samuel A.**) takes **no responsibility** for how the packed executables are used. If you pack a target for black-hat malware, ransomware, a spyware, a keylogger, a credential stealer, a dropper, or any other illegal software, that responsibility is entirely yours.

Conversely — packing a fully legitimate EXE (a game, a driver UI, a commercial tool, an open-source utility, your own hobby project) is exactly what Chameleos was built for. It is a tool for **protecting legitimate binaries**, not for hiding malicious ones.

Use it in good faith. If a packer removes bytes, restructures sections, or randomises a stub, that is engineering — what you do with the packed file after is the moral question, and the author is not part of it.

