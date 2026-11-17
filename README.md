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


## Latest virus scans 17.11.2026

- **Runtime:** `https://www.kleenscan.biz/runtime/scan_result/e385e6bf2299bb078b79cb0b829e9bdb3e212d3b2049783d300d3e439ff880a8`
- **Scantime:** `https://www.kleenscan.biz/scan_result/1e0c7b14fe1daf6973566ccb06323b92ba15b335bbbb422b25ed5ec5a81db5fc`

Every transaction is valued, whatever the size. There is no minimum.
Chameleos is developed in my spare time. If you find it useful and want to say thanks, Bitcoin is welcome — every satoshi is appreciated.
BTC: bc1qve3g7ts96767xwe8kvna7mjk7d5rvpvle7q5vc

---

## Support tier — 500 € and above

Anyone who sends **500 € or more** worth of BTC (at the exchange rate on the day of transfer) gets a **custom, private stub build** — a `stub64.bin` and `stub32.bin` that are **not** the versions published in the public repository.

### What "custom" means

| Property | Public stubs | Custom stubs |
|---|---|---|
| **Bootstrap prologue** | Fixed instruction set | Different set of plausible junk instructions and different register allocation |
| **Marker layout** | Same `0xCC`/`0xDD` system, fixed positions and counts | Same system, different positions and counts → different structural fingerprint |
| **Sled shape** | Fixed length range and filler bytes | Different length range and different filler bytes |
| **Section name pool** | Fixed list of plausible linker names | Different list of plausible linker names |

Custom stubs remain fully compatible with `packer.exe` — they satisfy every requirement in [`INVARIANTS.md`](INVARIANTS.md), so the packer will use them without any code change. They are provided under the same MIT terms as the public ones, with the additional property that **you will be the only outside recipient** of that particular variant.

---

## How to claim a support tier

1. **Send the BTC** to the address above.
2. **Contact me** with the transaction TXID so I can verify the amount.
3. I'll confirm the amount and deliver the custom stubs within a few days.

### Contact

- **GitHub Discussions** — open a thread in [`Discussions`](https://github.com/YOUR_USERNAME/Chameleos/discussions)
- **GitHub profile** — message me through my profile page ([@YOUR_USERNAME](https://github.com/YOUR_USERNAME))

If you'd rather have a private channel, include that preference in your message and I'll reply with a direct one.

---

## A note on the exchange rate

The BTC amount is evaluated at the exchange rate on the **day of transfer**, not on the day you claim the tier. This settles the boundary in one sentence so nobody has to argue about whether a transfer sent in March and claimed in April was "500 € or more".

If your transfer lands just under the 500 € boundary, feel free to send a small top-up — the total across both transactions is what counts.

---

## What the support actually funds

Nothing about the *public* release changes when you support the project:

- The public `packer.c`, `stub64.bin`, `stub32.bin`, and all documentation stay free, MIT-licensed, and updated on the same schedule as before.
- Bug fixes and public features are not gated behind support — if something is broken in the public release, it gets fixed in the public release.

What your support funds is that this project **exists at all** — the hours spent producing the stubs, keeping the packer compatible with current Windows builds, and writing the docs you're reading right now. A small support is genuinely what keeps small tools like this one alive.

---

## Thank you

To everyone who has supported the project so far — thank you. Every "thanks" genuinely means a lot — it's what keeps me working on small tools like this one.

---

*Chameleos is distributed under the MIT License — see [`LICENSE`](LICENSE). The public runtime stubs (`stub64.bin`, `stub32.bin`) are binary-only; their assembly sources are maintained privately and their behavior is specified in [`INVARIANTS.md`](INVARIANTS.md).*



## Disclaimer

Chameleos is a legitimate executable-protection tool. It compresses, encrypts, and restructures standard Windows PE executables to make them smaller and structurally distinct. It contains **no malicious payload**, **no anti-debug tricks**, **no persistence mechanism**, and **no side effects** on the host system beyond the output EXE you ask it to produce.

The author (** W33v3ly Samuel A.**) takes **no responsibility** for how the packed executables are used. If you pack a target for black-hat malware, ransomware, a spyware, a keylogger, a credential stealer, a dropper, or any other illegal software, that responsibility is entirely yours.

Conversely — packing a fully legitimate EXE (a game, a driver UI, a commercial tool, an open-source utility, your own hobby project) is exactly what Chameleos was built for. It is a tool for **protecting legitimate binaries**, not for hiding malicious ones.

Use it in good faith. If a packer removes bytes, restructures sections, or randomises a stub, that is engineering — what you do with the packed file after is the moral question, and the author is not part of it.

