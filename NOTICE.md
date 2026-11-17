# Notice

Chameleos is distributed under the MIT License — see [LICENSE](LICENSE).

## Scope

The MIT License applies to all files present in this repository, including
`packer.c`, `stub64.bin`, and `stub32.bin`.

The assembly sources of the runtime stubs (`stub64.asm`, `stub32.asm`) are
**not** part of this repository and are not covered by the MIT License. They
are maintained privately by the author.

Any binary that satisfies the invariants described in
[INVARIANTS.md](INVARIANTS.md) is functionally interchangeable with the
shipped stubs and may be used in place of them under the terms of the MIT
License granted for those binaries.
