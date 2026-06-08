# Assembly Scaffold Reference

`mareu scaffold --lang asm` generates assembly **programmatically** (correct by
construction) rather than from `.hbs` templates. Every artifact carries the
machine-readable header and is a *starting point* (RFC §4.3) — the execve
shellcode is null-free and assemble-clean; egghunter/loader carry explicit
"verify syscall numbers/badchars on target" notes.

## Selection

| Flag | Values | Default |
|------|--------|---------|
| `--class` | `shellcode` \| `egghunter` \| `loader` \| `ret2` | `shellcode` |
| `--arch` | `x86_64` \| `x86` \| `aarch64` | `x86_64` |
| `--syntax` | `nasm` \| `gas` \| `both` | `both` |

`--syntax both` emits a matched pair (`.nasm` + `.s`). For non-x86 arches NASM
does not apply, so the request collapses to a single GNU `as` (`.s`) file.

Use `--save` to write each artifact to its own file (`mareu_scaffold_<ts>/`); to
stdout, multiple artifacts are concatenated with `// ===== filename =====`
banners.

## Artifacts

### `shellcode` — `execve("/bin/sh")`

Null-free on x86_64/x86 (the path immediate `0x68732f2f6e69622f` = `"/bin//sh"`
has no zero byte). aarch64 builds `"/bin/sh\0"` in `x1` via `movz`/`movk` to
avoid a literal pool.

| arch | syscall | verified |
|------|---------|----------|
| x86_64 | `__NR_execve = 59`, `syscall` | assembles + null-free disasm |
| x86 | `__NR_execve = 11`, `int 0x80` | assembles |
| aarch64 | `__NR_execve = 221`, `svc #0` | constructed (no local aarch64 assembler) |

### `egghunter` — `access(2)`-based

Scans memory for a doubled EGG tag, using `access(2)` to skip unmapped pages
without faulting. **Verify** `__NR_access` (21 on x86_64, 33 on x86) and the
`-EFAULT` low byte (`0xf2`) for your target. Set the EGG to your payload prefix.

### `loader` — `mmap` RWX stager

`mmap(NULL, 0x1000, RWX, MAP_PRIVATE|ANON, -1, 0)` → `read(0, buf, 0x1000)` →
`jmp buf`. Not null-free (carries `-1`); intended as a stager, not an inline
payload.

### `ret2` — proof / `win` stub

`write(1, "[pwned]\n", 8); exit(0)`. Jump here (or `ret` into it) to confirm a
control-flow hijack before swapping in a real payload.

## Assembling

The header's `assemble:` line gives the exact command, e.g.:

```bash
# NASM/Intel
nasm -f elf64 sc.nasm -o sc.o && ld sc.o -o sc
# GNU as/AT&T
as sc.s -o sc.o && ld sc.o -o sc
# 32-bit
as --32 sc.s -o sc.o && ld -m elf_i386 sc.o -o sc
# aarch64 (cross)
aarch64-linux-gnu-as sc.s -o sc.o && aarch64-linux-gnu-ld sc.o -o sc
```

## No silent fallback

Requesting an offline language with no template (e.g. `--lang rust` without
`--ai`) is a clear error — Mareu never emits C mislabeled as another language.
With `--ai`, any language is delegated to the model.
