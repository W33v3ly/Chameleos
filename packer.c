#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifndef IMAGE_DLLCHARACTERISTICS_NX_COMPAT
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT  0x0100
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF   0x4000
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_CET_COMPAT
#define IMAGE_DLLCHARACTERISTICS_CET_COMPAT 0x8000
#endif

#define LZ4_HASHLOG   16
#define LZ4_HASH_SIZE (1 << LZ4_HASHLOG)

/* ================= LZ4 ================= */
static unsigned int lz4_hash(const unsigned char *p) {
    unsigned int v = (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
                     ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
    return (v * 2654435761u) >> (32 - LZ4_HASHLOG);
}
static int emit_seq(unsigned char *dst, int dp,
                    const unsigned char *lit, int lit_len,
                    int offset, int match_len)
{
    int tp = dp++;
    unsigned char token = 0;
    if (lit_len >= 15) {
        token |= 0xF0; int rem = lit_len - 15;
        while (rem >= 255) { dst[dp++] = 255; rem -= 255; }
        dst[dp++] = (unsigned char)rem;
    } else token |= (lit_len << 4);
    memcpy(dst + dp, lit, lit_len); dp += lit_len;
    if (match_len >= 4) {
        dst[dp++] = (unsigned char)(offset & 0xFF);
        dst[dp++] = (unsigned char)((offset >> 8) & 0xFF);
        int ml = match_len - 4;
        if (ml >= 15) {
            token |= 0x0F; int rem = ml - 15;
            while (rem >= 255) { dst[dp++] = 255; rem -= 255; }
            dst[dp++] = (unsigned char)rem;
        } else token |= ml;
    }
    dst[tp] = token;
    return dp;
}
static int lz4_compress(const unsigned char *src, int n, unsigned char *dst) {
    if (n == 0) return 0;
    int *hash = (int*)malloc(LZ4_HASH_SIZE * sizeof(int));
    memset(hash, 0xFF, LZ4_HASH_SIZE * sizeof(int));
    int sp = 0, dp = 0, anchor = 0;
    int limit = n - 12; if (limit < 0) limit = 0;
    while (sp < limit) {
        unsigned int h = lz4_hash(src + sp);
        int ref = hash[h]; hash[h] = sp;
        if (ref >= 0 && sp - ref <= 65535 &&
            *(unsigned int*)(src+ref) == *(unsigned int*)(src+sp))
        {
            int ml = 4;
            while (sp + ml < n && src[ref + ml] == src[sp + ml]) ml++;
            dp = emit_seq(dst, dp, src + anchor, sp - anchor, sp - ref, ml);
            sp += ml; anchor = sp;
            for (int p = (int)(sp - ml) + 1; p < sp - 3; p++)
                hash[lz4_hash(src + p)] = p;
        } else sp++;
    }
    dp = emit_seq(dst, dp, src + anchor, n - anchor, 0, 0);
    free(hash);
    return dp;
}

/* ================= Junk table (portable x86+x64) ================= */
typedef struct { unsigned char bytes[8]; int len; } JunkInsn;
static const JunkInsn junk_table[] = {
    {{0x90}, 1}, {{0x66,0x90}, 2}, {{0x0F,0x1F,0x00}, 3},
    {{0x0F,0x1F,0x40,0x00}, 4}, {{0x0F,0x1F,0x44,0x00,0x00}, 5},
    {{0x50,0x58}, 2}, {{0x53,0x5B}, 2}, {{0x51,0x59}, 2},
    {{0x52,0x5A}, 2}, {{0x56,0x5E}, 2}, {{0x57,0x5F}, 2},
    {{0x55,0x5D}, 2}, {{0x9C,0x9D}, 2},
};
#define JUNK_N (sizeof(junk_table)/sizeof(junk_table[0]))

static int gen_junk_fixed(unsigned char *dst, int target) {
    int pos = 0, stall = 0;
    while (pos < target && stall < 200) {
        int idx = rand() % (int)JUNK_N;
        if (pos + junk_table[idx].len > target) { stall++; continue; }
        memcpy(dst + pos, junk_table[idx].bytes, junk_table[idx].len);
        pos += junk_table[idx].len;
    }
    while (pos < target) dst[pos++] = 0x90;
    return pos;
}
static int gen_junk_var(unsigned char *dst, int max_len) {
    int target = 1 + rand() % (max_len - 1);
    return gen_junk_fixed(dst, target);
}
static int is_marker(const unsigned char *p, int n, unsigned char b) {
    if (n < 8) return 0;
    for (int i = 0; i < 8; i++) if (p[i] != b) return 0;
    return 1;
}
static int find_seq(const unsigned char *buf, int n, const unsigned char *pat, int plen) {
    for (int i = 0; i <= n - plen; i++)
        if (!memcmp(buf + i, pat, plen)) return i;
    return -1;
}
static DWORD align_up(DWORD v, DWORD a) { return (v + a - 1) & ~(a - 1); }

/* ================= Payload cipher: SUB + ROL 3 ================= */
static unsigned char rol8(unsigned char b, int r) {
    r &= 7; if (!r) return b;
    return (unsigned char)((b << r) | (b >> (8 - r)));
}
static void payload_encode(unsigned char *buf, DWORD len, const unsigned char key[32]) {
    for (DWORD j = 0; j < len; j++)
        buf[j] = rol8((unsigned char)(buf[j] - key[j & 31]), 3);
}

/* ================= PE checksum ================= */
static DWORD calc_checksum(unsigned char *buf, DWORD size, DWORD checksum_off) {
    DWORD sum = 0;
    for (DWORD i = 0; i < size / 2; i++) {
        if (i * 2 == checksum_off || i * 2 + 1 == checksum_off) continue;
        sum += *(unsigned short*)(buf + i * 2);
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (size % 2) sum += *(unsigned char*)(buf + size - 1);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += size;
    return sum;
}

/* ================= main ================= */
int main(int argc, char **argv) {
    if (argc != 3) { printf("Usage: %s <in.exe> <out.exe>\n", argv[0]); return 1; }
    srand((unsigned)time(NULL) ^ (unsigned)GetTickCount());

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END); long fsize = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *fd = (unsigned char*)malloc(fsize);
    fread(fd, 1, fsize, f); fclose(f);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)fd;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { puts("not a PE"); return 1; }
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64*)(fd + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { puts("bad NT"); return 1; }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) { puts("require EXE"); return 1; }
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) { puts("require EXE"); return 1; }

    int is64 = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    DWORD nsec = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *sec;
    DWORD sec_align, file_align, orig_entry;

    if (is64) {
        sec_align  = nt->OptionalHeader.SectionAlignment;
        file_align = nt->OptionalHeader.FileAlignment;
        orig_entry = nt->OptionalHeader.AddressOfEntryPoint;
        sec = (IMAGE_SECTION_HEADER*)((unsigned char*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    } else {
        IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32*)(fd + dos->e_lfanew);
        sec_align  = nt32->OptionalHeader.SectionAlignment;
        file_align = nt32->OptionalHeader.FileAlignment;
        orig_entry = nt32->OptionalHeader.AddressOfEntryPoint;
        sec = (IMAGE_SECTION_HEADER*)((unsigned char*)&nt32->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    }

    IMAGE_SECTION_HEADER *imp_sec = NULL, *rel_sec = NULL;
    DWORD imp_rva = is64 ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
                         : ((IMAGE_NT_HEADERS32*)(fd + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD rel_rva = is64 ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
                         : ((IMAGE_NT_HEADERS32*)(fd + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    for (DWORD i = 0; i < nsec; i++) {
        DWORD end = sec[i].VirtualAddress + sec[i].Misc.VirtualSize;
        if (imp_rva && imp_rva >= sec[i].VirtualAddress && imp_rva < end) imp_sec = &sec[i];
        if (rel_rva && rel_rva >= sec[i].VirtualAddress && rel_rva < end) rel_sec = &sec[i];
    }

    unsigned char *is_packed = (unsigned char*)calloc(nsec, 1);
    int *packed_idx = (int*)malloc(nsec * sizeof(int));
    int pack_count = 0;
    for (DWORD i = 0; i < nsec; i++) {
        if (!sec[i].SizeOfRawData) continue;
        if (!strncmp((char*)sec[i].Name, ".reloc", 8)) continue;
        if (!strncmp((char*)sec[i].Name, ".idata", 8)) continue;
        if (!strncmp((char*)sec[i].Name, ".tls",   8)) continue;
        if (!strncmp((char*)sec[i].Name, ".pdata", 8)) continue;
        if (!strncmp((char*)sec[i].Name, ".rsrc",  8)) continue;
        if (&sec[i] == imp_sec || &sec[i] == rel_sec) continue;
        is_packed[i] = 1;
        packed_idx[pack_count++] = (int)i;
    }
    if (!pack_count) { puts("nothing to pack"); return 1; }

    typedef struct { DWORD rva, orig_sz, packed_sz, key; unsigned char *data; } PS;
    PS *ps = (PS*)calloc(pack_count, sizeof(PS));
    DWORD total_packed = 0;

    unsigned char global_key[32];
    for (int i = 0; i < 32; i++) global_key[i] = (unsigned char)(rand() & 0xFF);

    for (int i = 0; i < pack_count; i++) {
        IMAGE_SECTION_HEADER *s = &sec[packed_idx[i]];
        unsigned char *src = fd + s->PointerToRawData;
        unsigned char *buf = (unsigned char*)malloc(s->SizeOfRawData * 2 + 64);
        int clen = lz4_compress(src, s->SizeOfRawData, buf);
        payload_encode(buf, (DWORD)clen, global_key);
        ps[i] = (PS){ s->VirtualAddress, s->SizeOfRawData, (DWORD)clen, 0, buf };
        total_packed += clen;
        printf("  %-8s rva=%08X raw=%8u -> %8u (%.0f%%)\n",
               s->Name, s->VirtualAddress, s->SizeOfRawData, clen,
               100.0 * clen / (s->SizeOfRawData ? s->SizeOfRawData : 1));
    }

    const char *stub_path = is64 ? "stub64.bin" : "stub32.bin";
    FILE *sf = fopen(stub_path, "rb");
    if (!sf) { printf("missing %s\n", stub_path); return 1; }
    fseek(sf, 0, SEEK_END); long stub_sz = ftell(sf); fseek(sf, 0, SEEK_SET);
    unsigned char *stub = (unsigned char*)malloc(stub_sz);
    fread(stub, 1, stub_sz, sf); fclose(sf);

    unsigned char *mstub = (unsigned char*)malloc(stub_sz + 64 * 24);
    int msz = 0, var_m = 0, fix_m = 0;
    for (int i = 0; i < (int)stub_sz; ) {
        if (is_marker(stub + i, (int)stub_sz - i, 0xCC)) {
            msz += gen_junk_var(mstub + msz, 20); i += 8; var_m++;
        } else if (is_marker(stub + i, (int)stub_sz - i, 0xDD)) {
            msz += gen_junk_fixed(mstub + msz, 8); i += 8; fix_m++;
        } else {
            mstub[msz++] = stub[i++];
        }
    }
    printf("mutated: %d var + %d fix, stub %ld -> %d bytes\n", var_m, fix_m, stub_sz, msz);
    if (var_m == 0 || fix_m == 0) {
        puts("WARNING: stub has no markers - did you rebuild stub*.bin with build.bat?");
    }

    /* ---- section name: legitimate linker names ---- */
    static const char *names[] = {
        ".text1", ".text2", ".data1", ".data2",
        ".rdata1", ".rdata2", ".reloc1", ".pdata1"
    };
    const char *chosen = names[rand() % (sizeof(names)/sizeof(names[0]))];
    char sec_name[9] = {0};
    strncpy(sec_name, chosen, 8);

    /* ---- random sled (not executed) ---- */
    DWORD sled_len = 16 + (rand() % 496);
    unsigned char *sled = (unsigned char*)malloc(sled_len);
    static const unsigned char sled_fill[] = {0x90,0x90,0x90,0x90,0x98,0x99,0x66,0x90};
    #define SLED_N (sizeof(sled_fill)/sizeof(sled_fill[0]))
    for (DWORD i = 0; i < sled_len; i++) sled[i] = sled_fill[rand() % SLED_N];

    /* ---- layout ---- */
    DWORD sizeImg = is64 ? nt->OptionalHeader.SizeOfImage
                         : ((IMAGE_NT_HEADERS32*)(fd + dos->e_lfanew))->OptionalHeader.SizeOfImage;
    DWORD new_rva  = align_up(sizeImg, sec_align);
    DWORD stub_va  = new_rva + sled_len;
    DWORD meta_rva = stub_va + msz;

    /* ---- patch meta_rva in stub body ---- */
    if (is64) {
        unsigned char pat[10] = {0x49,0xBE, 0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
        int off = find_seq(mstub, msz, pat, 10);
        if (off < 0) { puts("FATAL: meta magic (x64) not found"); return 1; }
        uint64_t mr = (uint64_t)meta_rva;
        memcpy(mstub + off + 2, &mr, 8);
    } else {
        unsigned char pat[5] = {0xBB, 0x44,0x33,0x22,0x11};
        int off = find_seq(mstub, msz, pat, 5);
        if (off < 0) { puts("FATAL: meta magic (x86) not found"); return 1; }
        uint32_t mr = (uint32_t)meta_rva;
        memcpy(mstub + off + 1, &mr, 4);
    }

    /* ---- build blob: sled + stub + metadata + payload ---- */
    DWORD meta_sz = 8 + (DWORD)pack_count * 16 + 32;
    DWORD padding_sz = (DWORD)(rand() % 256);
    DWORD blob_sz = sled_len + (DWORD)msz + meta_sz + total_packed + padding_sz;
    unsigned char *blob = (unsigned char*)malloc(blob_sz);
    unsigned char *p = blob;

    memcpy(p, sled, sled_len);      p += sled_len;
    memcpy(p, mstub, msz);          p += msz;

    *(DWORD*)p = orig_entry;         p += 4;
    *(DWORD*)p = (DWORD)pack_count;  p += 4;
    for (int i = 0; i < pack_count; i++) {
        *(DWORD*)p = ps[i].rva;       p += 4;
        *(DWORD*)p = ps[i].orig_sz;   p += 4;
        *(DWORD*)p = ps[i].packed_sz; p += 4;
        *(DWORD*)p = ps[i].key;       p += 4;
    }
    memcpy(p, global_key, 32);       p += 32;
    for (int i = 0; i < pack_count; i++) {
        memcpy(p, ps[i].data, ps[i].packed_sz); p += ps[i].packed_sz;
    }
    for (DWORD i = 0; i < padding_sz; i++) *p++ = (unsigned char)rand();

    /* ---- section offset table ----
       packed sections get fake_raw = file_align random bytes to keep
       SizeOfRawData non-zero (defeats "empty section" heuristic). */
    DWORD fake_raw = file_align;

    DWORD new_rsz = align_up(blob_sz, file_align);

    DWORD hdr_end = dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)
                  + nt->FileHeader.SizeOfOptionalHeader
                  + (nsec + 1) * sizeof(IMAGE_SECTION_HEADER);
    DWORD hdr_sz = align_up(hdr_end, file_align);

    DWORD cur = hdr_sz;
    DWORD *new_off = (DWORD*)calloc(nsec + 1, sizeof(DWORD));
    for (DWORD i = 0; i < nsec; i++) {
        if (is_packed[i]) {
            new_off[i] = cur;
            cur = align_up(cur + fake_raw, file_align);
        } else if (sec[i].SizeOfRawData) {
            new_off[i] = cur;
            cur = align_up(cur + sec[i].SizeOfRawData, file_align);
        }
    }
    new_off[nsec] = cur;
    DWORD out_sz = cur + new_rsz;

    unsigned char *out = (unsigned char*)calloc(out_sz, 1);
    memcpy(out, fd, hdr_sz);

    IMAGE_NT_HEADERS64 *o_nt = (IMAGE_NT_HEADERS64*)(out + ((IMAGE_DOS_HEADER*)out)->e_lfanew);
    IMAGE_SECTION_HEADER *o_s = (IMAGE_SECTION_HEADER*)((unsigned char*)&o_nt->OptionalHeader
                                  + nt->FileHeader.SizeOfOptionalHeader);
    o_nt->FileHeader.NumberOfSections = nsec + 1;
    o_nt->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

    /* ---- normalise DllCharacteristics ---- */
    {
        WORD c;
        if (is64) c = ((IMAGE_NT_HEADERS64*)o_nt)->OptionalHeader.DllCharacteristics;
        else      c = ((IMAGE_NT_HEADERS32*)o_nt)->OptionalHeader.DllCharacteristics;

        c &= (WORD)~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        c &= (WORD)~IMAGE_DLLCHARACTERISTICS_GUARD_CF;
        c &= (WORD)~IMAGE_DLLCHARACTERISTICS_CET_COMPAT;
        c |=  (WORD)IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

        if (is64) ((IMAGE_NT_HEADERS64*)o_nt)->OptionalHeader.DllCharacteristics = c;
        else      ((IMAGE_NT_HEADERS32*)o_nt)->OptionalHeader.DllCharacteristics = c;
    }

    if (is64) {
        o_nt->OptionalHeader.AddressOfEntryPoint = stub_va;
        o_nt->OptionalHeader.SizeOfImage         = new_rva + align_up(blob_sz, sec_align);
        o_nt->OptionalHeader.SizeOfHeaders       = hdr_sz;
    } else {
        IMAGE_NT_HEADERS32 *o_nt32 = (IMAGE_NT_HEADERS32*)(out + ((IMAGE_DOS_HEADER*)out)->e_lfanew);
        o_nt32->OptionalHeader.AddressOfEntryPoint = stub_va;
        o_nt32->OptionalHeader.SizeOfImage         = new_rva + align_up(blob_sz, sec_align);
        o_nt32->OptionalHeader.SizeOfHeaders       = hdr_sz;
    }

    /* ---- packed sections: fake_raw random bytes; survivors copied intact ---- */
    for (DWORD i = 0; i < nsec; i++) {
        IMAGE_SECTION_HEADER *s = &o_s[i];
        if (is_packed[i]) {
            s->SizeOfRawData    = fake_raw;
            s->PointerToRawData = new_off[i];
            for (DWORD k = 0; k < fake_raw; k++)
                out[new_off[i] + k] = (unsigned char)rand();
            s->Characteristics |= IMAGE_SCN_MEM_WRITE;
        } else if (sec[i].SizeOfRawData) {
            s->PointerToRawData = new_off[i];
            s->SizeOfRawData    = sec[i].SizeOfRawData;
            memcpy(out + new_off[i], fd + sec[i].PointerToRawData, sec[i].SizeOfRawData);
        }
    }

    /* ---- the appended section ---- */
    IMAGE_SECTION_HEADER *ns = &o_s[nsec];
    memset(ns, 0, sizeof(*ns));
    memcpy(ns->Name, sec_name, 8);
    ns->Misc.VirtualSize = blob_sz;
    ns->VirtualAddress   = new_rva;
    ns->SizeOfRawData    = new_rsz;
    ns->PointerToRawData = new_off[nsec];
    ns->Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
                         | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    memcpy(out + new_off[nsec], blob, blob_sz);

    /* ---- compute and write CheckSum ---- */
    DWORD csum_off = dos->e_lfanew + 4 + 20 + 64;
    if (is64) ((IMAGE_NT_HEADERS64*)(out + dos->e_lfanew))->OptionalHeader.CheckSum = 0;
    else      ((IMAGE_NT_HEADERS32*)(out + dos->e_lfanew))->OptionalHeader.CheckSum = 0;
    DWORD sum = calc_checksum(out, out_sz, csum_off);
    if (is64) ((IMAGE_NT_HEADERS64*)(out + dos->e_lfanew))->OptionalHeader.CheckSum = sum;
    else      ((IMAGE_NT_HEADERS32*)(out + dos->e_lfanew))->OptionalHeader.CheckSum = sum;

    FILE *of = fopen(argv[2], "wb");
    if (!of) { perror("fopen out"); return 1; }
    fwrite(out, 1, out_sz, of); fclose(of);

    printf("section: %s  sled=%lu  oep=%08lX\n", sec_name,
           (unsigned long)sled_len, (unsigned long)stub_va);
    printf("input  : %8ld   packed : %8u (%.0f%%)\n",
           fsize, out_sz, 100.0 * out_sz / fsize);

    for (int i = 0; i < pack_count; i++) free(ps[i].data);
    free(ps); free(packed_idx); free(is_packed); free(new_off);
    free(stub); free(mstub); free(blob); free(sled); free(fd); free(out);
    return 0;
}
