#!/usr/bin/env python3
"""Apply small, pinned-source hardening overlays to the external ELF helpers.

The submodules are pinned by the parent repository and are not writable through
this checkout's GitHub connection. Keeping the changes here makes the build
reproducible without pretending to modify upstream repositories.
"""
from pathlib import Path
import sys

def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"Cannot apply {label}: source anchor changed in {path}")
    path.write_text(text.replace(old, new, 1))

def patch_plti(root: Path) -> None:
    path = root / "src/elf_util.c"
    replace_once(
        path,
        """struct sleb128_decoder {
  const uint8_t *current;
  const uint8_t *end;
};

static void sleb128_decoder_init(struct sleb128_decoder *decoder, const uint8_t *buffer, size_t count) {
  decoder->current = buffer;
  decoder->end = buffer + count;
}

static int64_t sleb128_decode(struct sleb128_decoder *decoder) {
  int64_t value = 0;
  size_t shift = 0;
  uint8_t byte;
  const size_t size = sizeof(int64_t) * CHAR_BIT;

  do {
    if (decoder->current >= decoder->end)
      LOGF("Failed to decode SLEB128: buffer overrun");

    byte = *decoder->current++;
    value |= ((int64_t)(byte & 0x7F)) << shift;
    shift += 7;
  } while (byte & 0x80);

  if (shift < size && (byte & 0x40)) {
    value |= -((int64_t)1 << shift);
  }

  return value;
}""",
        """struct sleb128_decoder {
  const uint8_t *current;
  const uint8_t *end;
  bool failed;
};

static void sleb128_decoder_init(struct sleb128_decoder *decoder, const uint8_t *buffer, size_t count) {
  decoder->current = buffer;
  decoder->end = buffer + count;
  decoder->failed = false;
}

/* A signed 64-bit LEB128 value is at most ten bytes. Malformed relocation
   streams must fail closed rather than reading past the dynamic section or
   shifting by 64 (undefined behaviour). */
static int64_t sleb128_decode(struct sleb128_decoder *decoder) {
  uint64_t value = 0;
  unsigned shift = 0;

  for (unsigned i = 0; i < 10; i++) {
    if (decoder->current >= decoder->end) {
      decoder->failed = true;
      return 0;
    }

    uint8_t byte = *decoder->current++;
    uint8_t payload = byte & 0x7f;

    if (shift == 63 && payload != 0 && payload != 0x7f) {
      decoder->failed = true;
      return 0;
    }

    value |= (uint64_t)payload << shift;
    shift += 7;

    if ((byte & 0x80) == 0) {
      if (shift < 64 && (byte & 0x40)) value |= UINT64_MAX << shift;
      return (int64_t)value;
    }
  }

  decoder->failed = true;
  return 0;
}""",
        "PLTI bounded SLEB128 decoder",
    )
    replace_once(
        path,
        """  uint64_t num_relocs = sleb128_decode(&decoder);
  if (num_relocs <= 0) return false;""",
        """  uint64_t num_relocs = (uint64_t)sleb128_decode(&decoder);
  /* Each relocation consumes at least one input byte. This also bounds the
     allocation requested by an untrusted or corrupted APS2 stream. */
  if (decoder.failed || num_relocs == 0 || num_relocs > elf->rel_android_size_) return false;""",
        "PLTI relocation count bound",
    )
    replace_once(
        path,
        """  for (uint64_t i = 0; i < num_relocs; ) {
    uint64_t group_size = sleb128_decode(&decoder);
    uint64_t group_flags = sleb128_decode(&decoder);

    size_t group_r_offset_delta = 0;""",
        """  for (uint64_t i = 0; i < num_relocs; ) {
    uint64_t group_size = (uint64_t)sleb128_decode(&decoder);
    uint64_t group_flags = (uint64_t)sleb128_decode(&decoder);

    if (decoder.failed || group_size == 0 || group_size > num_relocs - i ||
        (group_flags & ~UINT64_C(0x0f)) != 0) {
      free(entries);
      return false;
    }

    size_t group_r_offset_delta = 0;""",
        "PLTI relocation group bounds",
    )
    replace_once(
        path,
        """  buffer->data = entries;
  buffer->size = out_index * (elf->rel_android_is_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));""",
        """  if (decoder.failed || out_index != num_relocs) {
    free(entries);
    return false;
  }

  buffer->data = entries;
  buffer->size = out_index * (elf->rel_android_is_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));""",
        "PLTI decoder final validation",
    )

def patch_csoloader(root: Path) -> None:
    path = root / "src/elf_util.c"
    replace_once(
        path,
        """static ElfW(Word) *offsetOf_Word(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (ElfW(Word) *)(((uintptr_t)head) + off);
}

static int dl_cb""",
        """static ElfW(Word) *offsetOf_Word(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (ElfW(Word) *)(((uintptr_t)head) + off);
}

/* Validate all file-backed ELF tables before turning their offsets into
   pointers. Module shared objects are supplied by third parties; a malformed
   section/program table must not make the loader walk outside the file copy. */
static bool elf_file_range_valid(size_t file_size, uint64_t offset, uint64_t length) {
  return offset <= file_size && length <= (uint64_t)file_size - offset;
}

static bool elf_validate_file_tables(const struct csoloader_elf *img) {
  if (!img || !img->header || img->size < sizeof(ElfW(Ehdr))) return false;

  const ElfW(Ehdr) *ehdr = img->header;
  if (ehdr->e_ehsize != sizeof(ElfW(Ehdr)) ||
      ehdr->e_phentsize != sizeof(ElfW(Phdr)) ||
      ehdr->e_phnum == 0 ||
      !elf_file_range_valid(img->size, ehdr->e_phoff,
                            (uint64_t)ehdr->e_phnum * sizeof(ElfW(Phdr)))) return false;

  ElfW(Phdr) *phdr = (ElfW(Phdr) *)((uintptr_t)img->header + ehdr->e_phoff);
  bool has_load = false;
  bool has_dynamic = false;
  for (size_t i = 0; i < ehdr->e_phnum; i++) {
    const ElfW(Phdr) *ph = &phdr[i];
    if (ph->p_memsz < ph->p_filesz ||
        !elf_file_range_valid(img->size, ph->p_offset, ph->p_filesz) ||
        ph->p_vaddr + ph->p_memsz < ph->p_vaddr) return false;
    if (ph->p_type == PT_LOAD && ph->p_memsz != 0) has_load = true;
    if (ph->p_type == PT_DYNAMIC) {
      if (ph->p_memsz < sizeof(ElfW(Dyn)) ||
          ph->p_memsz % sizeof(ElfW(Dyn)) != 0) return false;
      has_dynamic = true;
    }
  }
  if (!has_load || !has_dynamic) return false;

  /* Fully stripped ELF files may omit section headers. Partial or extended
     section-header encodings are rejected rather than interpreted loosely. */
  if (ehdr->e_shoff == 0 && ehdr->e_shnum == 0 && ehdr->e_shentsize == 0)
    return ehdr->e_shstrndx == SHN_UNDEF;
  if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 ||
      ehdr->e_shentsize != sizeof(ElfW(Shdr)) ||
      !elf_file_range_valid(img->size, ehdr->e_shoff,
                            (uint64_t)ehdr->e_shnum * sizeof(ElfW(Shdr)))) return false;
  if (ehdr->e_shstrndx != SHN_UNDEF && ehdr->e_shstrndx >= ehdr->e_shnum) return false;

  ElfW(Shdr) *shdr = (ElfW(Shdr) *)((uintptr_t)img->header + ehdr->e_shoff);
  const ElfW(Shdr) *shstr = NULL;
  if (ehdr->e_shstrndx != SHN_UNDEF) {
    shstr = &shdr[ehdr->e_shstrndx];
    if (shstr->sh_type != SHT_STRTAB ||
        !elf_file_range_valid(img->size, shstr->sh_offset, shstr->sh_size) ||
        shstr->sh_size == 0) return false;
  }

  for (size_t i = 0; i < ehdr->e_shnum; i++) {
    const ElfW(Shdr) *sh = &shdr[i];
    if (sh->sh_type != SHT_NOBITS &&
        !elf_file_range_valid(img->size, sh->sh_offset, sh->sh_size)) return false;
    if (shstr) {
      if (sh->sh_name >= shstr->sh_size ||
          memchr((const char *)img->header + shstr->sh_offset + sh->sh_name,
                 '\\0', shstr->sh_size - sh->sh_name) == NULL) return false;
    }
    if (sh->sh_type == SHT_DYNSYM || sh->sh_type == SHT_SYMTAB) {
      if (sh->sh_entsize != sizeof(ElfW(Sym)) ||
          sh->sh_size % sizeof(ElfW(Sym)) != 0 ||
          sh->sh_link >= ehdr->e_shnum) return false;
    }
  }

  return true;
}

static int dl_cb""",
        "CSOLoader ELF table validator",
    )
    replace_once(
        path,
        """  if (memcmp(img->header->e_ident, ELFMAG, SELFMAG) != 0) {
    LOGE("Invalid ELF header for %s", img->elf);

    csoloader_elf_destroy(img);

    return NULL;
  }

  if (img->header->e_shoff == 0""",
        """  if (memcmp(img->header->e_ident, ELFMAG, SELFMAG) != 0 ||
      !elf_validate_file_tables(img)) {
    LOGE("Invalid or out-of-bounds ELF tables for %s", img->elf);

    csoloader_elf_destroy(img);

    return NULL;
  }

  if (img->header->e_shoff == 0""",
        "CSOLoader ELF table validation call",
    )
    replace_once(
        path,
        """    ElfW(Addr) dynamic_vaddr = 0;
    bool dynamic_found = false;""",
        """    ElfW(Addr) dynamic_vaddr = 0;
    size_t dynamic_size = 0;
    bool dynamic_found = false;""",
        "CSOLoader dynamic size",
    )
    replace_once(
        path,
        """      if (phdr[i].p_type == PT_DYNAMIC) {
        dynamic_vaddr = phdr[i].p_vaddr;
        dynamic_found = true;""",
        """      if (phdr[i].p_type == PT_DYNAMIC) {
        dynamic_vaddr = phdr[i].p_vaddr;
        dynamic_size = phdr[i].p_memsz;
        dynamic_found = true;""",
        "CSOLoader dynamic segment size",
    )
    replace_once(
        path,
        """    if (dyn) for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; ++d) {
      uintptr_t ptr_val = (uintptr_t)img->base + d->d_un.d_ptr - img->bias;""",
        """    bool dynamic_terminated = false;
    if (dyn) for (ElfW(Dyn) *d = dyn;
                   (uintptr_t)d < (uintptr_t)dyn + dynamic_size; ++d) {
      if (d->d_tag == DT_NULL) {
        dynamic_terminated = true;
        break;
      }
      uintptr_t ptr_val = (uintptr_t)img->base + d->d_un.d_ptr - img->bias;""",
        "CSOLoader bounded dynamic scan",
    )
    replace_once(
        path,
        """    }

    /* INFO: Populate EH regions from Program Headers when possible */""",
        """    }

    if (!dynamic_terminated) {
      LOGE("PT_DYNAMIC has no DT_NULL terminator in %s", img->elf);
      csoloader_elf_destroy(img);
      return NULL;
    }

    /* INFO: Populate EH regions from Program Headers when possible */""",
        "CSOLoader dynamic terminator check",
    )

def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: patch-submodules.py <PLTI-dir> <CSOLoader-dir>")
    patch_plti(Path(sys.argv[1]))
    patch_csoloader(Path(sys.argv[2]))

if __name__ == "__main__":
    main()
