"""
sBPF ELF relocation types.

Type 8:  R_BPF_64_RELATIVE — adjusts addresses for load base (lddw data refs)
Type 10: R_BPF_64_32 — 32-bit symbol reference (syscalls, named function calls)

Standard BPF types (1-4) included for completeness.

BPF instructions are 8 bytes: [opcode(1), regs(1), offset(2), immediate(4)].
Relocations that patch the immediate field must read/write only bytes 4-7,
not the full 8-byte instruction.
"""

import struct

from cle.backends.elf.relocation.elfreloc import ELFReloc
from cle.backends.elf.relocation import ALL_RELOCATIONS


class BPFImmRelocMixin:
    """Mixin that reads/writes the 32-bit immediate field (bytes 4-7) of a
    BPF instruction, rather than the full native word at the relocation offset."""

    def _read_imm32(self):
        """Read the 32-bit immediate at relative_addr + 4."""
        data = self.owner.memory.load(self.relative_addr + 4, 4)
        return struct.unpack("<i", data)[0]  # signed 32-bit LE

    def _write_imm32(self, value):
        """Write a 32-bit value at relative_addr + 4."""
        self.owner.memory.store(
            self.relative_addr + 4,
            struct.pack("<I", value & 0xFFFFFFFF),
        )

    def relocate(self):
        if not self.resolved:
            return False
        self._write_imm32(self.value)
        return True


class R_BPF_64_64(ELFReloc):
    """Type 1: 64-bit absolute relocation (lddw)."""

    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend


class R_BPF_64_ABS64(ELFReloc):
    """Type 2: 64-bit absolute."""

    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend


class R_BPF_64_ABS32(BPFImmRelocMixin, ELFReloc):
    """Type 3: 32-bit absolute."""

    @property
    def value(self):
        return (self.resolvedby.rebased_addr + self.addend) & 0xFFFFFFFF


class R_BPF_64_NODYLD32(BPFImmRelocMixin, ELFReloc):
    """Type 4: 32-bit, no dynamic linking."""

    @property
    def value(self):
        return (self.resolvedby.rebased_addr + self.addend) & 0xFFFFFFFF


class R_BPF_64_RELATIVE(ELFReloc):
    """Type 8: Relative relocation (Solana-specific).

    Handles both instruction and data relocations:
    - In .text (lddw instructions): patches the 32-bit immediate at offset+4.
    - In data sections (.data.rel.ro vtable entries): patches the full 64-bit
      value so that ldxdw loads a valid function pointer.

    In both cases the addend is read from bytes 4-7 (the 32-bit imm field
    of the lddw layout that the Solana linker uses uniformly).
    """

    AUTO_HANDLE_NONE = True

    def __init__(self, owner, symbol, relative_addr, addend=None):
        if addend is None:
            # Addend is always in bytes 4-7 (lddw imm layout), even for data
            data = owner.memory.load(relative_addr + 4, 4)
            addend = struct.unpack("<i", data)[0]
        super().__init__(owner, symbol, relative_addr, addend=addend)
        # Determine if this reloc targets a lddw instruction (code) or a
        # data entry (vtable pointer).  lddw always starts with opcode 0x18.
        # We check the byte directly rather than using section info because
        # sections may not be fully populated during early CLE loading.
        try:
            opcode = owner.memory.load(relative_addr, 1)[0]
            self._is_code = opcode == 0x18
        except Exception:
            self._is_code = False

    @property
    def value(self):
        if self.resolvedby is not None:
            return self.resolvedby.rebased_addr
        return self.owner.mapped_base + self.addend

    def relocate(self):
        if not self.resolved:
            return False
        if self._is_code:
            # lddw instruction: patch 32-bit immediate at offset+4
            self.owner.memory.store(
                self.relative_addr + 4,
                struct.pack("<I", self.value & 0xFFFFFFFF),
            )
        else:
            # Data section: write full 64-bit value so ldxdw reads a valid address
            self.owner.memory.store(
                self.relative_addr,
                struct.pack("<Q", self.value & 0xFFFFFFFFFFFFFFFF),
            )
        return True


class R_BPF_64_32(ELFReloc):
    """Type 10: 32-bit symbol reference.

    Used for CALL instructions referencing external symbols (syscalls)
    and named internal functions. We do NOT patch the instruction memory
    because syscall dispatch is handled via address-based hooks in SimSolana,
    and patching would corrupt the CALL immediate used for internal call
    target computation.
    """

    def relocate(self):
        # Intentionally a no-op: syscalls are hooked by SimSolana,
        # not dispatched via the immediate value.
        return True

    @property
    def value(self):
        return 0


relocation_table_sbpf = {
    1: R_BPF_64_64,
    2: R_BPF_64_ABS64,
    3: R_BPF_64_ABS32,
    4: R_BPF_64_NODYLD32,
    8: R_BPF_64_RELATIVE,
    10: R_BPF_64_32,
}

ALL_RELOCATIONS["sBPF"] = relocation_table_sbpf
