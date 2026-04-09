"""
sBPF ELF relocation types.

Type 8:  R_BPF_64_RELATIVE — adjusts addresses for load base (internal calls, data refs)
Type 10: R_BPF_64_32 — 32-bit symbol reference (syscalls, named function calls)

Standard BPF types (1-4) included for completeness.
"""

from cle.backends.elf.relocation.elfreloc import ELFReloc
from cle.backends.elf.relocation import ALL_RELOCATIONS


class R_BPF_64_64(ELFReloc):
    """Type 1: 64-bit absolute relocation."""

    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend


class R_BPF_64_ABS64(ELFReloc):
    """Type 2: 64-bit absolute."""

    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend


class R_BPF_64_ABS32(ELFReloc):
    """Type 3: 32-bit absolute."""

    @property
    def value(self):
        return (self.resolvedby.rebased_addr + self.addend) & 0xFFFFFFFF


class R_BPF_64_NODYLD32(ELFReloc):
    """Type 4: 32-bit, no dynamic linking."""

    @property
    def value(self):
        return (self.resolvedby.rebased_addr + self.addend) & 0xFFFFFFFF


class R_BPF_64_RELATIVE(ELFReloc):
    """Type 8: Relative relocation (Solana-specific).

    Used for internal function calls and data references.
    Adjusts values by the load base address.
    """

    AUTO_HANDLE_NONE = True

    @property
    def value(self):
        if self.resolvedby is not None:
            return self.resolvedby.rebased_addr
        return self.owner.mapped_base + self.addend


class R_BPF_64_32(ELFReloc):
    """Type 10: 32-bit symbol reference.

    Used for CALL instructions referencing external symbols (syscalls)
    and named internal functions. Patches the 32-bit immediate field.
    """

    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend


relocation_table_sbpf = {
    1: R_BPF_64_64,
    2: R_BPF_64_ABS64,
    3: R_BPF_64_ABS32,
    4: R_BPF_64_NODYLD32,
    8: R_BPF_64_RELATIVE,
    10: R_BPF_64_32,
}

ALL_RELOCATIONS["sBPF"] = relocation_table_sbpf
