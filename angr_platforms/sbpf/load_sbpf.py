import logging

from cle.backends import ELF, register_backend, ALL_BACKENDS

l = logging.getLogger(__name__)


class SolanaBPF(ELF):
    """CLE backend for Solana BPF ELF binaries.

    Auto-detects ELFs with e_machine == 247 (EM_BPF) or 263 (EM_SBPF).
    """

    is_default = True

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        ident = stream.read(20)
        stream.seek(0)
        if len(ident) < 20:
            return False
        if ident[:4] != b"\x7fELF":
            return False
        e_machine = int.from_bytes(ident[18:20], "little")
        return e_machine in (247, 263)

    def __init__(self, *args, **kwargs):
        from .arch_sbpf import ArchSBPF
        from . import reloc_sbpf  # noqa: F401 — registers relocation handlers

        super().__init__(*args, arch=ArchSBPF(), **kwargs)
        self.os = "SolanaBPF"


register_backend("sbpf", SolanaBPF)

# Move our backend to the front of ALL_BACKENDS so it's checked before the
# generic ELF backend (which also matches any ELF file).
_items = list(ALL_BACKENDS.items())
ALL_BACKENDS.clear()
ALL_BACKENDS["sbpf"] = SolanaBPF
for _k, _v in _items:
    if _k != "sbpf":
        ALL_BACKENDS[_k] = _v
