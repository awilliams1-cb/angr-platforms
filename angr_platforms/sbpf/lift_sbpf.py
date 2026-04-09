from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter

from .instrs_sbpf import ALU, Jump, LoadStore


class LifterSBPF(GymratLifter):
    """Lifter for Solana BPF (sBPF)"""

    instrs = list(ALU | Jump | LoadStore)


register(LifterSBPF, "sBPF")
