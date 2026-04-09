from archinfo import Arch, Endness, Register, RegisterOffset, register_arch
from archinfo.tls import TLSArchInfo


class ArchSBPF(Arch):
    """Solana BPF (sBPF) architecture."""

    name = "sBPF"
    bits = 64

    vex_arch = None
    qemu_name = "sBPF"
    ida_processor = "sBPF"

    max_inst_bytes = 16  # lddw is 16 bytes (two 8-byte slots)
    instruction_alignment = 8  # all sBPF instructions are 8-byte aligned

    def __init__(self, endness=Endness.LE):
        super().__init__(endness)

    register_list = [
        # return value
        Register(name="R0", vex_offset=0, size=8),
        # arguments from program to syscalls
        Register(name="R1", vex_offset=8, size=8, argument=True),
        Register(name="R2", vex_offset=16, size=8, argument=True),
        Register(name="R3", vex_offset=24, size=8, argument=True),
        Register(name="R4", vex_offset=32, size=8, argument=True),
        Register(name="R5", vex_offset=40, size=8, argument=True),
        # callee-saved registers
        Register(name="R6", vex_offset=48, size=8, general_purpose=True),
        Register(name="R7", vex_offset=56, size=8, general_purpose=True),
        Register(name="R8", vex_offset=64, size=8, general_purpose=True),
        Register(name="R9", vex_offset=72, size=8, general_purpose=True),
        # read-only frame pointer / stack pointer
        Register(
            name="R10",
            vex_offset=80,
            size=8,
            alias_names=("sp", "bp", "fp"),
            default_value=(Arch.initial_sp, True, (Arch.initial_sp, "stack")),
        ),
        # syscall number extracted from CALL instruction
        Register(name="syscall", vex_offset=88, size=8, artificial=True),
        Register(name="ip", vex_offset=96, size=8),
        Register(name="ip_at_syscall", vex_offset=104, size=8, artificial=True),
    ]
    bp_offset = RegisterOffset(80)
    ret_offset = RegisterOffset(0)       # R0 — return value register
    lr_offset = RegisterOffset(104)      # ip_at_syscall — return address for syscalls
    elf_tls = TLSArchInfo(1, 0, [], [0], [], 0, 0)  # dummy — sBPF has no TLS


register_arch(["sbpf", "bpf", "solana"], 64, "any", ArchSBPF)
