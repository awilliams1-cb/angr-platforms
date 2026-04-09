from angr.procedures.definitions import SimSyscallLibrary
from angr.calling_conventions import (
    SimCC,
    SimCCSyscall,
    register_default_cc,
    SimRegArg,
    register_syscall_cc,
)
from angr.simos import SimUserland, register_simos
from angr.sim_procedure import SimProcedure
from claripy import BVS, BVV

from . import ArchSBPF
from .procedures import (
    SolLog,
    SolLog64,
    SolLogPubkey,
    SolLogComputeUnits,
    SolMemcpy,
    SolMemmove,
    SolMemcmp,
    SolMemset,
    SolAllocFree,
    SolPanic,
    SolSha256,
    SolKeccak256,
    SolCreateProgramAddress,
    SolTryFindProgramAddress,
    SolInvokeSigned,
    SolGetClockSysvar,
    SolGetRentSysvar,
    SolSetReturnData,
    SolGetReturnData,
)


class SimCcSBPF(SimCC):
    """Calling convention for sBPF"""

    ARCH = ArchSBPF

    ARG_REGS = ["R1", "R2", "R3", "R4", "R5"]
    CALLER_SAVED_REGS = ["R6", "R7", "R8", "R9"]

    RETURN_VAL = SimRegArg("R0", 8)


register_default_cc("sBPF", SimCcSBPF)


class SimCcSyscallSBPF(SimCCSyscall):
    """Syscall calling convention for sBPF.

    Solana dispatches syscalls by hash: the CALL instruction's immediate operand
    is a murmur3 hash of the syscall name, stored in the 'syscall' register.
    """

    ARCH = ArchSBPF

    ARG_REGS = ["R1", "R2", "R3", "R4", "R5"]
    CALLER_SAVED_REGS = ["R6", "R7", "R8", "R9"]

    RETURN_VAL = SimRegArg("R0", 8)
    RETURN_ADDR = SimRegArg("ip_at_syscall", 8)

    @staticmethod
    def syscall_num(state):
        return state.regs.syscall


register_syscall_cc("sBPF", "default", SimCcSyscallSBPF)
register_syscall_cc("sBPF", "SolanaBPF", SimCcSyscallSBPF)
register_syscall_cc("sBPF", "solana", SimCcSyscallSBPF)


class ExitSimProcedure(SimProcedure):
    """End of sBPF program"""

    NO_RET = True
    ADDS_EXITS = True

    def run(self):
        self.exit(self.state.regs.R0)


# Solana syscall hash -> name mapping
# Hashes are murmur3-32 of the syscall function name
SOLANA_SYSCALLS = {
    "sol_log_": (0x71E3CF81, SolLog),
    "sol_log_64_": (0x0E83F6C6, SolLog64),
    "sol_log_pubkey": (0x7EF088CA, SolLogPubkey),
    "sol_log_compute_units_": (0x8E542497, SolLogComputeUnits),
    "sol_memcpy_": (0xB10B3C7E, SolMemcpy),
    "sol_memmove_": (0x978E258F, SolMemmove),
    "sol_memcmp_": (0x5FDCDE31, SolMemcmp),
    "sol_memset_": (0xA97D3F26, SolMemset),
    "sol_alloc_free_": (0xC83FBB85, SolAllocFree),
    "sol_panic_": (0xB31EC789, SolPanic),
    "sol_sha256": (0x2BBEE21E, SolSha256),
    "sol_keccak256": (0xB5199E49, SolKeccak256),
    "sol_create_program_address": (0xC93C75B2, SolCreateProgramAddress),
    "sol_try_find_program_address": (0xABCB0B77, SolTryFindProgramAddress),
    "sol_invoke_signed_c": (0xA22B9C85, SolInvokeSigned),
    "sol_get_clock_sysvar": (0xB3FBF63B, SolGetClockSysvar),
    "sol_get_rent_sysvar": (0x06F0E8E1, SolGetRentSysvar),
    "sol_set_return_data": (0xA9879553, SolSetReturnData),
    "sol_get_return_data": (0x95A7B588, SolGetReturnData),
    "abort": (0x856C0C37, SolPanic),  # abort maps to panic
}

syscall_lib = SimSyscallLibrary()
syscall_lib.set_library_names("SolanaBPF")
syscall_lib.add_all_from_dict({name: cls for name, (_, cls) in SOLANA_SYSCALLS.items()})
syscall_lib.add_number_mapping_from_dict(
    "solana", {hash_val: name for name, (hash_val, _) in SOLANA_SYSCALLS.items()}
)


# Solana memory layout constants
INPUT_REGION_ADDR = 0x100_000_000   # Account data input region
HEAP_START = 0x300_000_000          # Heap region (32KB)
HEAP_SIZE = 32 * 1024
STACK_SIZE = 4096


class SimSolana(SimUserland):
    """Simulate the Solana BPF runtime environment"""

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            syscall_library=syscall_lib,
            name="SolanaBPF",
            **kwargs,
        )

    def configure_project(self):
        super().configure_project(abi_list=["solana"])
        self._hook_syscalls_from_relocations()

    def _hook_syscalls_from_relocations(self):
        """Hook CALL instruction sites that reference known syscall symbols.

        sBPF binaries use R_BPF_64_32 (type 10) relocations to mark CALL
        instructions that target external symbols (syscalls). We read these
        relocations and hook each call site with the corresponding SimProcedure.
        """
        import logging
        l = logging.getLogger(__name__)

        # Build symbol name -> SimProcedure class mapping
        name_to_proc = {name: cls for name, (_, cls) in SOLANA_SYSCALLS.items()}

        main_obj = self.project.loader.main_object
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.relocation import RelocationSection
        except ImportError:
            return

        if not hasattr(main_obj, 'binary'):
            return

        try:
            with open(main_obj.binary, 'rb') as f:
                elf = ELFFile(f)
                dynsym = elf.get_section_by_name('.dynsym')
                if dynsym is None:
                    return

                for sec in elf.iter_sections():
                    if not isinstance(sec, RelocationSection):
                        continue
                    symtab = elf.get_section(sec['sh_link'])
                    for rel in sec.iter_relocations():
                        if rel['r_info_type'] != 10:  # R_BPF_64_32
                            continue
                        sym = symtab.get_symbol(rel['r_info_sym'])
                        if sym is None or not sym.name:
                            continue
                        sym_name = sym.name
                        # Map to SimProcedure
                        proc_cls = name_to_proc.get(sym_name)
                        if proc_cls is None:
                            # Try with trailing underscore variants
                            proc_cls = name_to_proc.get(sym_name + "_")
                            if proc_cls is None:
                                # Check for rust-style variant (sol_invoke_signed_rust -> sol_invoke_signed_c)
                                if sym_name == "sol_invoke_signed_rust":
                                    proc_cls = name_to_proc.get("sol_invoke_signed_c")
                        if proc_cls is None:
                            l.debug("No SimProcedure for sBPF symbol: %s", sym_name)
                            continue

                        # Hook the CALL instruction address.
                        # r_offset is already the ELF virtual address = CLE address.
                        call_addr = rel['r_offset']
                        if not self.project.is_hooked(call_addr):
                            self.project.hook(call_addr, proc_cls(), length=8)
                            l.info("Hooked sBPF syscall %s at %#x", sym_name, call_addr)
        except Exception as e:
            l.warning("Failed to process sBPF relocations for syscall hooking: %s", e)

    def state_blank(self, *args, **kwargs):
        state = super().state_blank(*args, **kwargs)

        # R1 points to the serialized account input data
        input_addr = BVV(INPUT_REGION_ADDR, 64)
        state.regs.R1 = input_addr

        return state


register_simos("SolanaBPF", SimSolana)
