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
# Number mapping is populated dynamically in configure_project from ELF relocations.
# Each call-site address is mapped to its symbol name. We initialize an empty
# mapping here so the ABI exists when configure_project runs.
syscall_lib.add_number_mapping_from_dict("solana", {})


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
        self._register_syscalls_from_relocations()
        self._preregister_call_targets()

    def _preregister_call_targets(self):
        """Pre-register all internal CALL targets as returning functions.

        sBPF functions always return via EXIT (Ijk_Ret).  CFGFast determines
        ``returning`` status *after* analyzing each function, but fragmented
        functions that lack an EXIT block get marked ``returning=False``,
        which prevents CFGFast from creating return-continuation edges at
        call sites.  This cascades: callers of "non-returning" functions
        also get marked non-returning, fragmenting the entire CFG.

        By pre-registering every CALL target with ``returning=True`` before
        CFGFast runs, ``_is_call_returning()`` immediately returns ``True``,
        FakeRet edges are created at every call site, and
        ``_analyze_function_features`` skips functions whose returning status
        is already determined — so the ``True`` persists.
        """
        import struct
        l = __import__("logging").getLogger(__name__)

        main_obj = self.project.loader.main_object
        text_sec = main_obj.sections_map.get(".text")
        if text_sec is None:
            return

        try:
            raw = self.project.loader.memory.load(
                text_sec.min_addr, text_sec.max_addr - text_sec.min_addr,
            )
        except Exception:
            return

        call_targets = set()
        for i in range(0, len(raw) - 7, 8):
            if raw[i] == 0x85:  # CALL
                imm = struct.unpack("<i", raw[i + 4:i + 8])[0]
                if imm == -1:  # syscall
                    continue
                target = text_sec.min_addr + i + (imm + 1) * 8
                if text_sec.min_addr <= target < text_sec.max_addr:
                    call_targets.add(target)

        # Also include the entry point
        call_targets.add(self.project.entry)

        for target in call_targets:
            func = self.project.kb.functions.function(addr=target, create=True)
            if func is not None:
                func.returning = True

        l.info("Pre-registered %d CALL targets as returning functions", len(call_targets))

    def _register_syscalls_from_relocations(self):
        """Register syscall mappings from type-10 ELF relocations.

        sBPF CALL instructions with imm=-1 are syscalls. The lifter emits
        Ijk_Sys_syscall with the call-site address as the syscall number.
        This method reads type-10 relocations to map each call-site address
        to the corresponding SimProcedure via the syscall library.

        This approach avoids hooking CALL instruction addresses, which would
        cause CFGFast to split functions at every syscall call site.
        """
        import logging
        l = logging.getLogger(__name__)

        name_to_proc = {name: cls for name, (_, cls) in SOLANA_SYSCALLS.items()}

        main_obj = self.project.loader.main_object
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.relocation import RelocationSection
        except ImportError:
            return

        if not hasattr(main_obj, 'binary'):
            return

        # Build a mapping of {call_site_addr: proc_name} for the syscall library
        addr_to_name = {}

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
                        if rel['r_info_type'] != 10:
                            continue
                        sym = symtab.get_symbol(rel['r_info_sym'])
                        if sym is None or not sym.name:
                            continue
                        sym_name = sym.name

                        # Resolve to a SimProcedure name in our library
                        proc_name = None
                        if sym_name in name_to_proc:
                            proc_name = sym_name
                        elif sym_name + "_" in name_to_proc:
                            proc_name = sym_name + "_"
                        elif sym_name == "sol_invoke_signed_rust":
                            proc_name = "sol_invoke_signed_c"

                        if proc_name is None:
                            l.debug("No SimProcedure for sBPF symbol: %s", sym_name)
                            continue

                        call_addr = rel['r_offset']
                        addr_to_name[call_addr] = proc_name
                        l.info("Registered syscall %s at call site %#x", sym_name, call_addr)

        except Exception as e:
            l.warning("Failed to process sBPF relocations: %s", e)
            return

        if not addr_to_name:
            return

        # Add call-site address → procedure name mappings to the syscall library.
        # The lifter stores self.addr in the syscall register for imm=-1 calls.
        syscall_lib.add_number_mapping_from_dict(
            "solana",
            {addr: name for addr, name in addr_to_name.items()},
        )

    def state_blank(self, *args, **kwargs):
        state = super().state_blank(*args, **kwargs)

        # R1 points to the serialized account input data
        input_addr = BVV(INPUT_REGION_ADDR, 64)
        state.regs.R1 = input_addr

        return state


register_simos("SolanaBPF", SimSolana)
