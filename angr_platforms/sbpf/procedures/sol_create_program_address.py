from angr.sim_procedure import SimProcedure
from claripy import BVS, BVV


class SolCreateProgramAddress(SimProcedure):
    """sol_create_program_address(seeds: u64, seeds_len: u64,
                                   program_id: u64, address_out: u64) -> u64

    Derives a program address (PDA) from seeds and a program ID.
    Returns 0 on success, non-zero if the derived address is on the ed25519 curve.

    Since PDA derivation involves SHA-256, we model the output as symbolic.
    """

    def run(self, seeds, seeds_len, program_id, address_out):
        sym_addr = BVS("pda_address", 256)
        self.state.memory.store(address_out, sym_addr)
        return 0


class SolTryFindProgramAddress(SimProcedure):
    """sol_try_find_program_address(seeds: u64, seeds_len: u64,
                                     program_id: u64, address_out: u64,
                                     bump_seed_out: u64) -> u64

    Finds a valid PDA by iterating bump seeds from 255 down to 0.
    Returns 0 on success.
    """

    def run(self, seeds, seeds_len, program_id, address_out, bump_seed_out):
        sym_addr = BVS("pda_address", 256)
        self.state.memory.store(address_out, sym_addr)
        # Bump seed is a single byte (0-255)
        sym_bump = BVS("pda_bump", 8)
        self.state.memory.store(bump_seed_out, sym_bump)
        self.state.add_constraints(sym_bump.ULE(255))
        return 0
