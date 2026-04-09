from angr.sim_procedure import SimProcedure
from claripy import BVS


class SolSha256(SimProcedure):
    """sol_sha256(vals: u64, val_len: u64, hash_result: u64) -> u64

    Computes SHA-256 hash. Since we can't efficiently model the hash symbolically,
    we return a fresh symbolic 32-byte value.
    """

    def run(self, vals, val_len, hash_result):
        # Store a fresh symbolic 256-bit value at the result pointer
        sym_hash = BVS("sha256_result", 256)
        self.state.memory.store(hash_result, sym_hash)
        return 0
