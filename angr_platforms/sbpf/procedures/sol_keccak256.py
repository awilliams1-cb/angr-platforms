from angr.sim_procedure import SimProcedure
from claripy import BVS


class SolKeccak256(SimProcedure):
    """sol_keccak256(vals: u64, val_len: u64, hash_result: u64) -> u64

    Computes Keccak-256 hash. Returns a fresh symbolic 32-byte value.
    """

    def run(self, vals, val_len, hash_result):
        sym_hash = BVS("keccak256_result", 256)
        self.state.memory.store(hash_result, sym_hash)
        return 0
