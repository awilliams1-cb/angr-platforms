from angr.sim_procedure import SimProcedure


class SolMemcpy(SimProcedure):
    """sol_memcpy_(dst: u64, src: u64, n: u64) -> u64

    Copies n bytes from src to dst. Non-overlapping.
    """

    def run(self, dst, src, n):
        data = self.state.memory.load(src, n)
        self.state.memory.store(dst, data)
        return 0


class SolMemmove(SimProcedure):
    """sol_memmove_(dst: u64, src: u64, n: u64) -> u64

    Copies n bytes from src to dst. Handles overlapping regions.
    """

    def run(self, dst, src, n):
        data = self.state.memory.load(src, n)
        self.state.memory.store(dst, data)
        return 0


class SolMemcmp(SimProcedure):
    """sol_memcmp_(s1: u64, s2: u64, n: u64, result_ptr: u64) -> u64

    Compares n bytes. Stores result (0 if equal) at result_ptr.
    """

    def run(self, s1, s2, n, result_ptr):
        from claripy import BVV, If

        data1 = self.state.memory.load(s1, n)
        data2 = self.state.memory.load(s2, n)
        result = If(data1 == data2, BVV(0, 32), BVV(1, 32))
        self.state.memory.store(result_ptr, result, endness="Iend_LE")
        return 0


class SolMemset(SimProcedure):
    """sol_memset_(dst: u64, val: u64, n: u64) -> u64

    Sets n bytes at dst to val (low byte).
    """

    def run(self, dst, val, n):
        from claripy import BVV

        # Extract low byte from val
        byte_val = val[7:0]
        # For concrete n, unroll; for symbolic, store byte-by-byte up to a limit
        if self.state.solver.symbolic(n):
            # Conservative: store symbolic byte pattern
            for i in range(256):  # cap at 256 for symbolic
                cond = self.state.solver.UGT(n, i)
                if self.state.solver.is_false(cond):
                    break
                self.state.memory.store(dst + i, byte_val, condition=cond)
        else:
            length = self.state.solver.eval(n)
            if length > 0:
                pattern = byte_val
                for _ in range(length - 1):
                    pattern = pattern.concat(byte_val)
                self.state.memory.store(dst, pattern)
        return 0
