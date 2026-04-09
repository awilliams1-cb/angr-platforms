from angr.sim_procedure import SimProcedure
from claripy import BVV


# Solana heap: 32KB starting at 0x300000000
HEAP_START = 0x300_000_000
HEAP_SIZE = 32 * 1024


class SolAllocFree(SimProcedure):
    """sol_alloc_free_(size: u64, free_addr: u64) -> u64

    Bump allocator. If size > 0, allocates and returns pointer.
    If size == 0 and free_addr != 0, this is a free (no-op in bump allocator).
    Returns 0 on failure (out of memory).
    """

    HEAP_OFFSET_KEY = "sol_heap_offset"

    def run(self, size, free_addr):
        heap_offset = self.state.globals.get(self.HEAP_OFFSET_KEY, 0)

        # Free is a no-op in Solana's bump allocator
        if self.state.solver.is_true(size == 0):
            return 0

        if self.state.solver.symbolic(size):
            # For symbolic sizes, return a symbolic pointer but track the allocation
            ptr = BVV(HEAP_START + heap_offset, 64)
            # Assume a reasonable max allocation for symbolic sizes
            self.state.globals[self.HEAP_OFFSET_KEY] = heap_offset + 4096
            return ptr

        alloc_size = self.state.solver.eval(size)
        # Align to 8 bytes
        alloc_size = (alloc_size + 7) & ~7

        if heap_offset + alloc_size > HEAP_SIZE:
            return 0  # out of memory

        ptr = HEAP_START + heap_offset
        self.state.globals[self.HEAP_OFFSET_KEY] = heap_offset + alloc_size
        return ptr
