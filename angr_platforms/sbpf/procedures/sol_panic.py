from angr.sim_procedure import SimProcedure


class SolPanic(SimProcedure):
    """sol_panic_(file_ptr: u64, file_len: u64, line: u64, column: u64) -> !

    Aborts the program.
    """

    NO_RET = True

    def run(self, file_ptr, file_len, line, column):
        self.exit(1)
