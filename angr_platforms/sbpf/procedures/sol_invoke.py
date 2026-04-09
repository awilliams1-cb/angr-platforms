from angr.sim_procedure import SimProcedure


class SolInvokeSigned(SimProcedure):
    """sol_invoke_signed_c(instruction: u64, account_infos: u64,
                            account_infos_len: u64, signers_seeds: u64,
                            signers_seeds_len: u64) -> u64

    Cross-program invocation (CPI). This is the most complex Solana syscall.
    For now, stub as returning 0 (success). Full CPI modeling is a future
    enhancement (F3 in the plan).
    """

    def run(self, instruction, account_infos, account_infos_len,
            signers_seeds, signers_seeds_len):
        return 0
