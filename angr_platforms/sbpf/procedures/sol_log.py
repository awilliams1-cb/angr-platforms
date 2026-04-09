from angr.sim_procedure import SimProcedure


class SolLog(SimProcedure):
    """sol_log_(msg_ptr: u64, msg_len: u64) -> u64

    Logs a UTF-8 string. We stub this as a no-op returning 0 (success).
    """

    def run(self, msg_ptr, msg_len):
        return 0


class SolLog64(SimProcedure):
    """sol_log_64_(arg1-arg5: u64) -> u64

    Logs 5 u64 values. Stub returning 0.
    """

    def run(self, arg1, arg2, arg3, arg4, arg5):
        return 0


class SolLogPubkey(SimProcedure):
    """sol_log_pubkey(pubkey_ptr: u64) -> u64

    Logs a public key. Stub returning 0.
    """

    def run(self, pubkey_ptr):
        return 0


class SolLogComputeUnits(SimProcedure):
    """sol_log_compute_units_() -> u64

    Logs remaining compute units. Stub returning 0.
    """

    def run(self):
        return 0
