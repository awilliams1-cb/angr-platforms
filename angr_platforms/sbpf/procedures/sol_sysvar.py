from angr.sim_procedure import SimProcedure
from claripy import BVS, BVV


class SolGetClockSysvar(SimProcedure):
    """sol_get_clock_sysvar(addr: u64) -> u64

    Writes the Clock sysvar struct at addr:
      - slot:            u64
      - epoch_start_ts:  i64
      - epoch:           u64
      - leader_schedule_epoch: u64
      - unix_timestamp:  i64
    Total: 40 bytes.
    """

    def run(self, addr):
        slot = BVS("clock_slot", 64)
        epoch_start_ts = BVS("clock_epoch_start_ts", 64)
        epoch = BVS("clock_epoch", 64)
        leader_schedule_epoch = BVS("clock_leader_schedule_epoch", 64)
        unix_timestamp = BVS("clock_unix_timestamp", 64)

        self.state.memory.store(addr, slot, endness="Iend_LE")
        self.state.memory.store(addr + 8, epoch_start_ts, endness="Iend_LE")
        self.state.memory.store(addr + 16, epoch, endness="Iend_LE")
        self.state.memory.store(addr + 24, leader_schedule_epoch, endness="Iend_LE")
        self.state.memory.store(addr + 32, unix_timestamp, endness="Iend_LE")
        return 0


class SolGetRentSysvar(SimProcedure):
    """sol_get_rent_sysvar(addr: u64) -> u64

    Writes the Rent sysvar struct at addr:
      - lamports_per_byte_year: u64
      - exemption_threshold:    f64 (8 bytes)
      - burn_percent:           u8
    Total: 17 bytes.
    """

    def run(self, addr):
        lamports_per_byte_year = BVS("rent_lamports_per_byte_year", 64)
        exemption_threshold = BVS("rent_exemption_threshold", 64)
        burn_percent = BVS("rent_burn_percent", 8)

        self.state.memory.store(addr, lamports_per_byte_year, endness="Iend_LE")
        self.state.memory.store(addr + 8, exemption_threshold, endness="Iend_LE")
        self.state.memory.store(addr + 16, burn_percent)
        return 0
