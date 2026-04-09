from angr.sim_procedure import SimProcedure
from claripy import BVV


class SolSetReturnData(SimProcedure):
    """sol_set_return_data(data: u64, data_len: u64) -> u64

    Sets the return data for the current instruction.
    Stored in state.globals for retrieval by sol_get_return_data.
    """

    RETURN_DATA_KEY = "sol_return_data"
    RETURN_DATA_LEN_KEY = "sol_return_data_len"
    RETURN_DATA_PROGRAM_KEY = "sol_return_data_program"

    def run(self, data, data_len):
        if self.state.solver.symbolic(data_len):
            length = 1024  # cap for symbolic
        else:
            length = self.state.solver.eval(data_len)

        ret_data = self.state.memory.load(data, length)
        self.state.globals[self.RETURN_DATA_KEY] = ret_data
        self.state.globals[self.RETURN_DATA_LEN_KEY] = data_len
        return 0


class SolGetReturnData(SimProcedure):
    """sol_get_return_data(data: u64, data_len: u64, program_id: u64) -> u64

    Gets the return data set by the last CPI call.
    Returns the length of return data available.
    """

    def run(self, data, data_len, program_id):
        ret_data = self.state.globals.get(SolSetReturnData.RETURN_DATA_KEY, None)
        ret_len = self.state.globals.get(SolSetReturnData.RETURN_DATA_LEN_KEY, None)

        if ret_data is not None and ret_len is not None:
            self.state.memory.store(data, ret_data)
            return ret_len
        return 0
