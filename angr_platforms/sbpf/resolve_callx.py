"""
Indirect jump resolver for sBPF CALLX instructions.

CALLX reads a function pointer from a register. This resolver traces
backward through the block's VEX IR to find where the target register
was loaded from. If the value was loaded from a constant address in
memory (e.g., a vtable in .rodata or .data.rel.ro), the resolver reads
the function pointer directly and resolves the call.

Limitation: In practice, most CALLX calls in compiled Solana programs are
Rust trait vtable dispatches. The typical pattern is:

    R0 + offset -> R2    (load vtable pointer from serialized account data)
    *R2         -> R2    (dereference to get function pointer)
    CALLX R2             (call through pointer)

The vtable pointer originates from runtime account data (passed via R1 at
program entry), so the function pointer address is not known statically.
This resolver cannot resolve these cases. Resolving them would require
either symbolic execution (CFGEmulated), Anchor IDL dispatch table info,
or Rust type/vtable recovery.

Post-CFGFast vtable resolution is handled separately by vtable_sbpf.py.
"""

import logging
import pyvex

from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver

l = logging.getLogger(__name__)


class SBPFCallXResolver(IndirectJumpResolver):
    """Resolve sBPF CALLX indirect calls by tracing register loads."""

    def __init__(self, project):
        super().__init__(project, timeless=False)

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if jumpkind != "Ijk_Call":
            return False
        # Check if the block's jump target is a register GET (not a constant)
        if isinstance(block, pyvex.IRSB) and isinstance(block.next, pyvex.expr.RdTmp):
            return True
        return False

    def resolve(self, cfg, addr, func_addr, block, jumpkind,
                func_graph_complete=True, **kwargs):
        if not isinstance(block, pyvex.IRSB):
            return False, []

        targets = set()

        # The block.next is a RdTmp — find which temp holds the target
        if not isinstance(block.next, pyvex.expr.RdTmp):
            return False, []

        target_tmp = block.next.tmp

        # Trace backward: find the statement that writes to target_tmp
        for i in range(len(block.statements) - 1, -1, -1):
            stmt = block.statements[i]
            if not isinstance(stmt, pyvex.IRStmt.WrTmp):
                continue
            if stmt.tmp != target_tmp:
                continue

            # Case 1: Direct load from a constant address
            # Pattern: t = LDle:I64(const_addr)
            if isinstance(stmt.data, pyvex.IRExpr.Load):
                load_addr = self._resolve_expr_to_const(block, stmt.data.addr)
                if load_addr is not None:
                    target = self._read_pointer(load_addr)
                    if target is not None and self._is_target_valid(cfg, target):
                        targets.add(target)
                        l.info("SBPFCallXResolver: resolved CALLX at %#x -> %#x "
                               "(loaded from %#x)", addr, target, load_addr)

            # Case 2: GET from a register
            # Pattern: t = GET:I64(reg_offset)
            # Trace further back to find what wrote to that register
            elif isinstance(stmt.data, pyvex.IRExpr.Get):
                reg_offset = stmt.data.offset
                load_addr = self._trace_register_to_load(block, reg_offset, i)
                if load_addr is not None:
                    target = self._read_pointer(load_addr)
                    if target is not None and self._is_target_valid(cfg, target):
                        targets.add(target)
                        l.info("SBPFCallXResolver: resolved CALLX at %#x -> %#x "
                               "(reg loaded from %#x)", addr, target, load_addr)

            break  # Only look at the first matching write

        if targets:
            return True, list(targets)
        return False, []

    def _resolve_expr_to_const(self, block, expr):
        """Try to resolve a VEX expression to a concrete integer value."""
        if isinstance(expr, pyvex.IRExpr.Const):
            return expr.con.value
        if isinstance(expr, pyvex.IRExpr.RdTmp):
            # Look up the temp definition
            for stmt in block.statements:
                if isinstance(stmt, pyvex.IRStmt.WrTmp) and stmt.tmp == expr.tmp:
                    return self._resolve_expr_to_const(block, stmt.data)
        return None

    def _trace_register_to_load(self, block, reg_offset, before_stmt_idx):
        """Trace backward to find where a register was loaded from.

        Look for: PUT(reg_offset) = LDle(const_addr) or similar patterns.
        """
        for i in range(before_stmt_idx - 1, -1, -1):
            stmt = block.statements[i]
            if isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == reg_offset:
                # Found the write to this register
                if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                    # Look up the temp
                    for j in range(i - 1, -1, -1):
                        s2 = block.statements[j]
                        if isinstance(s2, pyvex.IRStmt.WrTmp) and s2.tmp == stmt.data.tmp:
                            if isinstance(s2.data, pyvex.IRExpr.Load):
                                return self._resolve_expr_to_const(block, s2.data.addr)
                            break
                break
        return None

    def _read_pointer(self, addr):
        """Read a pointer-sized value from CLE memory."""
        try:
            return self.project.loader.memory.unpack_word(
                addr, size=self.project.arch.bytes
            )
        except KeyError:
            return None
