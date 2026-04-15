"""
Indirect jump resolver for sBPF CALLX instructions.

CALLX reads a function pointer from a register. This resolver traces
backward through the block's VEX IR to find where the target register
was loaded from. If the value was loaded from a constant address in
memory (e.g., a vtable in .rodata or .data.rel.ro), the resolver reads
the function pointer directly and resolves the call.

When single-block VEX tracing fails (the common case for Rust trait
vtable dispatch, where the function pointer is loaded through a two-level
dereference that often spans multiple basic blocks), the resolver falls
back to a binary-level heuristic: it scans the enclosing function for
lddw constants that reference .data.rel.ro, looks up the vtable entries
at those addresses, and returns all method pointers as possible targets.
"""

import logging
import struct

import pyvex

from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver

l = logging.getLogger(__name__)


class SBPFCallXResolver(IndirectJumpResolver):
    """Resolve sBPF CALLX indirect calls by tracing register loads."""

    def __init__(self, project):
        super().__init__(project, timeless=False)
        self._vtable_map = None  # lazily built on first use

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

        # Try precise VEX-level resolution first
        targets = self._resolve_vex(block, addr)

        # Fall back to vtable heuristic if VEX tracing didn't resolve
        if not targets:
            targets = self._resolve_vtable(cfg, func_addr, addr)

        if targets:
            return True, list(targets)
        return False, []

    # ── VEX-level resolution ───────────────────────────────────

    def _resolve_vex(self, block, addr):
        """Try to resolve the CALLX target by tracing VEX IR in this block."""
        if not isinstance(block.next, pyvex.expr.RdTmp):
            return set()

        targets = set()
        target_tmp = block.next.tmp

        for i in range(len(block.statements) - 1, -1, -1):
            stmt = block.statements[i]
            if not isinstance(stmt, pyvex.IRStmt.WrTmp):
                continue
            if stmt.tmp != target_tmp:
                continue

            # Case 1: Direct load from a constant address
            if isinstance(stmt.data, pyvex.IRExpr.Load):
                load_addr = self._resolve_expr_to_const(block, stmt.data.addr)
                if load_addr is not None:
                    target = self._read_pointer(load_addr)
                    if target is not None and self._is_target_valid(None, target):
                        targets.add(target)
                        l.info("SBPFCallXResolver: resolved CALLX at %#x -> %#x "
                               "(loaded from %#x)", addr, target, load_addr)

            # Case 2: GET from a register — trace further back
            elif isinstance(stmt.data, pyvex.IRExpr.Get):
                reg_offset = stmt.data.offset
                load_addr = self._trace_register_to_load(block, reg_offset, i)
                if load_addr is not None:
                    target = self._read_pointer(load_addr)
                    if target is not None and self._is_target_valid(None, target):
                        targets.add(target)
                        l.info("SBPFCallXResolver: resolved CALLX at %#x -> %#x "
                               "(reg loaded from %#x)", addr, target, load_addr)

            break

        return targets

    # ── Vtable heuristic resolution ────────────────────────────

    def _resolve_vtable(self, cfg, func_addr, callx_addr):
        """Resolve CALLX via vtable heuristic.

        Scans the enclosing function for lddw constants referencing
        .data.rel.ro and returns all function pointers from the
        corresponding vtable groups.
        """
        from .vtable_sbpf import build_vtable_map

        main_obj = self.project.loader.main_object
        text_sec = main_obj.sections_map.get(".text")
        relro_sec = main_obj.sections_map.get(".data.rel.ro")
        if not text_sec or not relro_sec:
            return set()

        # Build vtable map once and cache
        if self._vtable_map is None:
            self._vtable_map = build_vtable_map(self.project)
        if not self._vtable_map:
            return set()

        # Find the function containing this CALLX
        func = cfg.kb.functions.get(func_addr) if cfg is not None else None
        if func is None:
            return set()

        # Scan the function's blocks for lddw constants into .data.rel.ro
        vtable_refs = set()
        for block_node in func.blocks:
            try:
                raw = self.project.loader.memory.load(block_node.addr, block_node.size)
            except Exception:
                continue

            i = 0
            while i < len(raw) - 7:
                if raw[i] == 0x18 and i + 16 <= len(raw):  # lddw
                    imm_lo = struct.unpack("<I", raw[i + 4:i + 8])[0]
                    imm_hi = struct.unpack("<I", raw[i + 12:i + 16])[0]
                    val = (imm_hi << 32) | imm_lo
                    if relro_sec.min_addr <= val < relro_sec.max_addr:
                        vtable_refs.add(val)
                    i += 16
                else:
                    i += 8

        # Resolve vtable references to function pointers
        targets = set()
        for vt_addr in vtable_refs:
            for fn_addr in self._vtable_map.get(vt_addr, frozenset()):
                if self._is_target_valid(cfg, fn_addr):
                    targets.add(fn_addr)

        if targets:
            l.info("SBPFCallXResolver: vtable heuristic resolved CALLX at %#x "
                   "in func %#x -> %d targets (vtable refs: %s)",
                   callx_addr, func_addr, len(targets),
                   ", ".join(f"{a:#x}" for a in vtable_refs))

        return targets

    # ── Helpers ─────────────────────────────────────────────────

    def _resolve_expr_to_const(self, block, expr):
        """Try to resolve a VEX expression to a concrete integer value."""
        if isinstance(expr, pyvex.IRExpr.Const):
            return expr.con.value
        if isinstance(expr, pyvex.IRExpr.RdTmp):
            for stmt in block.statements:
                if isinstance(stmt, pyvex.IRStmt.WrTmp) and stmt.tmp == expr.tmp:
                    return self._resolve_expr_to_const(block, stmt.data)
        return None

    def _trace_register_to_load(self, block, reg_offset, before_stmt_idx):
        """Trace backward to find where a register was loaded from."""
        for i in range(before_stmt_idx - 1, -1, -1):
            stmt = block.statements[i]
            if isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == reg_offset:
                if isinstance(stmt.data, pyvex.IRExpr.RdTmp):
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
