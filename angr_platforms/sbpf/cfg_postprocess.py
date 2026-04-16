"""
Post-CFGFast function boundary correction for sBPF.

CFGFast fragments sBPF functions due to a race condition in its analysis
ordering: blocks are claimed by whichever function's worklist job runs
first, causing later functions to treat branches to already-claimed blocks
as "branching to outside" and splitting at those points.

This module provides a merge pass that reassembles the fragments.  The
invariant is simple:

    **Only CALL targets and the ELF entry point are real function starts.**

Everything else (FakeRet continuations, branch targets, error handlers)
belongs to the nearest preceding real function.  This is correct for sBPF
because CALL is the only function entry mechanism and EXIT is the only
return mechanism — all other control flow (``Ijk_Boring``) is
intra-function.
"""

import logging
import struct

l = logging.getLogger(__name__)


def merge_function_fragments(proj, cfg):
    """Merge spurious function fragments back into their parent functions.

    After CFGFast completes, this pass:

    1. Identifies *real* function starts: addresses that are the target of
       at least one ``CALL`` instruction, plus the ELF entry point.
    2. For every function whose address is **not** a real start, transfers
       all of its blocks into the nearest preceding real function and
       removes the spurious function from the knowledge base.
    3. Rebuilds the call graph edges that were broken by the fragmentation.

    This must be called **after** CFGFast and **before** any analysis that
    depends on correct function boundaries (IDL application, call-graph
    extraction, decompilation).

    Parameters
    ----------
    proj : angr.Project
        The angr project (used to read binary data).
    cfg : CFGFast result (or _CFGWrapper)
        Must expose ``cfg.kb.functions``.

    Returns
    -------
    int
        Number of functions merged.
    """
    main_obj = proj.loader.main_object
    text_sec = main_obj.sections_map.get(".text")
    if text_sec is None:
        return 0

    # ── Step 1: find real function starts ──────────────────────
    try:
        raw = proj.loader.memory.load(
            text_sec.min_addr, text_sec.max_addr - text_sec.min_addr,
        )
    except Exception:
        return 0

    real_starts = {proj.entry}
    for i in range(0, len(raw) - 7, 8):
        if raw[i] == 0x85:  # CALL
            imm = struct.unpack("<i", raw[i + 4:i + 8])[0]
            if imm == -1:  # syscall
                continue
            target = text_sec.min_addr + i + (imm + 1) * 8
            if text_sec.min_addr <= target < text_sec.max_addr:
                real_starts.add(target)

    functions = cfg.kb.functions
    all_addrs = sorted(functions.keys())

    # Also keep any function outside .text (SimProcedures, externs, etc.)
    for addr in all_addrs:
        if not (text_sec.min_addr <= addr < text_sec.max_addr):
            real_starts.add(addr)

    spurious = [a for a in all_addrs if a not in real_starts]
    if not spurious:
        l.info("No spurious functions to merge")
        return 0

    l.info("Found %d real function starts, %d spurious fragments to merge",
           len(real_starts), len(spurious))

    # ── Step 2: map each spurious function to its parent ───────
    # Parent = nearest real function start that precedes it.
    real_sorted = sorted(real_starts & set(all_addrs))

    def _find_parent(addr):
        """Binary search for the nearest real start <= addr."""
        lo, hi = 0, len(real_sorted) - 1
        result = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if real_sorted[mid] <= addr:
                result = real_sorted[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return result

    # ── Step 3: merge blocks ───────────────────────────────────
    merged_count = 0
    for spur_addr in spurious:
        parent_addr = _find_parent(spur_addr)
        if parent_addr is None or parent_addr == spur_addr:
            continue

        parent_func = functions.get(parent_addr)
        spur_func = functions.get(spur_addr)
        if parent_func is None or spur_func is None:
            continue

        # Transfer all blocks from the spurious function to the parent
        for block in list(spur_func.blocks):
            try:
                parent_func._register_nodes(True, block)
            except Exception:
                pass

        # Transfer transition graph edges
        for src, dst, data in list(spur_func.transition_graph.edges(data=True)):
            try:
                parent_func.transition_graph.add_edge(src, dst, **data)
            except Exception:
                pass

        # If the spurious function had return sites, propagate them
        if spur_func.has_return:
            parent_func.returning = True

        # Remove the spurious function
        try:
            del functions[spur_addr]
        except KeyError:
            pass

        merged_count += 1

    # ── Step 4: fix up returning status ────────────────────────
    # After merging, parent functions now contain EXIT blocks that
    # they didn't have before.  sBPF EXIT is the only return
    # mechanism, but the lifter emits Ijk_Exit (not Ijk_Ret) since
    # EXIT doubles as program termination when the call stack is
    # empty.  Both jumpkinds indicate the function returns.
    for addr in real_sorted:
        func = functions.get(addr)
        if func is None:
            continue
        if func.returning is not True:
            for block in func.blocks:
                try:
                    irsb = proj.factory.block(block.addr, size=block.size).vex
                    if irsb.jumpkind in ("Ijk_Ret", "Ijk_Exit"):
                        func.returning = True
                        break
                except Exception:
                    continue

    l.info("Merged %d spurious fragments into parent functions "
           "(%d functions remain)", merged_count, len(functions))
    return merged_count
