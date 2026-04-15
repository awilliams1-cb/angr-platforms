"""
Rust vtable resolution for sBPF binaries.

Solana programs compiled from Rust use trait object vtable dispatch for
``dyn Trait`` calls.  The vtables are static data in ``.data.rel.ro``,
with function pointers patched by type-8 (R_BPF_64_RELATIVE) relocations.

At the binary level the layout of each vtable entry is 8 bytes: the
function address occupies bytes 4-7 (matching the lddw imm-field layout
used uniformly by the Solana linker), with bytes 0-3 being zero.

This module provides:
- Discovery of vtable function pointers (for use as CFGFast function_starts)
- Grouping of vtable entries into logical vtable clusters
- Call-graph edge resolution: for every function containing a CALLX
  instruction *and* a lddw constant referencing .data.rel.ro, edges are
  added from that function to all method pointers in the referenced vtable.
"""

import logging
import struct

l = logging.getLogger(__name__)

# Maximum gap (bytes) between consecutive vtable function-pointer entries
# that are still considered part of the same vtable.  Rust vtable layout
# is: drop(8) | size(8) | align(8) | method0(8) | method1(8) | ...
# The size/align slots contain plain integers (not function pointers), so
# there can be gaps of up to ~24 bytes between the drop entry and the
# first method entry.
_VTABLE_GROUP_GAP = 48


def scan_vtable_functions(proj):
    """Return the set of function addresses found in .data.rel.ro vtables.

    This should be called **before** CFGFast so the addresses can be passed
    as ``function_starts``, ensuring they are analysed even when unreachable
    via direct CALL instructions.
    """
    main_obj = proj.loader.main_object
    text_sec = main_obj.sections_map.get(".text")
    relro_sec = main_obj.sections_map.get(".data.rel.ro")
    if not text_sec or not relro_sec:
        return set()

    try:
        raw = proj.loader.memory.load(
            relro_sec.min_addr, relro_sec.max_addr - relro_sec.min_addr,
        )
    except Exception:
        return set()

    fn_addrs = set()
    for i in range(0, len(raw) - 7, 8):
        lo = struct.unpack("<I", raw[i:i + 4])[0]
        hi = struct.unpack("<I", raw[i + 4:i + 8])[0]
        if lo == 0 and hi % 8 == 0 and text_sec.min_addr <= hi < text_sec.max_addr:
            fn_addrs.add(hi)

    l.info("Found %d vtable function pointers in .data.rel.ro", len(fn_addrs))
    return fn_addrs


def build_vtable_map(proj):
    """Build a mapping from .data.rel.ro addresses to vtable function sets.

    Vtable entries are grouped by proximity: entries within
    ``_VTABLE_GROUP_GAP`` bytes of each other belong to the same vtable.
    Every address in the vtable region (including a small margin before the
    first entry) maps to the full set of function pointers for that vtable.

    Returns ``{relro_addr: frozenset(fn_addrs)}``.
    """
    main_obj = proj.loader.main_object
    text_sec = main_obj.sections_map.get(".text")
    relro_sec = main_obj.sections_map.get(".data.rel.ro")
    if not text_sec or not relro_sec:
        return {}

    try:
        raw = proj.loader.memory.load(
            relro_sec.min_addr, relro_sec.max_addr - relro_sec.min_addr,
        )
    except Exception:
        return {}

    base = relro_sec.min_addr

    # Collect (relro_addr, fn_addr) pairs
    fn_entries = []
    for i in range(0, len(raw) - 7, 8):
        lo = struct.unpack("<I", raw[i:i + 4])[0]
        hi = struct.unpack("<I", raw[i + 4:i + 8])[0]
        if lo == 0 and hi % 8 == 0 and text_sec.min_addr <= hi < text_sec.max_addr:
            fn_entries.append((base + i, hi))

    # Group into vtable clusters
    groups = []  # [(start, end, {fn_addrs})]
    for relro_addr, fn_addr in fn_entries:
        if groups and relro_addr - groups[-1][1] <= _VTABLE_GROUP_GAP:
            groups[-1] = (groups[-1][0], relro_addr, groups[-1][2] | {fn_addr})
        else:
            groups.append((relro_addr, relro_addr, {fn_addr}))

    # Build map: a generous range around each vtable group maps to its fns.
    # This handles the common case where a lddw references a .rodata string
    # pointer that sits just before the first function-pointer entry.
    vtable_map = {}
    for start, end, fns in groups:
        frozen = frozenset(fns)
        for addr in range(start - 32, end + 8, 8):
            if relro_sec.min_addr <= addr < relro_sec.max_addr:
                vtable_map[addr] = frozen

    l.info("Built vtable map: %d groups, %d total function pointers",
           len(groups), len({f for g in groups for f in g[2]}))
    return vtable_map


def resolve_vtable_call_edges(proj, cfg, call_graph):
    """Enrich *call_graph* with edges resolved from CALLX + vtable patterns.

    For each function in the CFG that contains both:
      - a CALLX instruction (opcode ``0x8d``)
      - a lddw constant (opcode ``0x18``) referencing ``.data.rel.ro``

    all function pointers from the referenced vtable group are added as
    call-graph edges.

    *call_graph* is modified **in-place** (``{func_addr: set(callee_addrs)}``).

    Returns the number of edges added.
    """
    main_obj = proj.loader.main_object
    text_sec = main_obj.sections_map.get(".text")
    relro_sec = main_obj.sections_map.get(".data.rel.ro")
    if not text_sec or not relro_sec:
        return 0

    try:
        raw = proj.loader.memory.load(
            text_sec.min_addr, text_sec.max_addr - text_sec.min_addr,
        )
    except Exception:
        return 0
    text_base = text_sec.min_addr

    vtable_map = build_vtable_map(proj)
    if not vtable_map:
        return 0

    edges_added = 0
    for func in cfg.kb.functions.values():
        has_callx = False
        vtable_refs = set()

        for block in func.blocks:
            rel = block.addr - text_base
            end = rel + block.size
            if rel < 0 or end > len(raw):
                continue

            i = rel
            while i < end - 7:
                op = raw[i]
                if op == 0x8d:  # CALLX
                    has_callx = True
                    i += 8
                elif op == 0x18 and i + 16 <= end:  # lddw (16 bytes)
                    imm_lo = struct.unpack("<I", raw[i + 4:i + 8])[0]
                    imm_hi = struct.unpack("<I", raw[i + 12:i + 16])[0]
                    val = (imm_hi << 32) | imm_lo
                    if relro_sec.min_addr <= val < relro_sec.max_addr:
                        vtable_refs.add(val)
                    i += 16
                else:
                    i += 8

        if not (has_callx and vtable_refs):
            continue

        existing = call_graph.get(func.addr, set())
        for vt_addr in vtable_refs:
            for fn_addr in vtable_map.get(vt_addr, frozenset()):
                if fn_addr not in existing:
                    call_graph.setdefault(func.addr, set()).add(fn_addr)
                    edges_added += 1
                    l.debug("Vtable edge: %#x -> %#x (via vtable ref %#x)",
                            func.addr, fn_addr, vt_addr)

    l.info("Resolved %d vtable call-graph edges", edges_added)
    return edges_added
