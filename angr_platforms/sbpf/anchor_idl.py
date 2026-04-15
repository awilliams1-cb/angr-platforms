"""
Anchor IDL integration for sBPF analysis.

Parses Anchor IDL JSON files and provides:
- Instruction discriminator mapping (8-byte SHA-256 prefix)
- Instruction handler identification in the binary
- Account type layout information
- Error code mapping
- Function annotation on angr's CFG

Usage:
    from angr_platforms.sbpf.anchor_idl import AnchorIDL

    idl = AnchorIDL.from_file("path/to/idl.json")
    idl.apply(proj, cfg)  # annotates functions with instruction names
"""

import hashlib
import json
import logging
import re
import struct

l = logging.getLogger(__name__)


class AnchorInstruction:
    """An Anchor program instruction parsed from the IDL."""

    __slots__ = ("name", "discriminator", "accounts", "args", "docs")

    def __init__(self, name, discriminator, accounts, args, docs=None):
        self.name = name
        self.discriminator = bytes(discriminator)  # 8 bytes
        self.accounts = accounts
        self.args = args
        self.docs = docs or []

    @property
    def discriminator_hex(self):
        return self.discriminator.hex()

    @property
    def discriminator_u64(self):
        """Discriminator as a little-endian u64 (how it's compared in the binary)."""
        return struct.unpack("<Q", self.discriminator)[0]

    def __repr__(self):
        return f"AnchorInstruction({self.name!r}, disc={self.discriminator_hex})"


class AnchorAccountType:
    """An Anchor account type parsed from the IDL."""

    __slots__ = ("name", "discriminator", "fields")

    def __init__(self, name, discriminator, fields=None):
        self.name = name
        self.discriminator = bytes(discriminator) if discriminator else None
        self.fields = fields or []

    def __repr__(self):
        return f"AnchorAccountType({self.name!r})"


class AnchorError:
    """An Anchor error code parsed from the IDL."""

    __slots__ = ("code", "name", "msg")

    def __init__(self, code, name, msg=""):
        self.code = code
        self.name = name
        self.msg = msg

    def __repr__(self):
        return f"AnchorError({self.code}, {self.name!r})"


class AnchorIDL:
    """Parsed Anchor IDL with binary analysis integration."""

    def __init__(self, metadata, instructions, accounts, errors, types, constants):
        self.metadata = metadata
        self.instructions = instructions
        self.accounts = accounts
        self.errors = errors
        self.types = types
        self.constants = constants

        # Build lookup tables
        self._disc_to_instruction = {
            ix.discriminator: ix for ix in self.instructions
        }
        self._error_code_to_error = {
            err.code: err for err in self.errors
        }

    @classmethod
    def from_file(cls, path):
        """Load an Anchor IDL from a JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data):
        """Parse an Anchor IDL from a dict (loaded JSON)."""
        metadata = data.get("metadata", {})

        instructions = [
            AnchorInstruction(
                name=ix["name"],
                discriminator=ix.get("discriminator") or _compute_discriminator(ix["name"]),
                accounts=ix.get("accounts", []),
                args=ix.get("args", []),
                docs=ix.get("docs", []),
            )
            for ix in data.get("instructions", [])
        ]

        accounts = [
            AnchorAccountType(
                name=acc["name"],
                discriminator=acc.get("discriminator"),
                fields=None,  # populated from types below
            )
            for acc in data.get("accounts", [])
        ]

        errors = [
            AnchorError(
                code=err["code"],
                name=err["name"],
                msg=err.get("msg", ""),
            )
            for err in data.get("errors", [])
        ]

        types = data.get("types", [])
        constants = data.get("constants", [])

        # Link account types to their field definitions
        type_by_name = {t["name"]: t for t in types}
        for acc in accounts:
            if acc.name in type_by_name:
                acc.fields = type_by_name[acc.name].get("type", {}).get("fields", [])

        return cls(metadata, instructions, accounts, errors, types, constants)

    @property
    def program_name(self):
        return self.metadata.get("name", "unknown")

    def lookup_discriminator(self, disc_bytes):
        """Look up an instruction by its 8-byte discriminator."""
        if isinstance(disc_bytes, (list, tuple)):
            disc_bytes = bytes(disc_bytes)
        return self._disc_to_instruction.get(disc_bytes)

    def lookup_error(self, code):
        """Look up an error by its code."""
        return self._error_code_to_error.get(code)

    def find_handlers(self, proj, cfg):
        """Find instruction handler functions by scanning for discriminator comparisons.

        Anchor programs dispatch instructions by comparing the first 8 bytes
        of the instruction data against each discriminator (as a u64). This
        method scans the binary for these comparisons and maps the branch
        targets to instruction names.

        Returns a dict of {handler_addr: AnchorInstruction}.
        """
        handlers = {}
        disc_values = {ix.discriminator_u64: ix for ix in self.instructions}

        main_obj = proj.loader.main_object
        try:
            data = proj.loader.memory.load(
                main_obj.min_addr,
                main_obj.max_addr - main_obj.min_addr,
            )
        except Exception:
            return handlers

        base = main_obj.min_addr

        # Scan the entire binary for lddw instructions loading discriminator constants.
        # Anchor dispatch pattern:
        #   lddw  R_x, <discriminator>    (16 bytes: opcode 0x18)
        #   jeq   R_data, R_x, +N         (branch if match)
        #   ...
        #   call  <handler>               (within the match branch)
        for i in range(0, len(data) - 16, 8):
            if data[i] != 0x18:
                continue
            imm_lo = struct.unpack("<I", data[i + 4:i + 8])[0]
            imm_hi = struct.unpack("<I", data[i + 12:i + 16])[0]
            imm64 = (imm_hi << 32) | imm_lo

            ix = disc_values.get(imm64)
            if ix is None:
                continue

            lddw_addr = base + i
            l.info("Found discriminator for '%s' at lddw %#x", ix.name, lddw_addr)

            # Anchor dispatch pattern after lddw:
            #   lddw  R_x, <discriminator>     (at i, 16 bytes)
            #   jeq   R_data, R_x, +offset     (at i+16, branches to handler on match)
            # Follow the jeq branch to find the handler entry point.
            jeq_offset = i + 16
            if jeq_offset + 8 <= len(data):
                jeq_opcode = data[jeq_offset]
                # jeq_r = 0x1d (class=101, src=1, op=0001) or
                # jeq_i = 0x15 (class=101, src=0, op=0001)
                if jeq_opcode in (0x1d, 0x15):
                    branch_offset = struct.unpack("<h", data[jeq_offset + 2:jeq_offset + 4])[0]
                    jeq_addr = base + jeq_offset
                    # Branch target = jeq_addr + (offset + 1) * 8
                    branch_target = jeq_addr + (branch_offset + 1) * 8

                    l.info("  jeq at %#x branches to %#x (offset=%+d)",
                           jeq_addr, branch_target, branch_offset)

                    # The branch target leads to the handler setup code.
                    # Scan forward from the branch target for the first CALL
                    # to find the actual handler function.
                    bt_rel = branch_target - base
                    text_end = base + len(data)
                    if 0 <= bt_rel < len(data) - 80:
                        for j in range(bt_rel, min(bt_rel + 80, len(data) - 8), 8):
                            if data[j] == 0x85:  # CALL
                                call_addr = base + j
                                imm = struct.unpack("<i", data[j + 4:j + 8])[0]
                                target = call_addr + (imm + 1) * 8
                                if not (base <= target < text_end and target % 8 == 0):
                                    break
                                handlers[target] = ix
                                l.info("Mapped handler: %s -> %#x", ix.name, target)
                                # If CFGFast missed this as a function start,
                                # register it now so the rest of the pipeline
                                # (renaming, continuation tracing) works.
                                if cfg is not None and target not in cfg.kb.functions:
                                    cfg.kb.functions.function(addr=target)
                                    l.info("  Registered missing function at %#x", target)
                                break
                    else:
                        # Branch target might itself be a handler function
                        if base <= branch_target < text_end:
                            handlers[branch_target] = ix
                            l.info("Mapped handler (direct): %s -> %#x",
                                   ix.name, branch_target)
                            if cfg is not None and branch_target not in cfg.kb.functions:
                                cfg.kb.functions.function(addr=branch_target)

        return handlers

    def apply(self, proj, cfg):
        """Apply IDL information to an angr project's CFG.

        - Finds instruction handlers and renames their functions
        - Follows continuation functions through syscall hooks
        - Stores the IDL on the project for later use
        - Returns the handler mapping (including continuations)

        Usage:
            idl = AnchorIDL.from_file("idl.json")
            handlers = idl.apply(proj, cfg)
        """
        handlers = self.find_handlers(proj, cfg)

        # Rename handler stub functions and find continuations.
        # Anchor handlers typically: stub (setup + sol_log_) → continuation (real logic).
        # The SolLog hook breaks the CFG edge, so the continuation is a separate function
        # at hook_addr + 8. We trace through hooks to find and rename continuations.
        hooked = set(proj._sim_procedures.keys())
        continuations = {}

        for addr, ix in list(handlers.items()):
            func = cfg.kb.functions.get(addr)
            if func is None:
                continue

            func.name = f"ix_{ix.name}"
            l.info("Renamed %s -> ix_%s at %#x", func.name, ix.name, addr)

            # Trace through hooked edges to find continuation functions
            self._find_continuations(
                cfg, func, ix, hooked, continuations, depth=0
            )

        # Add continuations to handlers and rename them
        for cont_addr, (ix, depth) in continuations.items():
            cont_func = cfg.kb.functions.get(cont_addr)
            if cont_func is not None and cont_func.name.startswith("sub_"):
                cont_func.name = f"ix_{ix.name}_impl{'_' + str(depth) if depth > 1 else ''}"
                handlers[cont_addr] = ix
                l.info("Renamed continuation %s at %#x (depth %d)",
                       cont_func.name, cont_addr, depth)

        # Store IDL on the project for later use
        if not hasattr(proj, '_anchor_idls'):
            proj._anchor_idls = []
        proj._anchor_idls.append(self)

        return handlers

    def _find_continuations(self, cfg, func, ix, hooked, continuations, depth):
        """Trace through hooks to find continuation functions."""
        if depth > 5:
            return

        # Find edges from this function to hooked addresses
        for src, dst, data in cfg.graph.edges(data=True):
            if src.function_address != func.addr:
                continue
            if dst.addr not in hooked:
                continue

            # After the hook (8 bytes), there's a continuation
            cont_addr = dst.addr + 8
            cont_func = cfg.kb.functions.get(cont_addr)
            if cont_func is None or cont_addr in continuations:
                continue

            continuations[cont_addr] = (ix, depth + 1)

            # Recurse: the continuation might also hit hooks
            self._find_continuations(
                cfg, cont_func, ix, hooked, continuations, depth + 1
            )

    def summary(self):
        """Return a human-readable summary of the IDL."""
        lines = [
            f"Program: {self.program_name} v{self.metadata.get('version', '?')}",
            f"Instructions: {len(self.instructions)}",
        ]
        for ix in self.instructions:
            args_str = ", ".join(f"{a['name']}: {_type_str(a['type'])}" for a in ix.args)
            lines.append(f"  {ix.name}({args_str}) disc={ix.discriminator_hex}")
        lines.append(f"Account types: {len(self.accounts)}")
        for acc in self.accounts:
            lines.append(f"  {acc.name}")
        lines.append(f"Errors: {len(self.errors)}")
        for err in self.errors:
            lines.append(f"  {err.code}: {err.name}")
        return "\n".join(lines)


def _camel_to_snake(name):
    """Convert camelCase to snake_case (e.g. 'adminSetCreator' -> 'admin_set_creator')."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _compute_discriminator(name):
    """Compute the Anchor discriminator for an instruction name.

    Pre-0.30 Anchor IDLs omit explicit discriminators.  The canonical
    discriminator is sha256("global:<snake_case_name>")[0:8].
    """
    snake = _camel_to_snake(name)
    return list(hashlib.sha256(f"global:{snake}".encode()).digest()[:8])


def _type_str(t):
    """Convert an IDL type to a readable string."""
    if isinstance(t, str):
        return t
    if isinstance(t, dict):
        if "defined" in t:
            return t["defined"].get("name", str(t["defined"]))
        if "array" in t:
            inner, size = t["array"]
            return f"[{_type_str(inner)}; {size}]"
        if "vec" in t:
            return f"Vec<{_type_str(t['vec'])}>"
        if "option" in t:
            return f"Option<{_type_str(t['option'])}>"
    return str(t)
