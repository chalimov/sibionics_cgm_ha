"""ARM64 emulator for SIBIONICS calibration algorithm.

Loads libnative-algorithm-v1_1_6A.so and libnative-sensitivity-v110.so via
Unicorn CPU emulation. Runs the REAL binary algorithm for medically accurate
glucose calibration (97% within +/-2 mg/dL of official app).

This is NOT a Python reimplementation — it executes the actual ARM64 machine
code from the SIBIONICS APK.
"""

from __future__ import annotations

import logging
import math
import os
import struct
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any

from unicorn import UC_ARCH_ARM64, UC_HOOK_INTR, UC_MODE_ARM, UC_PROT_ALL, Uc, UcError
from unicorn.arm64_const import (
    UC_ARM64_REG_D0,
    UC_ARM64_REG_D1,
    UC_ARM64_REG_D2,
    UC_ARM64_REG_D3,
    UC_ARM64_REG_D4,
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_S0,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_W0,
    UC_ARM64_REG_W1,
    UC_ARM64_REG_W2,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
)
from elftools.elf.elffile import ELFFile

from .const import BG_REFERENCE, CTX_SIZE, TARGET_HIGH, TARGET_LOW

_LOGGER = logging.getLogger(__name__)

# Memory layout
STACK_ADDR = 0x7F000000
STACK_SIZE = 0x200000
HEAP_ADDR = 0x10000000
HEAP_SIZE = 0x2000000
HOOK_ADDR = 0x20000000
HOOK_SIZE = 0x100000
TLS_ADDR = 0x30000000
TLS_SIZE = 0x1000
STACK_CANARY = 0xDEADBEEFCAFEBABE

# Heap usage warning threshold (75%)
HEAP_WARN_THRESHOLD = int(HEAP_SIZE * 0.75)

# Default library locations (relative to this file)
_LIB_DIR = os.path.join(os.path.dirname(__file__), "lib")


def _find_lib_dir() -> str:
    """Find the directory containing the .so algorithm libraries."""
    # Check integration's own lib/ directory first
    if os.path.isdir(_LIB_DIR):
        algo = os.path.join(_LIB_DIR, "libnative-algorithm-v1_1_6A.so")
        if os.path.isfile(algo):
            return _LIB_DIR

    # Fallback: check the cgm project's apk_extract
    fallback = os.path.join(
        os.path.dirname(__file__), "..", "..", "..",
        "cgm", "apk_extract", "lib", "arm64-v8a"
    )
    fallback = os.path.normpath(fallback)
    if os.path.isdir(fallback):
        return fallback

    raise FileNotFoundError(
        "Algorithm libraries not found. Place libnative-algorithm-v1_1_6A.so "
        "and libnative-sensitivity-v110.so in the integration's lib/ directory."
    )


# ── ELF Parsing ──────────────────────────────────────────────────────

def _parse_elf(path: str, base_addr: int) -> dict[str, Any]:
    """Parse ELF file for emulation."""
    info: dict[str, Any] = {"base": base_addr, "path": path}
    with open(path, "rb") as f:
        elf = ELFFile(f)

        info["sections"] = {}
        for sec in elf.iter_sections():
            if not sec.name:
                continue
            entry = {
                "addr": sec["sh_addr"],
                "size": sec["sh_size"],
                "offset": sec["sh_offset"],
                "type": sec["sh_type"],
            }
            if sec["sh_type"] not in ("SHT_NOBITS",):
                entry["data"] = sec.data()
            else:
                entry["data"] = b"\x00" * sec["sh_size"]
            info["sections"][sec.name] = entry

        info["segments"] = []
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                info["segments"].append({
                    "vaddr": seg["p_vaddr"],
                    "memsz": seg["p_memsz"],
                    "filesz": seg["p_filesz"],
                    "flags": seg["p_flags"],
                    "data": seg.data(),
                })

        dynsym = elf.get_section_by_name(".dynsym")
        info["symbols"] = {}
        info["exports"] = {}
        info["imports"] = []
        for sym in dynsym.iter_symbols():
            if sym.name:
                info["symbols"][sym.name] = {
                    "addr": sym["st_value"],
                    "size": sym["st_size"],
                    "type": sym["st_info"]["type"],
                    "bind": sym["st_info"]["bind"],
                    "shndx": sym["st_shndx"],
                }
                if sym["st_shndx"] != "SHN_UNDEF" and sym["st_value"] != 0:
                    info["exports"][sym.name] = base_addr + sym["st_value"]
                elif sym["st_shndx"] == "SHN_UNDEF":
                    info["imports"].append(sym.name)

        rela_plt = elf.get_section_by_name(".rela.plt")
        plt_sec = elf.get_section_by_name(".plt")
        info["plt_map"] = {}
        info["got_entries"] = {}

        if rela_plt and plt_sec:
            plt_data = plt_sec.data()
            plt_addr = plt_sec["sh_addr"]
            plt_size = plt_sec["sh_size"]
            got_to_sym = {}
            for rel in rela_plt.iter_relocations():
                sym = dynsym.get_symbol(rel["r_info_sym"])
                got_to_sym[rel["r_offset"]] = (sym.name, sym["st_value"])

            num_entries = plt_size // 16
            for i in range(1, num_entries):
                entry_offset = i * 16
                entry_addr = plt_addr + entry_offset
                if entry_offset + 16 > len(plt_data):
                    break
                insns = struct.unpack("<4I", plt_data[entry_offset:entry_offset + 16])
                adrp = insns[0]
                if (adrp & 0x9F000000) != 0x90000000:
                    continue
                immlo = (adrp >> 29) & 0x3
                immhi = (adrp >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                page_offset = imm << 12
                pc_page = entry_addr & ~0xFFF
                target_page = pc_page + page_offset
                ldr = insns[1]
                ldr_imm12 = (ldr >> 10) & 0xFFF
                ldr_offset = ldr_imm12 * 8
                got_addr = target_page + ldr_offset
                if got_addr in got_to_sym:
                    sym_name, sym_value = got_to_sym[got_addr]
                    info["plt_map"][entry_addr] = (sym_name, sym_value, got_addr)
                    info["got_entries"][got_addr] = (sym_name, sym_value)

        rela_dyn = elf.get_section_by_name(".rela.dyn")
        info["rela_dyn"] = []
        if rela_dyn:
            for rel in rela_dyn.iter_relocations():
                sym_idx = rel["r_info_sym"]
                sym_name = ""
                sym_value = 0
                if sym_idx > 0:
                    sym = dynsym.get_symbol(sym_idx)
                    sym_name = sym.name
                    sym_value = sym["st_value"]
                info["rela_dyn"].append({
                    "offset": rel["r_offset"],
                    "type": rel["r_info_type"],
                    "sym_name": sym_name,
                    "sym_value": sym_value,
                    "addend": rel["r_addend"],
                })

    return info


# ── Heap Allocator ───────────────────────────────────────────────────

class _HeapAllocator:
    def __init__(self, base: int, size: int):
        self.base = base
        self.size = size
        self.next_free = base
        self.allocations: dict[int, int] = {}
        self._warned = False

    def malloc(self, size: int) -> int:
        size = (size + 15) & ~15
        if size == 0:
            size = 16
        if self.next_free + size > self.base + self.size:
            raise MemoryError(f"Heap exhausted: requested {size} bytes, used {self.used} of {self.size}")
        addr = self.next_free
        self.next_free += size
        self.allocations[addr] = size
        # Warn at 75% usage
        if not self._warned and self.used > HEAP_WARN_THRESHOLD:
            self._warned = True
            _LOGGER.warning(
                "Heap usage at %d%% (%d / %d bytes)",
                int(self.used * 100 / self.size), self.used, self.size,
            )
        return addr

    @property
    def used(self) -> int:
        return self.next_free - self.base

    def calloc(self, nmemb: int, size: int) -> int:
        return self.malloc(nmemb * size)

    def realloc(self, ptr: int, size: int) -> tuple[int, int]:
        new_addr = self.malloc(size)
        if ptr and ptr in self.allocations:
            return new_addr, min(self.allocations[ptr], size)
        return new_addr, 0

    def free(self, ptr: int) -> None:
        pass  # Bump allocator — freed on engine reset

    def posix_memalign(self, alignment: int, size: int) -> int:
        self.next_free = (self.next_free + alignment - 1) & ~(alignment - 1)
        return self.malloc(size)


# ── Calibration Engine ───────────────────────────────────────────────

class CalibrationEngine:
    """ARM64 emulator that runs the real SIBIONICS calibration algorithm.

    Usage:
        engine = CalibrationEngine()
        engine.initialize(sensitivity_input="QF32450C")
        result_mmol = engine.process(raw_mmol=6.5, temperature=34.2, index=100)
    """

    def __init__(self, lib_dir: str | None = None):
        self._lib_dir = lib_dir or _find_lib_dir()
        self._libs: dict[str, dict] = {}
        self._uc: Uc | None = None
        self._heap: _HeapAllocator | None = None
        self._hook_dispatch: dict[int, str] = {}
        self._next_hook = HOOK_ADDR + 0x10
        self._call_counts: dict[str, int] = defaultdict(int)
        self._global_exports: dict[str, int] = {}
        self._ctx_addr: int = 0
        self._initialized = False
        self._reading_index = 0
        self._emu_lock = threading.RLock()  # Thread safety for Unicorn engine (reentrant)

    @property
    def initialized(self) -> bool:
        return self._initialized

    def setup(self) -> None:
        """Parse ELF files and set up the emulator. Call once."""
        _LOGGER.info("Emulator setup starting (lib_dir=%s)", self._lib_dir)
        algo_path = os.path.join(self._lib_dir, "libnative-algorithm-v1_1_6A.so")
        sens_path = os.path.join(self._lib_dir, "libnative-sensitivity-v110.so")

        if not os.path.isfile(algo_path):
            raise FileNotFoundError(f"Algorithm library not found: {algo_path}")
        if not os.path.isfile(sens_path):
            raise FileNotFoundError(f"Sensitivity library not found: {sens_path}")

        _LOGGER.debug("Parsing ELF: %s", algo_path)
        self._libs["algo"] = _parse_elf(algo_path, 0x400000)
        _LOGGER.debug("Parsing ELF: %s", sens_path)
        self._libs["sens"] = _parse_elf(sens_path, 0x600000)

        # Build global symbol table
        for lib_info in self._libs.values():
            for sym_name, abs_addr in lib_info["exports"].items():
                if sym_name not in self._global_exports:
                    self._global_exports[sym_name] = abs_addr

        self._uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self._heap = _HeapAllocator(HEAP_ADDR, HEAP_SIZE)
        self._hook_dispatch = {}
        self._next_hook = HOOK_ADDR + 0x10

        self._setup_memory()
        self._apply_all_relocations()
        self._setup_all_gots()
        self._uc.hook_add(UC_HOOK_INTR, self._interrupt_handler)
        self._setup_tls()

        _LOGGER.info(
            "Emulator ready: %d libs, %d hooks, %d exports",
            len(self._libs), len(self._hook_dispatch), len(self._global_exports),
        )

    def decrypt_sensitivity(self, sensitivity_input: str) -> float:
        """Decrypt per-sensor sensitivity from QR serial fragment.

        Tries faction=1 (app mode) first, falls back to faction=0 (standard).
        """
        if not self._uc:
            raise RuntimeError("Call setup() first")

        _LOGGER.info("Decrypting sensitivity for input=%s", sensitivity_input[:4] + "****")

        # Try faction=1 first (app mode, used by official app), then faction=0
        for faction in (1, 0):
            val = self._decrypt_sensitivity_faction(sensitivity_input, faction)
            if val is not None and 0.3 <= val <= 4.0:
                _LOGGER.info("Sensitivity decrypted: %.4f (faction=%d)", val, faction)
                return val
            _LOGGER.debug("Faction %d returned %.4f — trying next", faction, val or 0.0)

        raise ValueError(f"Sensitivity decryption failed for both faction modes, input={sensitivity_input}")

    def _decrypt_sensitivity_faction(self, sensitivity_input: str, faction: int) -> float | None:
        """Try decrypting sensitivity with a specific faction mode."""
        with self._emu_lock:
            sens_info = self._libs["sens"]
            base = sens_info["base"]

            sym = sens_info["symbols"].get("md_sensitivity_decrypt_faction")
            if sym is None:
                sym = sens_info["symbols"].get("md_sensitivity_decrypt")
            if sym is None:
                raise RuntimeError("md_sensitivity_decrypt not found")

            func_addr = base + sym["addr"]

            str_addr = self._heap.malloc(len(sensitivity_input) + 16)
            self._uc.mem_write(str_addr, sensitivity_input.encode("utf-8") + b"\x00")
            float_addr = self._heap.malloc(16)
            self._uc.mem_write(float_addr, b"\x00" * 16)

            sp = self._uc.reg_read(UC_ARM64_REG_SP)
            try:
                self._uc.reg_write(UC_ARM64_REG_X0, str_addr)
                self._uc.reg_write(UC_ARM64_REG_X1, float_addr)
                self._uc.reg_write(UC_ARM64_REG_W2, faction)

                self._call_function(func_addr)

                ret = self._uc.reg_read(UC_ARM64_REG_W0)
                sens_bytes = bytes(self._uc.mem_read(float_addr, 4))
                sens_val = struct.unpack("<f", sens_bytes)[0]
            except Exception as exc:
                _LOGGER.debug("Sensitivity decrypt faction=%d failed: %s", faction, exc)
                return None
            finally:
                self._uc.reg_write(UC_ARM64_REG_SP, sp)

        return sens_val

    def initialize(self, sensitivity_input: str) -> None:
        """Initialize the calibration algorithm with per-sensor sensitivity."""
        if not self._uc:
            self.setup()

        _LOGGER.info("Initializing calibration algorithm...")
        sensitivity = self.decrypt_sensitivity(sensitivity_input)

        with self._emu_lock:
            # Allocate algorithm context
            self._ctx_addr = self._heap.malloc(CTX_SIZE + 256)
            self._uc.mem_write(self._ctx_addr, b"\x00" * (CTX_SIZE + 256))

            algo_info = self._libs["algo"]
            base = algo_info["base"]

            # Use dll_init with faction=1 sensitivity
            dll_sym = algo_info["symbols"].get("dll_init_algorithm_v116A_context")
            if dll_sym is None:
                raise RuntimeError("dll_init_algorithm_v116A_context not found")

            sp = self._uc.reg_read(UC_ARM64_REG_SP)
            try:
                self._uc.reg_write(UC_ARM64_REG_X0, self._ctx_addr)
                self._write_d(self._uc, UC_ARM64_REG_D0, float(sensitivity))
                self._call_function(base + dll_sym["addr"])
            finally:
                self._uc.reg_write(UC_ARM64_REG_SP, sp)

            _LOGGER.info("Algorithm initialized via dll_init (sensitivity=%.4f)", sensitivity)
            self._initialized = True
            self._reading_index = 0

    def process(
        self,
        raw_mmol: float,
        temperature: float,
        index: int | None = None,
    ) -> float:
        """Process a single glucose reading through the calibration algorithm."""
        if not self._initialized:
            raise RuntimeError("Call initialize() first")

        if index is None:
            index = self._reading_index
        self._reading_index = index + 1

        with self._emu_lock:
            algo_info = self._libs["algo"]
            base = algo_info["base"]

            sym = algo_info["symbols"].get("dll_process_alogrithm_v116A_context")
            if sym is None:
                raise RuntimeError("dll_process_alogrithm_v116A_context not found")

            func_addr = base + sym["addr"]
            sp = self._uc.reg_read(UC_ARM64_REG_SP)

            try:
                self._uc.reg_write(UC_ARM64_REG_X0, self._ctx_addr)
                self._uc.reg_write(UC_ARM64_REG_W1, index & 0xFFFFFFFF)
                self._write_d(self._uc, UC_ARM64_REG_D0, raw_mmol)
                self._write_d(self._uc, UC_ARM64_REG_D1, temperature)
                self._write_d(self._uc, UC_ARM64_REG_D2, BG_REFERENCE)
                self._write_d(self._uc, UC_ARM64_REG_D3, TARGET_LOW)
                self._write_d(self._uc, UC_ARM64_REG_D4, TARGET_HIGH)

                self._call_function(func_addr)

                result = self._read_d(self._uc, UC_ARM64_REG_D0)
            finally:
                self._uc.reg_write(UC_ARM64_REG_SP, sp)

        return result

    # ── Internal: memory setup ───────────────────────────────────────

    def _setup_memory(self) -> None:
        uc = self._uc
        self._mapped_regions: set[tuple[int, int]] = set()
        for lib_info in self._libs.values():
            base = lib_info["base"]
            for seg in lib_info["segments"]:
                vaddr = base + seg["vaddr"]
                memsz = seg["memsz"]
                page_start = vaddr & ~0xFFF
                page_end = (vaddr + memsz + 0xFFF) & ~0xFFF
                size = page_end - page_start
                region_key = (page_start, size)
                if region_key not in self._mapped_regions:
                    try:
                        uc.mem_map(page_start, size, UC_PROT_ALL)
                        self._mapped_regions.add(region_key)
                    except UcError:
                        pass
                uc.mem_write(vaddr, seg["data"][:seg["filesz"]])

        uc.mem_map(STACK_ADDR - STACK_SIZE, STACK_SIZE, UC_PROT_ALL)
        uc.reg_write(UC_ARM64_REG_SP, STACK_ADDR - 0x100)
        uc.mem_map(HEAP_ADDR, HEAP_SIZE, UC_PROT_ALL)
        uc.mem_map(HOOK_ADDR, HOOK_SIZE, UC_PROT_ALL)
        uc.mem_map(TLS_ADDR, TLS_SIZE, UC_PROT_ALL)
        self._sf_addr = self._heap.malloc(0x100)

    def _apply_all_relocations(self) -> None:
        for lib_info in self._libs.values():
            base = lib_info["base"]
            self._apply_relocations(lib_info, base)

    def _apply_relocations(self, lib_info: dict, base: int) -> None:
        uc = self._uc
        for rel in lib_info["rela_dyn"]:
            addr = base + rel["offset"]
            rtype = rel["type"]
            if rtype == 1027:  # R_AARCH64_RELATIVE
                uc.mem_write(addr, struct.pack("<Q", base + rel["addend"]))
            elif rtype in (1025, 1026):  # R_AARCH64_GLOB_DAT / R_AARCH64_JUMP_SLOT
                sym_name = rel["sym_name"]
                if rel["sym_value"] != 0:
                    uc.mem_write(addr, struct.pack("<Q", base + rel["sym_value"]))
                elif sym_name and sym_name in self._global_exports:
                    uc.mem_write(addr, struct.pack("<Q", self._global_exports[sym_name]))
                elif sym_name == "__sF":
                    uc.mem_write(addr, struct.pack("<Q", self._sf_addr))
            elif rtype == 257:  # R_AARCH64_ABS64
                if rel["sym_value"] != 0:
                    uc.mem_write(addr, struct.pack("<Q", base + rel["sym_value"] + rel["addend"]))
                elif rel["sym_name"] and rel["sym_name"] in self._global_exports:
                    uc.mem_write(addr, struct.pack("<Q", self._global_exports[rel["sym_name"]] + rel["addend"]))
            else:
                _LOGGER.debug("Unhandled relocation type %d at offset 0x%x", rtype, rel["offset"])

    def _setup_all_gots(self) -> None:
        for lib_info in self._libs.values():
            base = lib_info["base"]
            uc = self._uc
            for got_addr, (sym_name, sym_value) in lib_info["got_entries"].items():
                abs_got = base + got_addr
                if sym_value != 0:
                    uc.mem_write(abs_got, struct.pack("<Q", base + sym_value))
                elif sym_name in self._global_exports:
                    uc.mem_write(abs_got, struct.pack("<Q", self._global_exports[sym_name]))
                else:
                    hook = self._alloc_hook(sym_name)
                    uc.mem_write(abs_got, struct.pack("<Q", hook))

    def _setup_tls(self) -> None:
        self._uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_ADDR)
        self._uc.mem_write(TLS_ADDR + 0x28, struct.pack("<Q", STACK_CANARY))

    def _alloc_hook(self, name: str) -> int:
        for addr, n in self._hook_dispatch.items():
            if n == name:
                return addr
        addr = self._next_hook
        self._next_hook += 16
        self._hook_dispatch[addr] = name
        self._uc.mem_write(addr, struct.pack("<I", 0xD4200000))  # BRK #0
        return addr

    # ── Internal: function calling ───────────────────────────────────

    def _call_function(self, func_addr: int) -> None:
        sentinel = HOOK_ADDR
        self._uc.mem_write(sentinel, struct.pack("<I", 0xD65F03C0))  # RET
        self._uc.reg_write(UC_ARM64_REG_LR, sentinel)
        try:
            self._uc.emu_start(func_addr, sentinel, timeout=0, count=200_000_000)
        except UcError as e:
            pc = self._uc.reg_read(UC_ARM64_REG_PC)
            if pc == sentinel:
                return
            raise RuntimeError(f"Emulation error: {e} at PC=0x{pc:x}") from e

        # Verify execution completed (instruction limit not exhausted)
        pc = self._uc.reg_read(UC_ARM64_REG_PC)
        if pc != sentinel:
            raise RuntimeError(
                f"Instruction limit exhausted: PC=0x{pc:x} (expected sentinel 0x{sentinel:x})"
            )

    # ── Internal: interrupt/hook dispatch ─────────────────────────────

    def _interrupt_handler(self, uc: Uc, intno: int, user_data: Any) -> None:
        pc = uc.reg_read(UC_ARM64_REG_PC)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        if pc not in self._hook_dispatch:
            _LOGGER.error("Unexpected interrupt %d at PC=0x%x", intno, pc)
            uc.emu_stop()
            return
        name = self._hook_dispatch[pc]
        self._call_counts[name] += 1
        try:
            self._dispatch_hook(name, uc, pc, lr)
        except Exception:
            _LOGGER.exception("Hook %s failed at PC=0x%x", name, pc)
            uc.emu_stop()

    def _dispatch_hook(self, name: str, uc: Uc, pc: int, lr: int) -> None:
        # ── Math functions ──
        if name == "pow":
            b = self._read_d(uc, UC_ARM64_REG_D0)
            e = self._read_d(uc, UC_ARM64_REG_D1)
            try:
                r = math.pow(b, e)
            except (ValueError, OverflowError):
                _LOGGER.warning("pow(%.6g, %.6g) failed, returning NaN", b, e)
                r = float("nan")
            self._write_d(uc, UC_ARM64_REG_D0, r)
        # Note: math functions (exp, expf, sqrt, log, fabs, etc.) are NOT hooked.
        # They are resolved within the .so libraries' own compiled code.
        # Only pow() needs a hook (confirmed by the working standalone emulator).
        # ── Memory ──
        elif name == "malloc":
            sz = uc.reg_read(UC_ARM64_REG_X0) or 1
            a = self._heap.malloc(sz)
            uc.mem_write(a, b"\x00" * ((sz + 15) & ~15))
            uc.reg_write(UC_ARM64_REG_X0, a)
        elif name == "calloc":
            nm = uc.reg_read(UC_ARM64_REG_X0)
            sz = uc.reg_read(UC_ARM64_REG_X1)
            t = (nm * sz) or 1
            a = self._heap.calloc(nm, sz)
            uc.mem_write(a, b"\x00" * ((t + 15) & ~15))
            uc.reg_write(UC_ARM64_REG_X0, a)
        elif name == "realloc":
            ptr = uc.reg_read(UC_ARM64_REG_X0)
            sz = uc.reg_read(UC_ARM64_REG_X1)
            new, copy_sz = self._heap.realloc(ptr, sz)
            if copy_sz > 0 and ptr:
                uc.mem_write(new, bytes(uc.mem_read(ptr, copy_sz)))
            uc.reg_write(UC_ARM64_REG_X0, new)
        elif name == "free":
            self._heap.free(uc.reg_read(UC_ARM64_REG_X0))
        elif name == "posix_memalign":
            mp = uc.reg_read(UC_ARM64_REG_X0)
            al = uc.reg_read(UC_ARM64_REG_X1)
            sz = uc.reg_read(UC_ARM64_REG_X2)
            a = self._heap.posix_memalign(al, sz)
            uc.mem_write(a, b"\x00" * ((sz + 15) & ~15))
            uc.mem_write(mp, struct.pack("<Q", a))
            uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name in ("memcpy", "__memcpy_chk"):
            d, s, n = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1), uc.reg_read(UC_ARM64_REG_X2)
            if n > 0 and s and d:
                uc.mem_write(d, bytes(uc.mem_read(s, n)))
        elif name in ("memmove", "__memmove_chk"):
            d, s, n = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1), uc.reg_read(UC_ARM64_REG_X2)
            if n > 0 and s and d:
                uc.mem_write(d, bytes(uc.mem_read(s, n)))
        elif name in ("memset", "__memset_chk"):
            d = uc.reg_read(UC_ARM64_REG_X0)
            v = uc.reg_read(UC_ARM64_REG_X1) & 0xFF
            n = uc.reg_read(UC_ARM64_REG_X2)
            if n > 0 and d:
                uc.mem_write(d, bytes([v]) * n)
        elif name == "memchr":
            s = uc.reg_read(UC_ARM64_REG_X0)
            c = uc.reg_read(UC_ARM64_REG_X1) & 0xFF
            n = uc.reg_read(UC_ARM64_REG_X2)
            if n > 0 and s:
                data = bytes(uc.mem_read(s, n))
                idx = data.find(bytes([c]))
                uc.reg_write(UC_ARM64_REG_X0, s + idx if idx >= 0 else 0)
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name == "memcmp":
            s1, s2 = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1)
            n = uc.reg_read(UC_ARM64_REG_X2)
            if n > 0 and s1 and s2:
                d1, d2 = bytes(uc.mem_read(s1, n)), bytes(uc.mem_read(s2, n))
                uc.reg_write(UC_ARM64_REG_X0, ((-1) & 0xFFFFFFFFFFFFFFFF) if d1 < d2 else (1 if d1 > d2 else 0))
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
        # ── String ──
        elif name == "strcmp":
            s1 = self._read_cstring(uc, uc.reg_read(UC_ARM64_REG_X0))
            s2 = self._read_cstring(uc, uc.reg_read(UC_ARM64_REG_X1))
            uc.reg_write(UC_ARM64_REG_X0, ((-1 if s1 < s2 else 1 if s1 > s2 else 0) & 0xFFFFFFFFFFFFFFFF))
        elif name in ("strlen", "__strlen_chk"):
            uc.reg_write(UC_ARM64_REG_X0, len(self._read_cstring(uc, uc.reg_read(UC_ARM64_REG_X0))))
        elif name in ("strcpy", "__strcpy_chk"):
            d, s = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1)
            uc.mem_write(d, self._read_cstring(uc, s).encode("utf-8") + b"\x00")
        elif name in ("__strncpy_chk", "__strncpy_chk2"):
            d, s = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1)
            n = uc.reg_read(UC_ARM64_REG_X2)
            data = self._read_cstring(uc, s).encode("utf-8")[:n]
            uc.mem_write(d, data + b"\x00" * (n - len(data)))
        elif name == "strstr":
            ha = uc.reg_read(UC_ARM64_REG_X0)
            hs = self._read_cstring(uc, ha)
            ns = self._read_cstring(uc, uc.reg_read(UC_ARM64_REG_X1))
            idx = hs.find(ns)
            uc.reg_write(UC_ARM64_REG_X0, ha + idx if idx >= 0 else 0)
        elif name == "strspn":
            s = self._read_cstring(uc, uc.reg_read(UC_ARM64_REG_X0))
            accept = set(self._read_cstring(uc, uc.reg_read(UC_ARM64_REG_X1)))
            count = 0
            for ch in s:
                if ch in accept:
                    count += 1
                else:
                    break
            uc.reg_write(UC_ARM64_REG_X0, count)
        # ── Char classification ──
        elif name == "islower":
            c = uc.reg_read(UC_ARM64_REG_X0)
            uc.reg_write(UC_ARM64_REG_X0, 1 if 97 <= c <= 122 else 0)
        elif name == "isxdigit":
            c = uc.reg_read(UC_ARM64_REG_X0)
            uc.reg_write(UC_ARM64_REG_X0, 1 if (48 <= c <= 57 or 65 <= c <= 70 or 97 <= c <= 102) else 0)
        elif name == "toupper":
            c = uc.reg_read(UC_ARM64_REG_X0)
            uc.reg_write(UC_ARM64_REG_X0, c - 32 if 97 <= c <= 122 else c)
        # ── Numeric conversion ──
        elif name in ("strtol", "strtoul", "strtoll", "strtoull"):
            self._hook_strtol(uc)
        elif name in ("strtod", "strtold"):
            nptr = uc.reg_read(UC_ARM64_REG_X0)
            endptr = uc.reg_read(UC_ARM64_REG_X1)
            s = self._read_cstring(uc, nptr)
            try:
                val = float(s.strip())
            except ValueError:
                val = 0.0
            self._write_d(uc, UC_ARM64_REG_D0, val)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            if endptr:
                uc.mem_write(endptr, struct.pack("<Q", nptr + len(s)))
        elif name == "strtof":
            nptr = uc.reg_read(UC_ARM64_REG_X0)
            endptr = uc.reg_read(UC_ARM64_REG_X1)
            s = self._read_cstring(uc, nptr)
            try:
                val = float(s.strip())
            except ValueError:
                val = 0.0
            raw = struct.unpack("<I", struct.pack("<f", val))[0]
            uc.reg_write(UC_ARM64_REG_S0, raw)
            if endptr:
                uc.mem_write(endptr, struct.pack("<Q", nptr + len(s)))
        elif name == "snprintf":
            self._hook_snprintf(uc)
        elif name == "__dynamic_cast":
            pass  # x0 already has source ptr
        # ── Wide char stubs ──
        elif name in ("wcstod", "wcstof", "wcstol", "wcstoll", "wcstoul", "wcstoull", "wcstold"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
            self._write_d(uc, UC_ARM64_REG_D0, 0.0)
        elif name == "wcslen":
            s = uc.reg_read(UC_ARM64_REG_X0)
            length = 0
            if s:
                while length < 10000:
                    ch = struct.unpack("<I", bytes(uc.mem_read(s + length * 4, 4)))[0]
                    if ch == 0:
                        break
                    length += 1
            uc.reg_write(UC_ARM64_REG_X0, length)
        elif name in ("wmemcpy", "wmemmove"):
            d, s, n = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1), uc.reg_read(UC_ARM64_REG_X2)
            bc = n * 4
            if bc > 0 and s and d:
                uc.mem_write(d, bytes(uc.mem_read(s, bc)))
        elif name == "wmemset":
            d = uc.reg_read(UC_ARM64_REG_X0)
            c = uc.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF
            n = uc.reg_read(UC_ARM64_REG_X2)
            if n > 0 and d:
                uc.mem_write(d, struct.pack("<I", c) * n)
        elif name == "wmemchr":
            s = uc.reg_read(UC_ARM64_REG_X0)
            c = uc.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF
            n = uc.reg_read(UC_ARM64_REG_X2)
            target = struct.pack("<I", c)
            for i in range(n):
                if bytes(uc.mem_read(s + i * 4, 4)) == target:
                    uc.reg_write(UC_ARM64_REG_X0, s + i * 4)
                    uc.reg_write(UC_ARM64_REG_PC, lr)
                    return
            uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name == "wmemcmp":
            s1, s2 = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1)
            n = uc.reg_read(UC_ARM64_REG_X2)
            bc = n * 4
            if bc > 0 and s1 and s2:
                d1, d2 = bytes(uc.mem_read(s1, bc)), bytes(uc.mem_read(s2, bc))
                for i in range(0, bc, 4):
                    v1 = struct.unpack("<I", d1[i:i+4])[0]
                    v2 = struct.unpack("<I", d2[i:i+4])[0]
                    if v1 != v2:
                        uc.reg_write(UC_ARM64_REG_X0, (-1 & 0xFFFFFFFFFFFFFFFF) if v1 < v2 else 1)
                        uc.reg_write(UC_ARM64_REG_PC, lr)
                        return
            uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name == "swprintf":
            uc.reg_write(UC_ARM64_REG_X0, 0)
        # ── Logging/stdio stubs ──
        elif name in ("syslog", "openlog", "closelog", "fputc"):
            pass
        elif name == "__stack_chk_fail":
            _LOGGER.error("Stack corruption detected!")
            uc.emu_stop()
            return
        elif name == "abort":
            _LOGGER.error("abort() called in emulated code!")
            uc.emu_stop()
            return
        elif name == "android_set_abort_message":
            pass
        elif name in ("vfprintf", "vasprintf", "__vsnprintf_chk", "printf", "puts"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
        # ── Threading stubs ──
        elif name == "pthread_once":
            # Read once_control flag; if 0, call init function, then set to 1
            once_addr = uc.reg_read(UC_ARM64_REG_X0)
            init_func = uc.reg_read(UC_ARM64_REG_X1)
            if once_addr:
                flag = struct.unpack("<I", bytes(uc.mem_read(once_addr, 4)))[0]
                if flag == 0 and init_func:
                    uc.mem_write(once_addr, struct.pack("<I", 1))
                    # Call the init function
                    saved_lr = uc.reg_read(UC_ARM64_REG_LR)
                    try:
                        self._call_function(init_func)
                    except Exception as exc:
                        _LOGGER.warning("pthread_once init function failed: %s", exc)
                    uc.reg_write(UC_ARM64_REG_LR, saved_lr)
            uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name in ("pthread_key_create", "pthread_setspecific",
                       "pthread_getspecific", "pthread_mutex_lock", "pthread_mutex_unlock",
                       "pthread_create"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
        # ── C++ ABI ──
        elif name in ("__cxa_finalize", "__cxa_atexit"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name == "dl_iterate_phdr":
            uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name == "__errno":
            if not hasattr(self, "_errno_addr"):
                self._errno_addr = self._heap.malloc(16)
                uc.mem_write(self._errno_addr, struct.pack("<I", 0))
            uc.reg_write(UC_ARM64_REG_X0, self._errno_addr)
        elif name == "__sF":
            uc.reg_write(UC_ARM64_REG_X0, self._sf_addr)
        # ── Sensitivity stubs ──
        elif name == "md_sensitivity_decrypt":
            _LOGGER.error(
                "md_sensitivity_decrypt hook called — cross-library resolution failed. "
                "Cannot proceed with hardcoded fallback."
            )
            uc.emu_stop()
            return
        elif name in ("md_sensitivity_encrypt", "md_sensitivity_encrypt_faction",
                       "md_sensitivity_decrypt_faction", "global_app_decrypt",
                       "global_app_get_checksum", "global_encrypt_control_cmd",
                       "global_spilt_reply_data", "get_sensitivity_version", "s2jHook"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
        # ── cJSON stubs ──
        elif name.startswith("cJSON_"):
            if "Parse" in name or "Create" in name or "Get" in name:
                uc.reg_write(UC_ARM64_REG_X0, self._heap.malloc(64))
            elif "Print" in name:
                a = self._heap.malloc(16)
                uc.mem_write(a, b"{}\x00")
                uc.reg_write(UC_ARM64_REG_X0, a)
            elif "Delete" in name:
                pass
            elif "Add" in name:
                uc.reg_write(UC_ARM64_REG_X0, 1)
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
        # ── C++ runtime ──
        elif name.startswith("_Zn") or name.startswith("_ZN"):
            if "_Znwm" in name or "_Znam" in name:
                sz = uc.reg_read(UC_ARM64_REG_X0) or 1
                a = self._heap.malloc(sz)
                uc.mem_write(a, b"\x00" * ((sz + 15) & ~15))
                uc.reg_write(UC_ARM64_REG_X0, a)
            elif "_ZdlPv" in name or "_ZdaPv" in name:
                pass
            elif "_ZSt9terminatev" in name:
                _LOGGER.error("std::terminate() called!")
                uc.emu_stop()
                return
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name.startswith("_ZS") or name.startswith("_Zd"):
            if "_ZdlPv" in name or "_ZdaPv" in name:
                pass
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name.startswith("__cxa_"):
            if "allocate_exception" in name:
                a = self._heap.malloc(128)
                uc.mem_write(a, b"\x00" * 128)
                uc.reg_write(UC_ARM64_REG_X0, a)
            elif "throw" in name:
                _LOGGER.error("C++ exception thrown in emulated code")
                uc.emu_stop()
                return
            elif "get_globals" in name:
                if not hasattr(self, "_cxa_globals_addr"):
                    self._cxa_globals_addr = self._heap.malloc(256)
                    uc.mem_write(self._cxa_globals_addr, b"\x00" * 256)
                uc.reg_write(UC_ARM64_REG_X0, self._cxa_globals_addr)
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
        elif name.startswith("__gxx_"):
            uc.reg_write(UC_ARM64_REG_X0, 0)
        else:
            _LOGGER.warning("Unhooked function called: %s at PC=0x%x", name, pc)
            uc.reg_write(UC_ARM64_REG_X0, 0)

        uc.reg_write(UC_ARM64_REG_PC, lr)

    # ── Internal: helpers ─────────────────────────────────────────────

    def _hook_strtol(self, uc: Uc) -> None:
        nptr = uc.reg_read(UC_ARM64_REG_X0)
        endptr = uc.reg_read(UC_ARM64_REG_X1)
        base = uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
        s = self._read_cstring(uc, nptr)
        stripped = s.lstrip()
        if not stripped:
            if endptr:
                uc.mem_write(endptr, struct.pack("<Q", nptr))
            uc.reg_write(UC_ARM64_REG_X0, 0)
            return
        sign, pos = 1, 0
        if stripped[pos] in "+-":
            if stripped[pos] == "-":
                sign = -1
            pos += 1
        actual_base = base
        if base == 0:
            if pos < len(stripped) and stripped[pos] == "0":
                if pos + 1 < len(stripped) and stripped[pos + 1] in "xX":
                    actual_base, pos = 16, pos + 2
                else:
                    actual_base, pos = 8, pos + 1
            else:
                actual_base = 10
        digits = ""
        while pos < len(stripped):
            ch = stripped[pos]
            if actual_base <= 10:
                if ch.isdigit() and int(ch) < actual_base:
                    digits += ch
                    pos += 1
                else:
                    break
            else:
                if ch.isdigit() or (ch.lower() in "abcdef" and ord(ch.lower()) - ord("a") + 10 < actual_base):
                    digits += ch
                    pos += 1
                else:
                    break
        val = sign * int(digits, actual_base) if digits else 0
        if not digits:
            pos = 0
        skip_ws = len(s) - len(s.lstrip())
        if val < 0:
            val = val & 0xFFFFFFFFFFFFFFFF
        uc.reg_write(UC_ARM64_REG_X0, val & 0xFFFFFFFFFFFFFFFF)
        if endptr:
            uc.mem_write(endptr, struct.pack("<Q", nptr + skip_ws + pos))

    def _hook_snprintf(self, uc: Uc) -> None:
        dst = uc.reg_read(UC_ARM64_REG_X0)
        size = uc.reg_read(UC_ARM64_REG_X1)
        fmt_addr = uc.reg_read(UC_ARM64_REG_X2)
        fmt = self._read_cstring(uc, fmt_addr)
        result = ""
        if fmt in ("%d", "%i"):
            v = uc.reg_read(UC_ARM64_REG_X3)
            if v & 0x80000000:
                v -= 0x100000000
            result = str(v)
        elif fmt == "%u":
            result = str(uc.reg_read(UC_ARM64_REG_X3) & 0xFFFFFFFF)
        elif fmt == "%s":
            sa = uc.reg_read(UC_ARM64_REG_X3)
            result = self._read_cstring(uc, sa) if sa else ""
        elif fmt in ("%ld", "%li"):
            v = uc.reg_read(UC_ARM64_REG_X3)
            if v & 0x8000000000000000:
                v -= 0x10000000000000000
            result = str(v)
        elif fmt == "%lu":
            result = str(uc.reg_read(UC_ARM64_REG_X3))
        elif fmt in ("%f", "%lf", "%.6f"):
            result = f"{self._read_d(uc, UC_ARM64_REG_D0):.6f}"
        elif fmt in ("%e", "%.6e"):
            result = f"{self._read_d(uc, UC_ARM64_REG_D0):.6e}"
        elif fmt in ("%g", "%.6g"):
            result = f"{self._read_d(uc, UC_ARM64_REG_D0):.6g}"
        elif "%02x" in fmt.lower() or "%x" in fmt.lower():
            v = uc.reg_read(UC_ARM64_REG_X3) & 0xFFFFFFFF
            if "%02x" in fmt:
                result = f"{v:02x}"
            elif "%02X" in fmt:
                result = f"{v:02X}"
            else:
                result = f"{v:x}"
        else:
            _LOGGER.debug("Unhandled snprintf format: %r", fmt)
        data = result.encode("utf-8")
        if dst and size > 0:
            wl = min(len(data), size - 1)
            uc.mem_write(dst, data[:wl] + b"\x00")
        uc.reg_write(UC_ARM64_REG_X0, len(data))

    @staticmethod
    def _read_d(uc: Uc, reg: int) -> float:
        return struct.unpack("<d", struct.pack("<Q", uc.reg_read(reg)))[0]

    @staticmethod
    def _write_d(uc: Uc, reg: int, value: float) -> None:
        uc.reg_write(reg, struct.unpack("<Q", struct.pack("<d", value))[0])

    @staticmethod
    def _read_s(uc: Uc) -> float:
        """Read single-precision float from S0 (low 32 bits of D0)."""
        raw = uc.reg_read(UC_ARM64_REG_S0)
        return struct.unpack("<f", struct.pack("<I", raw & 0xFFFFFFFF))[0]

    @staticmethod
    def _write_s(uc: Uc, value: float) -> None:
        """Write single-precision float to S0."""
        raw = struct.unpack("<I", struct.pack("<f", value))[0]
        uc.reg_write(UC_ARM64_REG_S0, raw)

    @staticmethod
    def _read_cstring(uc: Uc, addr: int, max_len: int = 4096) -> str:
        if addr == 0:
            return ""
        result = bytearray()
        pos = addr
        remaining = max_len
        while remaining > 0:
            chunk_size = min(remaining, 256)
            try:
                chunk = bytes(uc.mem_read(pos, chunk_size))
            except UcError:
                break
            null = chunk.find(0)
            if null >= 0:
                result.extend(chunk[:null])
                break
            result.extend(chunk)
            pos += chunk_size
            remaining -= chunk_size
        return bytes(result).decode("utf-8", errors="replace")
