import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


MDMP_SIGNATURE = 0x504D444D   # "MDMP" little-endian
MDMP_VERSION = 0xA793


class StreamType(IntEnum):
    UNUSED                = 0
    RESERVED0             = 1
    RESERVED1             = 2
    THREAD_LIST           = 3
    MODULE_LIST           = 4
    MEMORY_LIST           = 5
    EXCEPTION             = 6
    SYSTEM_INFO           = 7
    THREAD_EX_LIST        = 8
    MEMORY64_LIST         = 9
    COMMENT_A             = 10
    COMMENT_W             = 11
    HANDLE_DATA           = 12
    FUNCTION_TABLE        = 13
    UNLOADED_MODULE_LIST  = 14
    MISC_INFO             = 15
    MEMORY_INFO_LIST      = 16
    THREAD_INFO_LIST      = 17
    HANDLE_OPERATION_LIST = 18
    TOKEN                 = 19
    JAVA_SCRIPT_DATA      = 20
    SYSTEM_MEMORY_INFO    = 21
    PROCESS_VM_COUNTERS   = 22


# ---- data classes ----

@dataclass
class Module:
    base: int
    size: int
    name: str

    @property
    def short_name(self) -> str:
        return self.name.rsplit("\\", 1)[-1]


@dataclass
class ExceptionRecord:
    code: int
    flags: int
    address: int
    params: list = field(default_factory=list)


@dataclass
class Context:
    """x64 CONTEXT subset — enough for triage."""
    context_flags: int = 0
    rax: int = 0
    rcx: int = 0
    rdx: int = 0
    rbx: int = 0
    rsp: int = 0
    rbp: int = 0
    rsi: int = 0
    rdi: int = 0
    r8:  int = 0
    r9:  int = 0
    r10: int = 0
    r11: int = 0
    r12: int = 0
    r13: int = 0
    r14: int = 0
    r15: int = 0
    rip: int = 0
    eflags: int = 0

    def as_dict(self) -> dict:
        return {
            "rax": self.rax, "rcx": self.rcx, "rdx": self.rdx, "rbx": self.rbx,
            "rsp": self.rsp, "rbp": self.rbp, "rsi": self.rsi, "rdi": self.rdi,
            "r8":  self.r8,  "r9":  self.r9,  "r10": self.r10, "r11": self.r11,
            "r12": self.r12, "r13": self.r13, "r14": self.r14, "r15": self.r15,
            "rip": self.rip, "eflags": self.eflags,
        }


@dataclass
class Thread:
    tid: int
    context: Optional[Context] = None


@dataclass
class SystemInfo:
    processor_arch: int = 0
    processor_level: int = 0
    processor_revision: int = 0
    number_of_processors: int = 0
    product_type: int = 0
    major_version: int = 0
    minor_version: int = 0
    build_number: int = 0
    platform_id: int = 0
    csd_version: str = ""

    @property
    def arch_name(self) -> str:
        return {0: "x86", 5: "ARM", 6: "IA64", 9: "x64", 12: "ARM64"}.get(
            self.processor_arch, f"unknown({self.processor_arch})"
        )


@dataclass
class Minidump:
    path: str
    size: int
    timestamp: int
    flags: int
    exception: Optional[ExceptionRecord] = None
    faulting_thread_id: int = 0
    threads: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    system_info: Optional[SystemInfo] = None

    def find_module(self, addr: int) -> Optional[Module]:
        for m in self.modules:
            if m.base <= addr < m.base + m.size:
                return m
        return None

    def rva_to_name(self, addr: int) -> str:
        m = self.find_module(addr)
        if not m:
            return f"0x{addr:x}"
        return f"{m.short_name}+0x{addr - m.base:x}"


# ---- low-level reader ----

class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def seek(self, pos: int):
        self.pos = pos

    def read(self, n: int) -> bytes:
        b = self.data[self.pos:self.pos + n]
        if len(b) != n:
            raise EOFError(f"wanted {n} bytes at 0x{self.pos:x}, got {len(b)}")
        self.pos += n
        return b

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]


# ---- CONTEXT x64 parser ----

def parse_context_x64(blob: bytes) -> Context:
    ctx = Context()
    if len(blob) < 0x100:
        return ctx
    r = Reader(blob)
    r.seek(0x30); ctx.context_flags = r.u32()
    r.seek(0x44); ctx.eflags = r.u32()
    r.seek(0x78); ctx.rax = r.u64()
    r.seek(0x80); ctx.rcx = r.u64()
    r.seek(0x88); ctx.rdx = r.u64()
    r.seek(0x90); ctx.rbx = r.u64()
    r.seek(0x98); ctx.rsp = r.u64()
    r.seek(0xA0); ctx.rbp = r.u64()
    r.seek(0xA8); ctx.rsi = r.u64()
    r.seek(0xB0); ctx.rdi = r.u64()
    r.seek(0xB8); ctx.r8  = r.u64()
    r.seek(0xC0); ctx.r9  = r.u64()
    r.seek(0xC8); ctx.r10 = r.u64()
    r.seek(0xD0); ctx.r11 = r.u64()
    r.seek(0xD8); ctx.r12 = r.u64()
    r.seek(0xE0); ctx.r13 = r.u64()
    r.seek(0xE8); ctx.r14 = r.u64()
    r.seek(0xF0); ctx.r15 = r.u64()
    r.seek(0xF8); ctx.rip = r.u64()
    return ctx


# ---- top-level parse ----

def parse(path: str) -> Minidump:
    with open(path, "rb") as f:
        data = f.read()

    md = Minidump(path=path, size=len(data), timestamp=0, flags=0)
    r = Reader(data)

    sig = r.u32()
    if sig != MDMP_SIGNATURE:
        raise ValueError(f"not a minidump (signature=0x{sig:08x})")

    _version = r.u32()
    num_streams = r.u32()
    dir_rva = r.u32()
    _checksum = r.u32()
    md.timestamp = r.u32()
    md.flags = r.u64()

    streams: dict[int, tuple[int, int]] = {}
    r.seek(dir_rva)
    for _ in range(num_streams):
        stype = r.u32()
        size = r.u32()
        rva = r.u32()
        streams[stype] = (rva, size)

    # module list
    if StreamType.MODULE_LIST in streams:
        rva, _sz = streams[StreamType.MODULE_LIST]
        r.seek(rva)
        count = r.u32()
        for _ in range(count):
            base = r.u64()
            mod_size = r.u32()
            _checksum = r.u32()
            _ts = r.u32()
            name_rva = r.u32()
            # skip VS_FIXEDFILEINFO (52) + CvRecord (8) + MiscRecord (8) + 2x u64 reserved (16)
            r.seek(r.pos + 52 + 8 + 8 + 16)
            save = r.pos
            r.seek(name_rva)
            nlen = r.u32()
            raw = r.read(nlen)
            name = raw.decode("utf-16-le", errors="replace")
            r.seek(save)
            md.modules.append(Module(base=base, size=mod_size, name=name))

    # exception stream
    if StreamType.EXCEPTION in streams:
        rva, _sz = streams[StreamType.EXCEPTION]
        r.seek(rva)
        md.faulting_thread_id = r.u32()
        _align = r.u32()
        code = r.u32()
        flags = r.u32()
        _rec = r.u64()
        address = r.u64()
        nparams = r.u32()
        _unused = r.u32()
        params = [r.u64() for _ in range(15)]
        md.exception = ExceptionRecord(
            code=code, flags=flags, address=address,
            params=params[:nparams],
        )
        ctx_size = r.u32()
        ctx_rva = r.u32()
        if ctx_size and ctx_rva:
            r.seek(ctx_rva)
            blob = r.read(ctx_size)
            ctx = parse_context_x64(blob)
            md.threads.append(Thread(tid=md.faulting_thread_id, context=ctx))

    # system info
    if StreamType.SYSTEM_INFO in streams:
        rva, _sz = streams[StreamType.SYSTEM_INFO]
        r.seek(rva)
        si = SystemInfo()
        si.processor_arch = r.u16()
        si.processor_level = r.u16()
        si.processor_revision = r.u16()
        si.number_of_processors = r.u8()
        si.product_type = r.u8()
        si.major_version = r.u32()
        si.minor_version = r.u32()
        si.build_number = r.u32()
        si.platform_id = r.u32()
        csd_rva = r.u32()
        if csd_rva:
            save = r.pos
            r.seek(csd_rva)
            nlen = r.u32()
            raw = r.read(nlen)
            si.csd_version = raw.decode("utf-16-le", errors="replace")
            r.seek(save)
        md.system_info = si

    return md