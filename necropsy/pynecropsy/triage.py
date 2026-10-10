from dataclasses import dataclass, field
from enum import Enum
from .minidump import Minidump


class Verdict(Enum):
    EXPLOITABLE          = "EXPLOITABLE"
    PROBABLY_EXPLOITABLE = "PROBABLY_EXPLOITABLE"
    UNKNOWN              = "UNKNOWN"
    NOT_EXPLOITABLE      = "NOT_EXPLOITABLE"


EXCEPTION_CODES = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC0000006: "IN_PAGE_ERROR",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000025: "NONCONTINUABLE_EXCEPTION",
    0xC000008C: "ARRAY_BOUNDS_EXCEEDED",
    0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
    0xC0000095: "INTEGER_OVERFLOW",
    0xC0000096: "PRIVILEGED_INSTRUCTION",
    0xC00000FD: "STACK_OVERFLOW",
    0xC0000409: "STACK_BUFFER_OVERRUN",
    0xC0000374: "HEAP_CORRUPTION",
    0xC0000602: "FAIL_FAST",
    0x80000003: "BREAKPOINT",
}

HIGH_VALUE_MODULES = [
    "mpengine", "mpclient", "mpcommu", "wdfilter", "mpksldrv",
    "ntoskrnl", "ntdll", "kernelbase", "msxml", "ole32",
    "jscript", "vbscript", "chakra", "winhttp", "ws2_32",
]

POISON_PATTERNS = {
    0x4141414141414141, 0x4242424242424242, 0x4343434343434343,
    0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xffffffffffffffff,
    0x41414141, 0x42424242, 0xdeadbeef, 0xcafebabe,
}


@dataclass
class Finding:
    rule: str
    severity: str
    detail: str


@dataclass
class TriageResult:
    path: str
    verdict: Verdict = Verdict.UNKNOWN
    score: int = 0
    exception_code: int = 0
    exception_name: str = "UNKNOWN"
    access_type: str = ""
    faulting_address: int = 0
    faulting_module: str = ""
    faulting_frame: str = ""
    instruction_pointer: int = 0
    stack_pointer: int = 0
    registers: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    rationale: str = ""

    def add(self, rule: str, severity: str, detail: str):
        self.findings.append(Finding(rule, severity, detail))

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "verdict": self.verdict.value,
            "score": self.score,
            "exception_code": f"0x{self.exception_code:08X}",
            "exception_name": self.exception_name,
            "access_type": self.access_type,
            "faulting_address": f"0x{self.faulting_address:x}",
            "faulting_module": self.faulting_module,
            "faulting_frame": self.faulting_frame,
            "instruction_pointer": f"0x{self.instruction_pointer:x}",
            "stack_pointer": f"0x{self.stack_pointer:x}",
            "registers": {k: f"0x{v:x}" for k, v in self.registers.items()},
            "findings": [
                {"rule": f.rule, "severity": f.severity, "detail": f.detail}
                for f in self.findings
            ],
            "rationale": self.rationale,
        }


# ---- helpers ----

def is_user_range(addr: int) -> bool:
    return 0 < addr < 0x0000_7FFF_FFFF_FFFF

def is_kernel_range(addr: int) -> bool:
    return addr >= 0xFFFF_8000_0000_0000

def is_null_near(addr: int) -> bool:
    return 0 <= addr < 0x10000

def is_poison(addr: int) -> bool:
    return addr in POISON_PATTERNS


# ---- rules ----

def rule_rip_control(t: TriageResult):
    rip = t.registers.get("rip", 0)
    addr = t.faulting_address
    if addr and rip and addr == rip:
        t.verdict = Verdict.EXPLOITABLE
        t.score += 50
        t.add("rip-control", "critical",
              f"RIP == faulting address (0x{rip:x}) — instruction pointer control")

def rule_poison_pointer(t: TriageResult):
    addr = t.faulting_address
    if addr and is_poison(addr):
        t.verdict = Verdict.EXPLOITABLE
        t.score += 45
        t.add("poison-ptr", "critical",
              f"faulting address 0x{addr:x} matches poison pattern")

def rule_access_violation(t: TriageResult):
    addr = t.faulting_address
    if t.access_type == "WRITE":
        if is_null_near(addr):
            if t.verdict == Verdict.UNKNOWN:
                t.verdict = Verdict.NOT_EXPLOITABLE
            t.add("write-null", "low",
                  f"write AV near null (0x{addr:x}) — usually benign")
        elif is_user_range(addr):
            if t.verdict not in (Verdict.EXPLOITABLE,):
                t.verdict = Verdict.PROBABLY_EXPLOITABLE
            t.score += 30
            t.add("write-av-user", "high",
                  f"write AV at user-controlled address 0x{addr:x}")
        elif is_kernel_range(addr):
            if t.verdict not in (Verdict.EXPLOITABLE,):
                t.verdict = Verdict.PROBABLY_EXPLOITABLE
            t.score += 25
            t.add("write-av-kernel", "high",
                  f"write AV at kernel address 0x{addr:x} — possible pointer corruption")
    elif t.access_type == "READ":
        if is_null_near(addr):
            if t.verdict == Verdict.UNKNOWN:
                t.verdict = Verdict.NOT_EXPLOITABLE
            t.add("read-null", "low", "read AV near null — common benign null deref")
        elif is_user_range(addr):
            if t.verdict == Verdict.UNKNOWN:
                t.verdict = Verdict.UNKNOWN
            t.score += 15
            t.add("read-av-user", "medium",
                  f"read AV at 0x{addr:x} — potential info leak")

def rule_stack_overflow(t: TriageResult):
    t.verdict = Verdict.PROBABLY_EXPLOITABLE
    t.score += 35
    t.add("stack-overflow", "high",
          "stack overflow — potential return address control")

def rule_heap_corruption(t: TriageResult):
    t.verdict = Verdict.EXPLOITABLE
    t.score += 45
    t.add("heap-corruption", "critical",
          "heap corruption detected — classic exploit primitive")

def rule_gs_canary(t: TriageResult):
    t.verdict = Verdict.PROBABLY_EXPLOITABLE
    t.score += 30
    t.add("gs-canary", "high",
          "stack buffer overrun (/GS canary) — buffer overflow path")

def rule_rip_non_canonical(t: TriageResult):
    rip = t.registers.get("rip", 0)
    if rip == 0:
        t.add("rip-null", "info", "RIP is null")
        return
    if not (is_user_range(rip) or is_kernel_range(rip)):
        t.verdict = Verdict.EXPLOITABLE
        t.score += 40
        t.add("rip-non-canonical", "critical",
              f"RIP 0x{rip:x} is non-canonical — control flow hijack")

def rule_high_value_module(t: TriageResult):
    fm = (t.faulting_module or "").lower()
    if any(h in fm for h in HIGH_VALUE_MODULES):
        t.score += 10
        t.add("high-value-module", "info",
              f"faulting module '{t.faulting_module}' is on the high-value list")


# ---- top-level ----

def triage(md: Minidump) -> TriageResult:
    t = TriageResult(path=md.path)

    if md.exception is None:
        t.verdict = Verdict.UNKNOWN
        t.rationale = "no exception record in dump"
        return t

    ex = md.exception
    t.exception_code = ex.code
    t.exception_name = EXCEPTION_CODES.get(ex.code, f"0x{ex.code:08X}")
    t.faulting_address = ex.address
    t.instruction_pointer = ex.address

    if ex.code == 0xC0000005 and len(ex.params) >= 2:
        flag = ex.params[0]
        addr = ex.params[1]
        t.faulting_address = addr
        t.access_type = {0: "READ", 1: "WRITE", 8: "EXECUTE"}.get(flag, "")

    for th in md.threads:
        if th.tid == md.faulting_thread_id and th.context is not None:
            t.registers = th.context.as_dict()
            t.instruction_pointer = th.context.rip
            t.stack_pointer = th.context.rsp
            break

    m = md.find_module(t.instruction_pointer)
    if m:
        t.faulting_module = m.short_name
        t.faulting_frame = md.rva_to_name(t.instruction_pointer)

    # dispatch
    if ex.code == 0xC0000005:
        rule_access_violation(t)
        rule_poison_pointer(t)
        rule_rip_control(t)
    elif ex.code == 0xC00000FD:
        rule_stack_overflow(t)
    elif ex.code == 0xC0000374:
        rule_heap_corruption(t)
    elif ex.code == 0xC0000409:
        rule_gs_canary(t)
    elif ex.code in (0xC0000094, 0xC0000095):
        t.verdict = Verdict.NOT_EXPLOITABLE
        t.add("arith", "low", "arithmetic exception — usually benign")
    elif ex.code == 0xC000001D:
        t.verdict = Verdict.UNKNOWN
        t.score += 10
        t.add("ill-inst", "medium", "illegal instruction — inspect dispatch path")
    else:
        t.add("unknown-code", "info", f"unhandled exception code 0x{ex.code:X}")

    rule_rip_non_canonical(t)
    rule_high_value_module(t)

    if not t.findings:
        t.verdict = Verdict.UNKNOWN
        t.add("no-rule", "info", "no triage rule matched")

    t.rationale = "; ".join(f.detail for f in t.findings)
    return t