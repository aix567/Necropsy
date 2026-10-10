"""Report writers — text, JSON, CSV, Markdown."""
import json
import csv
from io import StringIO
from .triage import TriageResult, Verdict


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sorted_findings(t: TriageResult):
    return sorted(t.findings, key=lambda f: SEV_ORDER.get(f.severity, 99))


def format_text(t: TriageResult, md=None) -> str:
    out = []
    out.append(f"[+] loading: {t.path}")
    if md is not None:
        out.append(f"    size:      {md.size} bytes")
        out.append(f"    timestamp: {md.timestamp}")
        if md.system_info:
            si = md.system_info
            out.append(f"    processor: {si.arch_name}, "
                       f"{si.number_of_processors} cores")
            out.append(f"    os:        {si.major_version}.{si.minor_version}."
                       f"{si.build_number}")
        out.append(f"    modules:   {len(md.modules)} loaded")
    out.append("")
    out.append("[*] exception")
    out.append(f"    code:     0x{t.exception_code:08X} ({t.exception_name})")
    if t.access_type:
        out.append(f"    access:   {t.access_type}")
    if t.faulting_address:
        out.append(f"    address:  0x{t.faulting_address:x}")
    out.append("")
    if t.registers:
        out.append("[*] registers")
        for k in ("rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx",
                  "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
                  "r13", "r14", "r15"):
            if k in t.registers:
                out.append(f"    {k:<4} 0x{t.registers[k]:016x}")
        out.append("")
    out.append("[*] verdict")
    out.append(f"    classification: {t.verdict.value}")
    out.append(f"    score:          {t.score}")
    if t.faulting_module:
        out.append(f"    module:         {t.faulting_module}")
    if t.faulting_frame:
        out.append(f"    frame:          {t.faulting_frame}")
    out.append("")
    if t.findings:
        out.append("[*] findings")
        for f in _sorted_findings(t):
            out.append(f"    [{f.severity:<8}] {f.rule:<20} {f.detail}")
    return "\n".join(out)


def format_json(t: TriageResult) -> str:
    return json.dumps(t.to_dict(), indent=2)


def format_csv_row(t: TriageResult) -> str:
    buf = StringIO()
    w = csv.writer(buf)
    w.writerow([t.path, t.verdict.value, t.score, t.exception_name,
                t.access_type, t.faulting_module, t.faulting_frame])
    return buf.getvalue().strip()


def csv_header() -> str:
    return "path,verdict,score,exception,access,module,frame"


def format_markdown(results: list[TriageResult]) -> str:
    lines = ["# necropsy — batch report", ""]
    lines.append(f"**Total dumps:** {len(results)}")
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict.value] = counts.get(r.verdict.value, 0) + 1
    for k in ("EXPLOITABLE", "PROBABLY_EXPLOITABLE", "UNKNOWN", "NOT_EXPLOITABLE"):
        if k in counts:
            lines.append(f"- **{k}:** {counts[k]}")
    lines.append("")

    lines.append("## Ranked by score")
    lines.append("")
    lines.append("| Score | Verdict | Dump | Exception | Access | Module | Frame |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in sorted(results, key=lambda x: -x.score):
        lines.append(
            f"| {r.score} | {r.verdict.value} | "
            f"{_basename(r.path)} | {r.exception_name} | "
            f"{r.access_type or '-'} | {r.faulting_module or '-'} | "
            f"{r.faulting_frame or '-'} |"
        )
    lines.append("")

    top = sorted(results, key=lambda x: -x.score)[:5]
    if top:
        lines.append("## Top findings")
        lines.append("")
        for r in top:
            lines.append(f"### {_basename(r.path)} — score {r.score}")
            lines.append("")
            lines.append(f"- **Verdict:** {r.verdict.value}")
            lines.append(f"- **Exception:** {r.exception_name} "
                         f"(`0x{r.exception_code:08X}`)")
            if r.access_type:
                lines.append(f"- **Access:** {r.access_type}")
            lines.append(f"- **Faulting address:** `0x{r.faulting_address:x}`")
            if r.faulting_module:
                lines.append(f"- **Module:** {r.faulting_module}")
            if r.faulting_frame:
                lines.append(f"- **Frame:** {r.faulting_frame}")
            lines.append("")
            if r.findings:
                lines.append("**Findings:**")
                for f in _sorted_findings(r):
                    lines.append(f"- `[{f.severity}]` **{f.rule}** — {f.detail}")
                lines.append("")
    return "\n".join(lines)


def _basename(p: str) -> str:
    return p.replace("\\", "/").rsplit("/", 1)[-1]