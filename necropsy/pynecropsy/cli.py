"""Command-line entry point."""
import argparse
import sys
from pathlib import Path

from . import __version__
from .minidump import parse
from .triage import triage, Verdict
from . import report


def _analyze(path: Path, fmt: str, verbose: bool) -> int:
    try:
        md = parse(str(path))
    except Exception as e:
        print(f"[!] failed to parse {path.name}: {e}", file=sys.stderr)
        return 1

    t = triage(md)

    if fmt == "json":
        print(report.format_json(t))
    elif fmt == "text":
        print(report.format_text(t, md))
    elif fmt == "csv":
        print(report.csv_header())
        print(report.format_csv_row(t))
    elif fmt == "quiet":
        print(f"{path.name}\t{t.verdict.value}\t{t.score}")
    return 0


def _batch(dir_path: Path, out_dir: Path, fmt: str, jobs: int) -> int:
    dumps = sorted(dir_path.glob("*.dmp"))
    if not dumps:
        print(f"[!] no .dmp files in {dir_path}", file=sys.stderr)
        return 1

    print(f"[*] found {len(dumps)} dumps in {dir_path}")

    results = []
    for i, d in enumerate(dumps, 1):
        try:
            md = parse(str(d))
            t = triage(md)
            results.append(t)
            print(f"  [{i}/{len(dumps)}] {d.name:<40} "
                  f"{t.verdict.value:<22} score={t.score}")
        except Exception as e:
            print(f"  [{i}/{len(dumps)}] {d.name:<40} [FAILED] {e}",
                  file=sys.stderr)

    if not results:
        print("[!] no dumps successfully analyzed", file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON (all results)
    import json
    (out_dir / "triage.json").write_text(
        json.dumps([r.to_dict() for r in results], indent=2),
        encoding="utf-8",
    )

    # CSV
    with open(out_dir / "triage.csv", "w", newline="", encoding="utf-8") as f:
        f.write(report.csv_header() + "\n")
        for r in results:
            f.write(report.format_csv_row(r) + "\n")

    # Markdown
    (out_dir / "triage.md").write_text(
        report.format_markdown(results),
        encoding="utf-8",
    )

    print()
    print(f"[+] wrote {out_dir}/triage.json")
    print(f"[+] wrote {out_dir}/triage.csv")
    print(f"[+] wrote {out_dir}/triage.md")

    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict.value] = counts.get(r.verdict.value, 0) + 1
    print()
    print("[*] summary:")
    for k in ("EXPLOITABLE", "PROBABLY_EXPLOITABLE", "UNKNOWN", "NOT_EXPLOITABLE"):
        if k in counts:
            print(f"    {k:<22} {counts[k]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="necropsy",
        description="Crash dump triage pipeline — rank minidumps by exploitability.",
    )
    p.add_argument("--version", action="version",
                   version=f"necropsy {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze a single .dmp file")
    a.add_argument("dump", type=Path, help="path to .dmp file")
    a.add_argument("--format", choices=["text", "json", "csv", "quiet"],
                   default="text", help="output format (default: text)")
    a.add_argument("-v", "--verbose", action="store_true")

    b = sub.add_parser("batch", help="analyze a directory of .dmp files")
    b.add_argument("dir", type=Path, help="directory containing .dmp files")
    b.add_argument("-o", "--out", type=Path, default=Path("triage_out"),
                   help="output directory (default: triage_out)")
    b.add_argument("--format", choices=["text", "json", "md"],
                   default="md", help="report format (default: md)")
    b.add_argument("-j", "--jobs", type=int, default=1,
                   help="parallel jobs (currently serial)")

    i = sub.add_parser("info", help="print parsed header info about a dump")
    i.add_argument("dump", type=Path)

    return p


def main(argv=None) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    if args.cmd == "analyze":
        return _analyze(args.dump, args.format, args.verbose)

    if args.cmd == "batch":
        return _batch(args.dir, args.out, args.format, args.jobs)

    if args.cmd == "info":
        try:
            md = parse(str(args.dump))
        except Exception as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1
        print(f"path:         {md.path}")
        print(f"size:         {md.size} bytes")
        print(f"timestamp:    {md.timestamp}")
        print(f"flags:        0x{md.flags:x}")
        print(f"modules:      {len(md.modules)}")
        print(f"threads:      {len(md.threads)}")
        if md.system_info:
            si = md.system_info
            print(f"arch:         {si.arch_name}")
            print(f"cores:        {si.number_of_processors}")
            print(f"os:           {si.major_version}.{si.minor_version}."
                  f"{si.build_number}")
            print(f"csd:          {si.csd_version}")
        if md.exception:
            ex = md.exception
            print(f"exception:    0x{ex.code:08X}")
            print(f"address:      0x{ex.address:x}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())