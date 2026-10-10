import json
import shutil
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EngineResult:
    path: str
    size: int = 0
    timestamp: int = 0
    module_count: int = 0
    verdict: str = "UNKNOWN"
    score: int = 0
    exception_code: str = ""
    exception_name: str = ""
    access_type: str = ""
    faulting_address: str = ""
    faulting_module: str = ""
    faulting_frame: str = ""
    instruction_pointer: str = ""
    stack_pointer: str = ""
    rationale: str = ""
    registers: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "EngineResult":
        return cls(
            path=d.get("path", ""),
            size=d.get("size", 0),
            timestamp=d.get("timestamp", 0),
            module_count=d.get("module_count", 0),
            verdict=d.get("verdict", "UNKNOWN"),
            score=d.get("score", 0),
            exception_code=d.get("exception_code", ""),
            exception_name=d.get("exception_name", ""),
            access_type=d.get("access_type", ""),
            faulting_address=d.get("faulting_address", ""),
            faulting_module=d.get("faulting_module", ""),
            faulting_frame=d.get("faulting_frame", ""),
            instruction_pointer=d.get("instruction_pointer", ""),
            stack_pointer=d.get("stack_pointer", ""),
            rationale=d.get("rationale", ""),
            registers=d.get("registers", {}),
            findings=d.get("findings", []),
        )


_ENGINE_CANDIDATES = [
    "necropsy-engine.exe",
    "necropsy-engine",
    "engine/build/necropsy-engine.exe",
    "engine/build/Release/necropsy-engine.exe",
    "engine/build/Debug/necropsy-engine.exe",
    str(Path(__file__).parent.parent / "engine" / "build" / "necropsy-engine.exe"),
]


def find_engine() -> Optional[str]:
    """Locate the C++ engine. Returns None if not present."""
    for c in _ENGINE_CANDIDATES:
        p = Path(c)
        if p.is_file():
            return str(p)
    # try PATH
    which = shutil.which("necropsy-engine")
    if which:
        return which
    which = shutil.which("necropsy-engine.exe")
    if which:
        return which
    return None


def analyze_with_engine(engine_path: str, dump_path: str,
                        timeout: int = 60) -> Optional[EngineResult]:
    """Run the C++ engine on a dump. Returns None on failure."""
    try:
        proc = subprocess.run(
            [engine_path, dump_path, "--json"],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        if proc.returncode != 0:
            return None
        payload = json.loads(proc.stdout)
        return EngineResult.from_dict(payload)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None