"""Run the kill chain phase by phase, saving the engagement after each hand-off."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from autostrike.models import Engagement, PhaseRecord
from autostrike.phases import (
    EnumerationPhase,
    ExploitSimPhase,
    Phase,
    PostExploitSimPhase,
    ReconPhase,
    ReportPhase,
    RunOptions,
)
from autostrike.transport import Transport

PHASE_NAMES = ["recon", "enumeration", "exploitation-sim", "post-exploitation-sim", "reporting"]


def build_phases(outdir: Path) -> list[Phase]:
    return [ReconPhase(), EnumerationPhase(), ExploitSimPhase(), PostExploitSimPhase(), ReportPhase(outdir)]


def run_pipeline(
    eng: Engagement,
    transport: Transport | None,
    opts: RunOptions,
    outdir: str | Path,
    start_at: str = "recon",
    log: Callable[[str], None] = print,
) -> Engagement:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    phases = build_phases(outdir)
    start = PHASE_NAMES.index(start_at)
    for phase in phases[start:]:
        if phase.name in ("recon", "enumeration") and transport is None:
            raise ValueError(f"phase {phase.name} needs a transport")
        started = _now()
        log(f"[{phase.name}] running")
        summary = phase.run(eng, transport, opts)
        eng.phases.append(PhaseRecord(name=phase.name, started=started, finished=_now(), summary=summary))
        eng.save(outdir / "engagement.json")
        log(f"[{phase.name}] {summary}")
    return eng


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
