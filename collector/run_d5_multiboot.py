#!/usr/bin/env python3
"""Frozen five-boot D5 orchestrator."""

from __future__ import annotations

import argparse, json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

from run_campaign import ACK
from run_d5_campaign import EXPECTED_BATCHES, PROTOCOL

SEEDS = (8601, 8602, 8603, 8604, 8605)

def now(): return datetime.now(timezone.utc).isoformat()
def boot_id(): return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
def write(path, state):
    path.parent.mkdir(parents=True, exist_ok=True); tmp=path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8"); tmp.replace(path)

def main():
    p=argparse.ArgumentParser(); p.add_argument("--state",required=True,type=Path)
    p.add_argument("--output-root",required=True,type=Path); p.add_argument("--project-root",required=True,type=Path)
    p.add_argument("--sham-ko",required=True,type=Path); p.add_argument("--hiding-ko",required=True,type=Path)
    p.add_argument("--isolated-vm-ack",required=True); a=p.parse_args()
    if os.geteuid()!=0 or a.isolated_vm_ack!=ACK: p.error("root and isolated ack required")
    if subprocess.run(["ip","route","show","default"],capture_output=True,text=True,check=True).stdout.strip(): raise RuntimeError("default route present")
    if any(line.split()[0] in {"caraxes","caraxes_sham"} for line in Path("/proc/modules").read_text().splitlines() if line): raise RuntimeError("module loaded at boot start")
    state=(json.loads(a.state.read_text()) if a.state.exists() else {"schema_version":1,"protocol_revision":PROTOCOL,"created_utc":now(),"total_boots":5,"next_sequence":1,"status":"ready","completed_boots":[]})
    if state.get("protocol_revision")!=PROTOCOL: raise RuntimeError("state protocol mismatch")
    seq=int(state["next_sequence"])
    if seq>5: state["status"]="complete"; state.setdefault("completed_utc",now()); write(a.state,state); return
    bid=boot_id()
    if bid in {x["boot_id"] for x in state["completed_boots"]}: raise RuntimeError("new boot required")
    out=a.output_root.resolve()/f"boot_{seq:02d}"
    if out.exists(): raise RuntimeError(f"refusing overwrite {out}")
    state.update(status="running",active_sequence=seq,active_boot_id=bid,active_seed=SEEDS[seq-1],active_started_utc=now()); write(a.state,state)
    cmd=[sys.executable,str(a.project_root.resolve()/"collector"/"run_d5_campaign.py"),"--sham-ko",str(a.sham_ko.resolve()),"--hiding-ko",str(a.hiding_ko.resolve()),"--output",str(out),"--seed",str(SEEDS[seq-1]),"--isolated-vm-ack",ACK]
    try:
        subprocess.run(cmd,check=True,cwd=a.project_root.resolve())
        manifests=list(out.glob("campaign_*.json")); manifest=json.loads(manifests[0].read_text()) if len(manifests)==1 else {}
        done=sum(x.get("status")=="complete" for x in manifest.get("schedule",[]))
        if manifest.get("status")!="complete" or done!=EXPECTED_BATCHES: raise RuntimeError(f"incomplete manifest {done}/{EXPECTED_BATCHES}")
    except BaseException as exc:
        state.update(status="failed",failed_utc=now(),failure=f"{type(exc).__name__}: {exc}"); write(a.state,state); raise
    state["completed_boots"].append({"sequence":seq,"boot_id":bid,"seed":SEEDS[seq-1],"batches":EXPECTED_BATCHES,"manifest":str(manifests[0]),"completed_utc":now()}); state["next_sequence"]=seq+1
    if seq==5: state.update(status="complete",completed_utc=now()); write(a.state,state); return
    state["status"]="rebooting"; write(a.state,state); subprocess.run(["sync"],check=True); subprocess.run(["systemctl","reboot"],check=True)

if __name__=="__main__": main()
