#!/usr/bin/env python3
"""Locked boot-cluster D5-r1 analysis (single W20 only)."""

from __future__ import annotations

import argparse, csv, gzip, hashlib, json
from pathlib import Path
import numpy as np

from analyze_d4_qualification import _extract, _write_csv
from d4_context_axis import fit_context_axis, score_context_axis

W=20; METHODS=("fixed","blind","guarded")

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def rate(rows,key="alert"): return sum(bool(r[key]) for r in rows)/len(rows)

def replay(root: Path):
    manifests=list(root.glob("campaign_*.json"))
    if len(manifests)!=1: raise ValueError(f"manifest count in {root}")
    manifest=json.loads(manifests[0].read_text())
    if manifest.get("protocol_revision")!="D5-r1-2026-09-19" or manifest.get("status")!="complete": raise ValueError("invalid D5 manifest")
    rows=[_extract(p) for p in sorted(root.glob("batch_*.json.gz"))]; by={r["campaign_position"]:r for r in rows}
    clean=[];sham=[];test=[]
    for item in manifest["schedule"]:
        r=by[item["position"]]
        if item["phase"]=="calibration": (clean if item["state"]=="unloaded" else sham).append(r)
        else: test.append((item,r))
    model=fit_context_axis(clean,sham)
    opcal=[r for r in clean if r["cpu_busy_fraction"]<model["context_split"]]
    anchor=float(np.median([r["first_raw_median"] for r in opcal])); opthr=float(max(r["first_raw_median"]/anchor for r in opcal)*1.01)
    predictions=[]
    for method in METHODS:
        ref=[(r["first_raw_median"],"unloaded") for r in opcal][-W:]
        for item,r in test:
            stratum,ss,st,sa=score_context_axis(model,r); aa=anchor if method=="fixed" else float(np.median([v for v,_ in ref])); oa=r["first_raw_median"]/aa>opthr
            alert=oa if method in {"fixed","blind"} else oa or sa
            accept=method=="blind" or (method=="guarded" and not sa)
            if method!="fixed" and accept: ref=(ref+[(r["first_raw_median"],item["state"])])[-W:]
            predictions.append({"boot_id":manifest["boot_id"],"method":method,"position":item["position"],"segment":item["segment"],"state":item["state"],"condition":item["condition"],"context_stratum":stratum,"security_alert":sa,"operational_alert":oa,"alert":alert,"accepted_update":method!="fixed" and accept,"window_attack_fraction":sum(s=="hiding" for _,s in ref)/len(ref) if method!="fixed" else 0.0})
    metrics=[]
    for method in METHODS:
        s=[r for r in predictions if r["method"]==method]; normal=[r for r in s if r["state"]!="hiding"];attack=[r for r in s if r["state"]=="hiding"];sham_rows=[r for r in s if r["state"]=="sham"]
        metrics.append({"boot_id":manifest["boot_id"],"method":method,"normal_n":len(normal),"normal_fpr":rate(normal),"sham_n":len(sham_rows),"sham_fpr":rate(sham_rows),"attack_n":len(attack),"attack_recall":rate(attack),"attack_updates":sum(r["accepted_update"] for r in attack),"attack_update_rate":sum(r["accepted_update"] for r in attack)/len(attack),"normal_updates":sum(r["accepted_update"] for r in normal),"normal_update_rate":sum(r["accepted_update"] for r in normal)/len(normal),"max_window_attack_fraction":max(r["window_attack_fraction"] for r in s),"unknown_rate":0.0})
    return manifest,predictions,metrics

def main():
    p=argparse.ArgumentParser();p.add_argument("--input",required=True,type=Path);p.add_argument("--lock",required=True,type=Path);p.add_argument("--output",required=True,type=Path);a=p.parse_args()
    if a.output.exists(): raise FileExistsError(a.output)
    lock=json.loads(a.lock.read_text())
    for name,item in lock["files"].items():
        path=Path(item["path"]); actual=sha(path)
        if actual!=item["sha256"]: raise RuntimeError(f"hash mismatch {name}: {actual}")
    boots=sorted(path for path in a.input.glob("boot_*" ) if path.is_dir())
    if len(boots)!=5: raise ValueError(f"expected 5 boots, got {len(boots)}")
    manifests=[];pred=[];metrics=[]
    for root in boots:
        m,preds,met=replay(root);manifests.append(m);pred+=preds;metrics+=met
    if len({m["boot_id"] for m in manifests})!=5: raise ValueError("boot IDs not unique")
    fixed={r["boot_id"]:r for r in metrics if r["method"]=="fixed"};guard={r["boot_id"]:r for r in metrics if r["method"]=="guarded"}
    diffs=np.array([guard[b]["normal_fpr"]-fixed[b]["normal_fpr"] for b in sorted(fixed)]);rng=np.random.default_rng(20260919);draw=rng.choice(diffs,size=(10000,len(diffs)),replace=True).mean(1);ci=[float(np.quantile(draw,.025)),float(np.quantile(draw,.975))]
    overall=[]
    for method in METHODS:
        s=[r for r in pred if r["method"]==method];normal=[r for r in s if r["state"]!="hiding"];attack=[r for r in s if r["state"]=="hiding"];sh=[r for r in s if r["state"]=="sham"]
        overall.append({"method":method,"normal_n":len(normal),"normal_fpr":rate(normal),"sham_fpr":rate(sh),"attack_n":len(attack),"attack_recall":rate(attack),"attack_update_rate":sum(r["accepted_update"] for r in attack)/len(attack),"normal_update_rate":sum(r["accepted_update"] for r in normal)/len(normal),"max_window_attack_fraction":max(r["window_attack_fraction"] for r in s),"unknown_rate":0.0})
    f=next(r for r in overall if r["method"]=="fixed");g=next(r for r in overall if r["method"]=="guarded")
    rules={"five_unique_boots":True,"guarded_recall_ge_0_95":g["attack_recall"]>=.95,"recall_drop_le_0_02":f["attack_recall"]-g["attack_recall"]<=.02,"fpr_reduction_ge_0_20":f["normal_fpr"]-g["normal_fpr"]>=.20,"paired_fpr_ci_upper_le_minus_0_05":ci[1]<=-.05,"attack_update_rate_le_0_10":g["attack_update_rate"]<=.10,"normal_update_rate_ge_0_90":g["normal_update_rate"]>=.90,"max_window_attack_fraction_le_0_30":g["max_window_attack_fraction"]<=.30,"unknown_rate_eq_0":g["unknown_rate"]==0,"sham_fpr_le_0_20":g["sham_fpr"]<=.20}
    report={"protocol":"D5-r1-2026-09-19","window":W,"boots":5,"overall":overall,"paired_guarded_minus_fixed_fpr_mean":float(diffs.mean()),"paired_bootstrap_95_ci":ci,"rules":rules,"method_efficacy_pass":all(rules.values()),"deployment_overhead_rule":"separate; existing D4 operation-latency overhead exceeds 5% and remains FAIL"}
    a.output.mkdir(parents=True);_write_csv(a.output/"per_boot_metrics.csv",metrics);_write_csv(a.output/"predictions.csv",pred);(a.output/"report.json").write_text(json.dumps(report,indent=2),encoding="utf-8");print(json.dumps(report,indent=2))

if __name__=="__main__": main()
