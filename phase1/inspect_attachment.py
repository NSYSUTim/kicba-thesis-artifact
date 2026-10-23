"""First pilot: preserve the actual BCC backend, event definitions and counts."""

import argparse
import json
import os
from pathlib import Path

from bcc import BPF

from coverage import compare_window


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    args = parser.parse_args()
    checkpoint = json.loads(args.checkpoint.read_text(encoding="utf-8-sig"))
    if not checkpoint.get("success") or not checkpoint.get("checkpoint_id"):
        raise RuntimeError("verified checkpoint required")
    if args.output.exists():
        raise FileExistsError(args.output)
    profile = Path("/sys/kernel/debug/tracing/kprobe_profile")
    events = Path("/sys/kernel/debug/tracing/kprobe_events")
    bpf = BPF(text="""
        #include <uapi/linux/ptrace.h>
        int inspect_enter(struct pt_regs *ctx) { return 0; }
        int inspect_return(struct pt_regs *ctx) { return 0; }
    """)
    record = {"loader_pid": os.getpid(), "maxactive": 256}
    try:
        bpf.attach_kprobe(event="filldir64", fn_name="inspect_enter")
        bpf.attach_kretprobe(event="filldir64", fn_name="inspect_return", maxactive=256)
        record["events_before"] = events.read_text()
        record["profile_before"] = profile.read_text()
        record["listing_count"] = len(os.listdir("/home/kicba"))
        record["profile_after"] = profile.read_text()
        record["events_after"] = events.read_text()
        required = ["r_filldir64_bcc_" + str(os.getpid())]
        record["required_events"] = required
        record["coverage"] = compare_window(
            record["profile_before"], record["profile_after"], required
        )
        record["entry_profile_present"] = (
            "p_filldir64_bcc_" + str(os.getpid()) in record["profile_after"]
        )
    except Exception as error:
        record["error"] = repr(error)
        raise
    finally:
        bpf.cleanup()
        record["events_after_cleanup"] = events.read_text()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2)
    print(json.dumps({key: record.get(key) for key in
                      ("coverage", "entry_profile_present", "listing_count", "error")}))


if __name__ == "__main__":
    main()
