#!/usr/bin/env python3
"""Compare accelerator first replies and stored details using only loopback fixtures."""
import argparse
import base64
import json
from pathlib import Path
import re
import tempfile
import time

from mcp_baseline import encode
from mcp_job_loopback import LoopbackJobs
from mcp_job_measure import Client, connected


class AcceleratorFixture(LoopbackJobs):
    packet_limit = 160_000

    def canned_reply(self, asset, packet):
        if b"__JMS_INSPECTION_PY__" not in packet:
            raise ValueError("unexpected fixture operation")
        match = re.search(rb'__jms_entry"\]\(json.loads\(base64.b64decode\("([A-Za-z0-9+/=]+)"\)', packet)
        if not match:
            raise ValueError("collector options missing")
        options = json.loads(base64.b64decode(match.group(1)))
        row = self.assets[asset]
        if options.get("mode") == "processes":
            self.count("ssh_enrich")
            pid, = options["pids"]
            return encode({"processes": [{"pid":pid, "user":"fixture",
                "container":{"name":"fixture-" + "c"*120}, "command":"exec " + "z"*140}]}) + b"\n"
        self.count("ssh_snapshot")
        time.sleep(row["latency"])
        states = {"free":["free"]*8, "partial":["free"]*6+["busy"]*7+["unknown"]*3,
                  "busy":["busy"]*16, "unknown":["unknown"]*16}[row["state"]]
        devices = [{"id":f"hygon:{i}","state":state,"model":"fixture-accelerator",
                    "util_pct":0.0 if state != "unknown" else None,
                    "memory_used_mib":(2.05078125 if state=="free" else 121703.53515625),
                    "memory_total_mib":147440.1171875}
                   for i,state in enumerate(states)]
        busy = [d["id"] for d in devices if d["state"] == "busy"]
        return encode(dict(state=row["state"], devices=devices,
            processes=[{"pid":1, "devices":busy}] if busy else [],
            errors=["process query incomplete"] if row["state"] == "unknown" else [],
            sampled_at=100, whole_node_available=row["state"]=="free")) + b"\n"


def read_all(c, action):
    arguments = action["arguments"].copy()
    assert action["tool"] == "read_result" and arguments["stream"] == "result"
    pages = []
    for _ in range(32):
        page = c.tool("detail", "read_result", **arguments)
        pages.append(page["text"])
        if page["eof"]:
            return json.loads("".join(pages))
        assert page["next_offset"] > arguments["offset"]
        arguments["offset"] = page["next_offset"]
    raise AssertionError("detail page budget exhausted")


def sample(b, mode, n, candidate, count):
    rows = [{"id":f"00000000-0000-4000-8000-{i+1:012d}","name":f"fixture-node-{i+1:02d}",
             "state":["free","partial","busy","unknown"][i%4],"latency":(n-i)*.018}
            for i in range(n)]
    with tempfile.TemporaryDirectory(prefix="jms-accelerator-first-page-") as d:
        root=Path(d)
        with AcceleratorFixture(root, {"targets":rows}).serving() as backend:
            with connected(b, root, backend.config, mode, timeout=120) as ex:
                c=Client(ex, False, count_result_tokens=count)
                args={"targets":[row["id"] for row in rows]}
                first=c.tool("first", "call", operation="jms_accelerator_status",arguments=args)
                snapshot_enrich={key:backend.counts[key] for key in ("ssh_snapshot","ssh_enrich")}
                wanted={"ssh_snapshot":n,"ssh_enrich":sum(r["state"] in ("partial","busy") for r in rows)}
                assert snapshot_enrich == wanted,(snapshot_enrich,wanted,backend.errors)
                if candidate:
                    hosts=first["hosts"]
                    assert [h["host"] for h in hosts]==[h["name"] for h in rows]
                    assert [h["state"] for h in hosts]==[h["state"] for h in rows]
                    assert "preview" not in first
                    assert first["snapshot_only"]
                    for i, host in enumerate(hosts):
                        assert not set(host) & {"occupants","devices","timing","address"}
                        if i%4==1:
                            assert host["free_devices"]==[f"hygon:{k}" for k in range(6)]
                            assert host["free"]==6 and host["total"]==16 and host["unknown"]==3
                        elif i%4==2:
                            assert host["activity"]=="occupied_low_util" and host["free"]==0
                        elif i%4==3:
                            assert host["unknown"]==16 and host["free"]==0
                # A completed scheduling decision does not require full diagnostics.
                decision_calls=1
                if "hosts" not in first:
                    old = read_all(c, first["next_action"])
                    assert len(old["hosts"]) == n
                    decision_calls += c.counts["detail"]
                if candidate and "diagnostics_action" in first:
                    details_action=first["diagnostics_action"]
                elif candidate:
                    details_action=first["details_action"]
                else:
                    stored=old if "hosts" not in first else first
                    details_action={"tool":"read_result","arguments":{"result_id":stored["result_id"],
                        "stream":"result","offset":0,"limit":4096}}
                details=read_all(c, details_action)
                assert len(details["hosts"])==n and "devices" in details["hosts"][0]
                assert {h["state"] for h in details["hosts"]}=={r["state"] for r in rows}
                assert not backend.errors,backend.errors
                assert snapshot_enrich == {key:backend.counts[key] for key in snapshot_enrich}
                tokens=c.result_tokens()
                decision_input=sum(count(text) for _,text in c.result_texts[:decision_calls])
                return dict(mode=mode,hosts=n,candidate=candidate,staged=first.get("staged",False),
                            decision_calls=decision_calls,decision_input=decision_input,
                            first_input=tokens["first"],all_input=tokens.total(),
                            all_calls=c.counts.total(),ssh=snapshot_enrich)



def check_unresolved(b, mode):
    rows = [{"id":f"00000000-0000-4000-8000-{i+1:012d}","name":f"valid-{i+1}",
             "state":"free","latency":.35 if i==0 else 0} for i in range(2)]
    with tempfile.TemporaryDirectory(prefix="jms-accelerator-unresolved-") as d:
        root=Path(d)
        with AcceleratorFixture(root, {"targets":rows}).serving() as backend:
            with connected(b, root, backend.config, mode, timeout=120) as ex:
                c=Client(ex, False)
                args={"targets":[rows[0]["id"],"missing-exact-target",rows[1]["id"]]}
                compact=c.tool("first","call",operation="jms_accelerator_status",arguments=args)
                assert not compact["ok"] and compact["hosts"]==[
                    {"host":"valid-1","state":"free","free":8,"total":8},
                    {"host":"missing-exact-target","state":"unknown","reason":"unresolved_target"},
                    {"host":"valid-2","state":"free","free":8,"total":8}]
                raw=read_all(c,compact["details_action"])
                assert raw["hosts"][1]["errors"] and raw["hosts"][1]["state"]=="unknown"
                assert backend.counts["ssh_snapshot"]==2 and backend.counts["ssh_enrich"]==0
                assert not backend.errors,backend.errors
    print(json.dumps({"mode":mode,"unresolved_target":"pass","permitted_ssh_snapshots":2}),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",type=Path,required=True)
    parser.add_argument("--mode",choices=("stdio","http"),required=True)
    parser.add_argument("--candidate",action="store_true")
    args=parser.parse_args()
    import tiktoken
    enc=tiktoken.get_encoding("o200k_base")
    if args.candidate: check_unresolved(args.binary.resolve(),args.mode)
    for n in (1,4,8):
        print(json.dumps(sample(args.binary.resolve(),args.mode,n,args.candidate,
                               lambda s:len(enc.encode_ordinary(s)))),flush=True)


if __name__=="__main__": main()
