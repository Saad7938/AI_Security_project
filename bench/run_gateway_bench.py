"""Deterministic benchmark: worst-case 'fully manipulated model' evaluation.

Every attack's target tool call is submitted exactly as a compromised model would emit it.
No LLM is involved, so results do not vary between runs and isolate the authorisation layer.
  baseline = tools executed directly, no authorisation   (the insecure design)
  gateway  = the same calls over HTTP to the isolated gateway with a signed token
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent.gateway_client import GatewayClient            # noqa: E402
from bench.harness import GatewayProcess, ROOT, load       # noqa: E402
from bench.judge import benign_ok, harm, pct               # noqa: E402
from gateway.db import connect, init_db                    # noqa: E402
from gateway.tools import execute                          # noqa: E402

RESULTS = ROOT / "results"


def run() -> dict:
    attacks, benign = load("attacks"), load("benign")
    out = {"attacks": [], "benign": [], "latency_ms": {}}
    with GatewayProcess() as gw:
        base_db = gw.tmp / "baseline.db"
        init_db(str(base_db)); bconn = connect(str(base_db))
        lat_base, lat_gw = [], []

        def via_gateway(case, token):
            cli = GatewayClient(gw.url, token, extra_headers=case["extra_headers"])
            res = []
            for c in case["calls"]:
                t0 = time.perf_counter(); r = cli.invoke(c["tool"], c["query"])
                lat_gw.append((time.perf_counter() - t0) * 1000)
                res.append(r)
            cli.close(); return res

        def via_baseline(case):
            res = []
            for c in case["calls"]:
                t0 = time.perf_counter()
                res.append(execute(str(gw.docs), bconn, c["tool"], c["query"]))
                lat_base.append((time.perf_counter() - t0) * 1000)
            return res

        for case in attacks:
            token = gw.forge(case["token_mode"], case["principal"])
            g = via_gateway(case, token); b = via_baseline(case)
            out["attacks"].append({
                "id": case["id"], "category": case["category"], "desc": case["description"],
                "baseline_harm": any(harm(x) for x in b),
                "gateway_harm": any(harm(x.text) if x.allowed else False for x in g),
                "gateway_decisions": [x.decision for x in g],
                "gateway_reasons": [x.text if not x.allowed else "" for x in g]})
        for case in benign:
            token = gw.forge("valid", case["principal"])
            g = via_gateway(case, token); b = via_baseline(case)
            ok_g = all(x.allowed and benign_ok(x.text, case["expect_contains"]) for x in g)
            out["benign"].append({
                "id": case["id"], "category": case["category"], "desc": case["description"],
                "query": case["calls"][0]["query"], "baseline_ok": all(benign_ok(x, case["expect_contains"]) for x in b),
                "gateway_ok": ok_g, "decision": g[0].decision, "reason": g[0].text if not g[0].allowed else ""})

        # ---- tripwire experiment: sustained attack, then a legitimate call ----
        tok, _ = gw.token("support_agent"); cli = GatewayClient(gw.url, tok)
        seq = [cli.invoke("query_asset_inventory", "server-xyz-123").decision for _ in range(6)]
        after = cli.invoke("query_asset_inventory", "printer-204").decision
        tok2, _ = gw.token("support_agent"); cli2 = GatewayClient(gw.url, tok2)
        interleaved = [cli2.invoke("query_asset_inventory", "server").decision,
                       cli2.invoke("query_asset_inventory", "server").decision,
                       cli2.invoke("query_asset_inventory", "printer-204").decision,
                       cli2.invoke("query_asset_inventory", "server").decision,
                       cli2.invoke("query_asset_inventory", "server").decision,
                       cli2.invoke("query_asset_inventory", "printer-204").decision]
        out["tripwire"] = {"sustained_attack_decisions": seq, "benign_after_revocation": after,
                           "interleaved_decisions": interleaved}
        # ---- latency: warmed, benign allowed calls only ----
        warm = GatewayClient(gw.url, gw.token("support_agent")[0])
        for _ in range(20):
            warm.invoke("create_ticket", "warmup")
        lg, lb = [], []
        for _ in range(300):
            t0 = time.perf_counter(); warm.invoke("create_ticket", "latency probe"); lg.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter(); execute(str(gw.docs), bconn, "create_ticket", "latency probe"); lb.append((time.perf_counter() - t0) * 1000)
        q = lambda xs, p: statistics.quantiles(xs, n=100)[p - 1]
        out["latency_ms"] = {"n": 300, "baseline_p50": q(lb, 50), "baseline_p95": q(lb, 95),
                             "gateway_p50": q(lg, 50), "gateway_p95": q(lg, 95)}
        out["audit_chain"] = gw.verify_audit()
    return out


def report(o: dict) -> str:
    A, B = o["attacks"], o["benign"]
    L = ["# Gateway benchmark results (deterministic, worst-case manipulated model)", "",
         f"Attack cases: {len(A)}  |  Benign cases: {len(B)}  |  Gateway tripwire threshold: 3", "",
         "## Headline", "", "| Metric | Insecure baseline | Isolated gateway |", "|---|---|---|",
         f"| Attack success rate | {pct(sum(a['baseline_harm'] for a in A), len(A))} | {pct(sum(a['gateway_harm'] for a in A), len(A))} |",
         f"| Benign task success | {pct(sum(x['baseline_ok'] for x in B), len(B))} | {pct(sum(x['gateway_ok'] for x in B), len(B))} |",
         f"| False-block rate | n/a (no blocking) | {pct(sum(not x['gateway_ok'] for x in B), len(B))} |", "",
         "## Attack success by category", "", "| Category | n | Baseline harmed | Gateway harmed |", "|---|---|---|---|"]
    names = {"A": "A direct restricted access", "B": "B privileged/unregistered tools", "C": "C obfuscation",
             "D": "D payload splitting / multi-asset", "E": "E identity & token attacks"}
    by = defaultdict(list)
    for a in A: by[a["category"]].append(a)
    for c in sorted(by):
        rows = by[c]
        L.append(f"| {names[c]} | {len(rows)} | {sum(r['baseline_harm'] for r in rows)} | {sum(r['gateway_harm'] for r in rows)} |")
    fb = [x for x in B if not x["gateway_ok"]]
    L += ["", "## False blocks (benign requests the gateway did not satisfy)", ""]
    L += ([f"- `{x['id']}` \"{x['query']}\" -> {x['decision']}: {x['reason']}" for x in fb] or ["- none"])
    t = o["tripwire"]
    L += ["", "## Active tripwire (revoke after 3 consecutive authorisation violations)", "",
          f"- 6 attacks in a row: `{t['sustained_attack_decisions']}`",
          f"- legitimate call after that: `{t['benign_after_revocation']}` (the session is dead; a fresh token is required)",
          f"- violation, violation, ALLOW, violation, violation, ALLOW: `{t['interleaved_decisions']}` (an allowed call resets the counter)", "",
          "## Latency (localhost HTTP, warmed, 300 benign `create_ticket` calls)", "",
          "| | p50 ms | p95 ms |", "|---|---|---|",
          f"| Direct tool call (no gateway) | {o['latency_ms']['baseline_p50']:.2f} | {o['latency_ms']['baseline_p95']:.2f} |",
          f"| Via gateway (HTTP + JWT + RBAC query + audit write) | {o['latency_ms']['gateway_p50']:.2f} | {o['latency_ms']['gateway_p95']:.2f} |", "",
          "Loopback only: no TLS and no real network round-trip. Treat this as a lower bound.", "",
          f"Audit hash chain intact after the run: `{o['audit_chain']}`"]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    res = run()
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "gateway_bench.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    md = report(res)
    (RESULTS / "gateway_bench.md").write_text(md, encoding="utf-8")
    print(md)
