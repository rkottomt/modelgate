"""Scan a batch of popular custom-code HF repos (code only) and summarise."""
import json, sys, time
from collections import Counter
from modelgate.scanner import scan
REPOS = [
 "microsoft/Phi-3-mini-4k-instruct", "microsoft/Phi-3-mini-128k-instruct", "microsoft/Phi-3.5-mini-instruct",
 "microsoft/Phi-3.5-MoE-instruct", "microsoft/Florence-2-large", "microsoft/Florence-2-base",
 "THUDM/chatglm3-6b", "THUDM/chatglm2-6b", "THUDM/glm-4-9b-chat", "Qwen/Qwen-7B-Chat", "Qwen/Qwen-VL-Chat",
 "Qwen/Qwen-1_8B-Chat", "deepseek-ai/DeepSeek-V3", "deepseek-ai/DeepSeek-V2-Lite", "deepseek-ai/DeepSeek-V2-Lite-Chat",
 "baichuan-inc/Baichuan2-7B-Chat", "baichuan-inc/Baichuan2-13B-Chat", "internlm/internlm2-chat-7b",
 "internlm/internlm2_5-7b-chat", "OpenGVLab/InternVL2-8B", "OpenGVLab/InternVL2-2B", "openbmb/MiniCPM-V-2_6",
 "openbmb/MiniCPM-2B-sft-bf16", "nomic-ai/nomic-embed-text-v1.5", "nomic-ai/nomic-embed-text-v1",
 "jinaai/jina-embeddings-v3", "jinaai/jina-embeddings-v2-base-en", "jinaai/jina-clip-v1",
 "Alibaba-NLP/gte-large-en-v1.5", "Alibaba-NLP/gte-base-en-v1.5", "apple/OpenELM-270M", "apple/OpenELM-1_1B",
 "nvidia/NV-Embed-v2", "tiiuae/falcon-7b", "tiiuae/falcon-7b-instruct", "01-ai/Yi-6B", "mosaicml/mpt-7b-instruct",
 "Salesforce/codet5p-220m-bimodal", "moonshotai/Kimi-K2-Instruct", "MiniMaxAI/MiniMax-Text-01",
]
rows = []
t0 = time.time()
for r in REPOS:
    try:
        rep = scan(r, use_llm=False, use_allowlist=False)
    except Exception as e:  # noqa
        print(r, "ERROR", e, flush=True); continue
    sb = rep.get("sandbox", {})
    sbx = sorted({f["rule_id"] for f in rep.get("findings", []) if f["source"] == "sandbox" and f["severity"] == "critical" and f["rule_id"] in ("SBX-NET","SBX-PROC","SBX-MEMFD","SBX-PROCNAME","SBX-EXFIL","SBX-CANARY","SBX-SENSITIVE")})
    row = {"repo": r, "verdict": rep["verdict"], "secs": rep.get("scan_seconds"), "sandbox": f"{sb.get('mode')}/{sb.get('status')}",
           "files": len((rep.get("bundle") or {}).get("files", {})), "fetch_failed": any(f["rule_id"].startswith("MG004") for f in rep.get("findings", [])),
           "malicious_behaviour": sbx, "top": rep.get("reasons", [])[:2]}
    rows.append(row); print(json.dumps(row)[:220], flush=True)
ok = [x for x in rows if not x["fetch_failed"]]
print("TOTAL", len(rows), "fetched", len(ok), "verdicts", Counter(x["verdict"] for x in ok),
      "ran_in_sandbox", sum(x["sandbox"].startswith("docker") for x in ok),
      "malicious_behaviour", sum(bool(x["malicious_behaviour"]) for x in ok),
      "mean_secs", round(sum(x["secs"] or 0 for x in ok)/max(1,len(ok)),2), "wall", round(time.time()-t0,1))
json.dump(rows, open(sys.argv[1], "w"), indent=2)
