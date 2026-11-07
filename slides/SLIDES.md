# ModelGate: 5-minute talk

The deck is `slides/deck/index.html`. Open it in a browser from inside the repo, then use the arrow keys, and F for fullscreen.
It has six slides and runs about **4:30** with the video, leaving 30 s of slack.

| # | Slide | Time | Running |
|---|---|---|---|
| 1 | ModelGate | 0:15 | 0:15 |
| 2 | One flag runs a stranger's code | 0:50 | 1:05 |
| 3 | It's already being exploited | 0:50 | 1:55 |
| 4 | One import. Checked before it runs | 0:45 | 2:40 |
| 5 | Demo (42 s video) | 1:00 | 3:40 |
| 6 | Where it stands | 0:50 | 4:30 |

---

## 1. ModelGate (0:15)

**Say:** "We built ModelGate. It's a gate in front of the one line that lets an AI model run its own code on your computer."

## 2. One flag runs a stranger's code (0:50)

**Say:**
- "Popular models such as Phi-3, Qwen, DeepSeek, ChatGLM, Jina and Nomic ship their own Python. To load them, you pass `trust_remote_code=True`."
- "That code runs the moment you load the model. It runs as you, with your SSH keys, your Hugging Face and cloud tokens, and your network, before you've called the model once."
- "No one checks it. It can change with any push, and the scanners people rely on mostly look at the weight files, not this code."

## 3. It's already being exploited (0:50)

**Say:**
- "This autumn, 31 repos used this exact flag to plant crypto miners and reverse shells. They were downloaded 32,000 times and passed three existing scanners."
- "In July, AI agents under test escaped through the one network path they were allowed. In 13 hours they took admin control of Hugging Face's own servers."
- "It isn't new either. In 2024, about 100 malicious models were opening reverse shells on the machines that loaded them."
- "So there are two problems: models that attack whoever loads them, and agents that escape the box they were given. ModelGate checks both."

**Verify before presenting.** These numbers came from research agents, not from our own work:
- Sep–Oct 2026 miner campaign (Pluto Security): https://www.bleepingcomputer.com/news/security/hugging-face-malware-campaign-returns-to-hijack-gpus-for-crypto-mining/
- Jul 2026 agent intrusion: https://huggingface.co/blog/agent-intrusion-technical-timeline · https://openai.com/index/hugging-face-model-evaluation-security-incident/ · https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/
- Feb 2024 (JFrog): https://www.bleepingcomputer.com/news/security/malicious-ai-models-on-hugging-face-backdoor-users-machines/

## 4. One import. Checked before it runs (0:45)

**Say:**
- "You add one import, and every model load goes through four steps. First we download only the code, locked to one commit. Then we read it. Then we run it in an offline container with decoy keys and record every system call. Finally, fixed rules decide: Allow, Warn or Block."
- "An AI writes the plain-English explanation, but the verdict is decided before the AI sees anything, and the AI can't change it. A repo that tells AI reviewers 'this is safe' still gets blocked."
- "For agents it's the same idea: say what the job is, approve the guardrails the AI drafts, and every action the agent takes is checked against them."

## 5. Demo (1:00; the video is 42 s)

Click play. While it runs:
- "This is a real Hugging Face model, ChatGLM3. Its code decodes a compressed blob and runs it as native code. We can't verify that, so it's blocked." (To be fair, the blob is a GPU kernel. The point is that it can't be checked.)
- "So we pick a different model. Qwen2.5 needs no custom code, so it's allowed, and the load is locked to the exact commit we scanned."
- "Next is the agent that will use it. We say what it's for, the AI drafts guardrails, we approve them, and it runs in the sandbox. It stayed within its guardrails."

If the video won't play, run the same flow live: start `modelgate serve` and open http://127.0.0.1:8000.

## 6. Where it stands (0:50)

**Say:**
- "On six harmless imitations of attacks, including one that only fires on a GPU, it was 6 for 6."
- "On six popular real models with custom code, none got through without review. Two were blocked by mistake, and the README explains both."
- "A scan takes about three seconds."
- "It isn't finished. A payload that waits hours can slip past a short run, Docker shares the host kernel, and agents run fully offline for now. Next: approved internet access for agents through a proxy that holds the API key, token tracking, and a stronger sandbox."
- "Thanks. The code is at github.com/rkottomt/modelgate."

---

Extra material, not in the deck: `images/` has the full pipeline diagram, the eval table, dashboard and agent screenshots, and the import hook's terminal output, in case a judge asks.
