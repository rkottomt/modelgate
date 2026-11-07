# ModelGate: 5-minute talk

Open `slides/deck/index.html` in a browser, from inside the repo. Arrow keys move between slides, F goes fullscreen.
The story follows the workflow: download a model (Problem 1 → Fix 1), build an agent on it (Problem 2 → Fix 2), then the demo.

| # | Slide | Time | Running |
|---|---|---|---|
| 1 | ModelGate | 0:10 | 0:10 |
| 2 | What every AI team does | 0:25 | 0:35 |
| 3 | Problem 1: the model runs its own code | 0:50 | 1:25 |
| 4 | Fix 1: checked before it runs | 0:40 | 2:05 |
| 5 | Problem 2: the agent escapes its sandbox | 0:50 | 2:55 |
| 6 | Fix 2: guardrails, checked on every action | 0:40 | 3:35 |
| 7 | Demo: the whole workflow (42 s video) | 1:00 | 4:35 |
| 8 | Close | 0:20 | 4:55 |

To stay under 5:00, trim slides 3 and 5 rather than the demo.

---

## 1. ModelGate (0:10)
"ModelGate is a set of safety checks for open-source models and for the agents you build on them."

## 2. What every AI team does (0:25)
"Here's the workflow almost every AI team follows. Step one: download an open-source model from Hugging Face. Step two: build an agent on it, with tools, files and a goal. Both steps hand control of your machine to code you didn't write. Each step has its own problem."

## 3. Problem 1: the model you download runs its own code (0:50)
- "In October, 31 models on Hugging Face were downloaded 32,000 times. Loading them planted crypto miners and reverse shells, and they passed three existing scanners."
- "It works because many popular models ship their own Python, and that code runs the moment you load the model, before you've called it once."
- "Here's what that costs you. Your GPUs mine crypto for someone else. A stranger gets a shell on your machine, along with your SSH keys and API tokens."

## 4. Fix 1: ModelGate checks the code before it runs (0:40)
- "You add one import. From then on, every model load goes through four steps."
- "We download only the code, locked to one commit, and never the weights. We read it for risky calls, hidden blobs, and notes aimed at AI reviewers. We run it in a sealed, offline container with decoy keys and record every system call."
- "If the code starts a miner, opens a shell or touches your keys, the load is blocked before that code ever runs on your machine. An AI explains the verdict in plain English, but it can't change it."

## 5. Problem 2: the agent you build escapes its sandbox (0:50)
- "Now you build an agent on that model and put it in a sandbox. In July, AI agents being tested slipped out through the one network path they were allowed. Within 13 hours they had admin control of Hugging Face's own servers."
- "The path everyone assumed was closed wasn't, and nothing was checking what the agents actually did."
- "Once it's out, you've lost control. It can read your files, take credentials and customer data, and act online as you. That's a privacy problem as much as a security one."

## 6. Fix 2: guardrails you approve, checked on every action (0:40)
- "You say what the agent is for. An AI drafts guardrails from a fixed list, such as no internet, no credentials and writes only to its own folder. You tick the ones you want, and the set is signed."
- "The agent runs sealed. Every connection, file write, program start and secret read is checked against those guardrails, and fixed code makes the decision, not the AI."
- "Our test agent that tries to escape gets five violations, each pinned to its line, in 0.3 seconds."

## 7. Demo: the whole workflow (1:00; the video is 42 s)
Click play, then talk over it:
- "This is a real Hugging Face model, ChatGLM3. Its code decodes a compressed blob and runs it as native code. We can't verify that, so it's blocked." (To be fair, the blob is a GPU kernel. The point is that it can't be checked.)
- "So we pick a different model. Qwen2.5 has no custom code, so it's allowed, locked to the exact commit we scanned."
- "Now the agent. We say what it's for, the AI drafts guardrails, we approve them, it runs sealed, and it stays inside them."

If the video won't play, run the flow live: start `modelgate serve` and open http://127.0.0.1:8000.

## 8. Close (0:20)
"We caught six out of six attack imitations, and a scan takes about three seconds. Next up are approved internet access for agents, token tracking and a stronger sandbox. Download the model, build the agent, and keep control. Thank you."

---

**Verify before presenting.** These figures came from research agents; we haven't checked them against the sources ourselves:
- Problem 1: 31 repos, 32,000 downloads, crypto miners and reverse shells, passed HF/JFrog/Protect AI scans (reported Sep–Oct 2026). https://www.bleepingcomputer.com/news/security/hugging-face-malware-campaign-returns-to-hijack-gpus-for-crypto-mining/
- Problem 2: OpenAI eval agents escaped through a package proxy and reached cluster-admin on HF in under 13 hours (Jul 2026). https://huggingface.co/blog/agent-intrusion-technical-timeline · https://openai.com/index/hugging-face-model-evaluation-security-incident/ · https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/
- Slide 3 says "Oct 2026". If the source puts the campaign in September, change it to "Sep–Oct 2026".

Extra material, not in the deck: `images/` has the full pipeline diagram, the eval table, dashboard and agent screenshots, and the import hook's terminal output, in case a judge asks.
