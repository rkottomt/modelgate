# ModelGate: 5-minute talk

Open `slides/deck/index.html` in a browser from inside the repo (arrow keys to move, F for fullscreen).
There are 9 slides, about **4:55** in total. The deck plays a 27-second cut on a real Hugging Face model. The 1-minute version for sharing is
https://drive.google.com/file/d/15GArDvuaBnmFyh9qrAGCWyC_mAGkBvph/view?usp=sharing

| # | Slide | Time | Running |
|---|---|---|---|
| 1 | ModelGate (title) | 0:10 | 0:10 |
| 2 | Why we built ModelGate | 0:40 | 0:50 |
| 3 | Millions run open models on their own machines | 0:25 | 1:15 |
| 4 | One import: checked before it runs | 0:30 | 1:45 |
| 5 | Three seconds in the trap | 0:45 | 2:25 |
| 6 | What makes a model unsafe | 0:40 | 3:05 |
| 7 | Demo (27 s video) | 0:45 | 3:50 |
| 8 | Already checked: 37 popular models | 0:40 | 4:35 |
| 9 | Close | 0:20 | 4:55 |

---

## 1. ModelGate (0:10)
"We're ModelGate. We run a model's code in a trap before it runs on your machine."

## 2. Why we built ModelGate (0:40)
"This is why we built ModelGate. On 29 October, Pluto Security reported 31 Hugging Face models with hidden code, downloaded about 32,000 times. The code ran automatically the moment someone loaded the model with a very common setting, `trust_remote_code=True`. It installed crypto-miners and backdoors, a second wave followed, and copies were still up days later. Hugging Face's, Protect AI's and JFrog's scanners all missed it."

## 3. Millions run open models on their own machines (0:25)
"This isn't a niche problem. More than 18 million people use Hugging Face, which hosts over 3 million models. Ollama alone says 8.9 million developers run open models locally. And about 37,000 models on Hugging Face need `trust_remote_code` to load, which means they run their own code. Every one of those loads runs on someone's own hardware, with their own keys."

## 4. One import (0:30)
"ModelGate is one import. Every load like this goes through four steps first. We fetch only the code, locked to one commit, and never the weights. We read it. We run it in a trap. Fixed rules decide, and an AI explains the result in plain English but can't change it.
We skip the weights on purpose. Weight files are already covered by existing scanners, and modern safetensors can't contain code. The gap nobody covered is the Python that ships next to the weights, and that's how the October campaign got through."

## 5. Three seconds in the trap (0:45)
"This is the hard part. We don't just read the code; we run it in a trap. The trap is **sealed**: no network, a read-only disk, no privileges, and the files are piped in, so there's no path back to your machine. It's **baited**: it looks like a GPU server, with a decoy SSH key and fake tokens that are fresh for every scan. We **exercise** the code: we tell it a GPU exists, build a tiny version of the model, run it, save it and load the tokenizer, because real payloads wait for exactly those moments. And it's **watched**: the kernel logs every connection and every program started, and Python tells us the exact line. This red row is real: the connection only happened during the forward pass, on line 19. All of that takes about three seconds per repo. If anything hangs or crashes, or Docker isn't available, the load is blocked."

## 6. What makes a model unsafe (0:40)
"Here are our exact criteria. A model is **blocked** if any one of these happens. It opens a network connection. It starts a program or a shell. It reads keys, tokens or credential files. It hides a program in memory or renames its process. It decodes hidden data and runs it. It ships compiled code we can't read. Or we can't finish checking it, because it crashed, timed out or there was no sandbox. Then there's **warn**, which means a person should look: network or shell code that didn't fire, `exec` or encoded blobs, code pulled from another repo, text aimed at AI reviewers, or parts of the model we couldn't run. A model is **allowed** only if none of that happens, and then the load is locked to the exact commit we checked. Fixed rules make these calls, never the AI."
(Maps to the code: sandbox rules SBX-NET, SBX-PROC, SBX-SENSITIVE/CANARY/EXFIL, SBX-MEMFD/PROCNAME, SBX-CRASH/TIMEOUT/NOT-ISOLATED; static rules MG100 combos, MG090 native files, MG062 blocked reference = Block. MG010–MG025, MG030, MG060, MG070, SBX-EXERCISE-INCOMPLETE = Warn.)

## 7. Demo (0:45; the video is 27 s)
Click play. While it runs:
- "This is a real model from Hugging Face, ChatGLM3. We paste it in, and it's blocked in about three seconds."
- "Here's why. Line 28 decodes a hidden base64 + bz2 blob and loads it as native code. Code that unpacks itself at runtime can't be checked, so it won't load." (To be fair, it's a GPU kernel. The point is that nobody can verify that before it runs.)
- "So we pick a different model. Qwen2.5 has no hidden code, so it's allowed and pinned to the exact commit we checked."

The 56-second video on Drive also shows the sandbox catching payloads that only fire on a GPU.

## 8. Already checked: 37 popular models (0:40)
"We didn't just test our own examples. We ran ModelGate over 37 of the most-used custom-code models on Hugging Face: Phi, Qwen, DeepSeek, GLM, InternVL, Jina, Nomic and more. It checked all 37 in 107 seconds, about 2.9 seconds each, and ran 29 of them inside the trap. None of them tried to connect out, start a program or touch keys. We also caught six out of six attack imitations. Seven models crashed on the current transformers version, so we couldn't watch them run, and ModelGate doesn't let them load. That's failing closed on purpose."
(Data: `slides/verified_models.json`; rerun with `python scan_popular.py out.json`.)

## 9. Close (0:20)
"The code runs in our trap before it runs on your GPU. Next, we want to scan every new commit on the Hub, so a model is checked before anyone downloads it. Thank you."

---

## Sources (checked 7 Nov 2026)
- Hugging Face scale: "More than 18 million developers, researchers and creators use Hugging Face to share more than 3 million models". NVIDIA blog, 3 Sep 2026: https://blogs.nvidia.com/blog/nvidia-to-acquire-hugging-face/
- Ollama: "serving 8.9 million developers" and "used by 85% of the Fortune 500". Ollama blog, 9 Jul 2026: https://ollama.com/blog/all-aboard-open-models
- Custom code on the Hub: 36,697 of 2,107,935 models (1.74%) need custom code. arXiv 2601.14163, Jan 2026: https://arxiv.org/html/2601.14163
- Pluto Security, "Hugging Face Malware Campaign: Load/Mine", 29 Oct 2026: https://pluto.security/blog/hugging-face-malware-campaign-load-mine/
  - Says "31 malicious repositories across seven Hugging Face accounts" and "more than 32,000 downloads" (downloads, not confirmed infections).
  - Says "Victims are mining into the operator's wallets right now" and that backdoors "can remain after mining stops".
- BleepingComputer (Ax Sharma), 29 Oct 2026: https://www.bleepingcomputer.com/news/security/hugging-face-malware-campaign-returns-to-hijack-gpus-for-crypto-mining/
  - Says the repos weren't flagged by "antivirus and partner tools from Protect AI and JFrog", and that anyone who loaded the models "should treat the machine as compromised".
- Hugging Face has disabled some of the repos but not all of them, so don't say they were all taken down.

## Likely judge questions
- **"Some malware waits a long time. If you only watch for 3 seconds, do you miss it?"** "The three-second run isn't our only check. We also read every line before anything runs. A payload that waits an hour still has to contain the code that opens the connection or starts the miner, and we flag that code whether or not it fires. Network access plus starting programs, or decoding hidden data and then running it, is blocked outright without running at all. Waiting hides *when* malware strikes, not *what* it contains. The remaining gap is a payload that is both delayed and well disguised. Our next step there is to fake the clock so time-delayed code fires immediately, and to run longer background checks."
- **"What if the malware is in the weights?"** "That's real, but it's a different attack path. It hides in old pickle files (`.bin`, `.pt`) that can run code when loaded. Existing scanners such as picklescan, ModelScan, Protect AI and JFrog were built for exactly that, safetensors files are pure data and can't run code, and recent PyTorch loads with `weights_only=True` by default. We cover the gap they don't: the Python code next to the weights. A simple next step is to flag repos that only ship pickle weights, or add a pickle scanner as one more stage." (Don't claim ModelGate checks weights today. It doesn't, and the README says so.)
- **"Can malware detect the sandbox and stay quiet?"** "Partly. The fake GPU, the real-looking host and the decoy keys defeat the usual checks. Code that probes the environment is flagged on its own, and payloads that wait hours are a limit we list."
- **"Why have an AI at all?"** "Only to explain. The verdict is computed before the AI runs, its output is validated, and nothing it says changes the result."
- **"What if the repo changes after the scan?"** "The scan is pinned to a commit, the load is forced to that same commit, and the cached code is re-hashed before it's imported. Approvals are signed and tied to the commit and code hash."

Extra material, not in the deck: `images/` has the full pipeline diagram, the eval table, dashboard screenshots and the import hook's terminal output.
