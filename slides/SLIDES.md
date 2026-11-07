# ModelGate: 5-minute talk

Open `slides/deck/index.html` in a browser from inside the repo (arrow keys to move, F for fullscreen).
There are 8 slides, about **4:50** in total. The deck plays the 34-second cut. The 1-minute version for sharing is
https://drive.google.com/file/d/15GArDvuaBnmFyh9qrAGCWyC_mAGkBvph/view?usp=sharing

| # | Slide | Time | Running |
|---|---|---|---|
| 1 | ModelGate (title) | 0:10 | 0:10 |
| 2 | Why we built ModelGate | 0:45 | 0:55 |
| 3 | Millions run open models on their own machines | 0:30 | 1:25 |
| 4 | One import: checked before it runs | 0:35 | 2:00 |
| 5 | Three seconds in the trap | 0:55 | 2:55 |
| 6 | Demo (34 s video) | 0:50 | 3:45 |
| 7 | Already checked: 37 popular models | 0:45 | 4:30 |
| 8 | Close | 0:20 | 4:50 |

---

## 1. ModelGate (0:10)
"We're ModelGate. We run a model's code in a trap before it runs on your machine."

## 2. Why we built ModelGate (0:45)
"This is why we built ModelGate. On 29 October, Pluto Security reported 31 Hugging Face models with hidden code, downloaded about 32,000 times. The code ran automatically the moment someone loaded the model with a very common setting, `trust_remote_code=True`. It installed crypto-miners and backdoors, a second wave followed, and copies were still up days later. Hugging Face's, Protect AI's and JFrog's scanners all missed it."

## 3. Millions run open models on their own machines (0:30)
"This isn't a niche problem. More than 18 million people use Hugging Face, which hosts over 3 million models. Ollama alone says 8.9 million developers run open models locally. And about 37,000 models on Hugging Face need `trust_remote_code` to load, which means they run their own code. Every one of those loads runs on someone's own hardware, with their own keys."

## 4. One import (0:35)
"ModelGate is one import. Every load like this goes through four steps first. We fetch only the code, locked to one commit, and never the weights. We read it. We run it in a trap. Fixed rules decide, and an AI explains the result in plain English but can't change it."

## 5. Three seconds in the trap (0:55)
"This is the hard part. We don't just read the code; we run it in a trap. The trap is **sealed**: no network, a read-only disk, no privileges, and the files are piped in, so there's no path back to your machine. It's **baited**: it looks like a GPU server, with a decoy SSH key and fake tokens that are fresh for every scan. We **exercise** the code: we tell it a GPU exists, build a tiny version of the model, run it, save it and load the tokenizer, because real payloads wait for exactly those moments. And it's **watched**: the kernel logs every connection and every program started, and Python tells us the exact line. This red row is real: the connection only happened during the forward pass, on line 19. All of that takes about three seconds per repo. If anything hangs or crashes, or Docker isn't available, the load is blocked."

## 6. Demo (0:50; the video is 34 s)
Click play. While it runs:
- "One import, and the load is refused before the code runs."
- "This next one waits. It only fires inside `forward()`, and only on a GPU. The sandbox fakes a GPU and runs the model, and the kernel catches the connection and the shell."
- "A real model with no hidden code is allowed, pinned to the exact commit we checked."

If the video won't play, run the same flow live: start `modelgate serve`, open http://127.0.0.1:8000 and click "deferred model".

## 7. Already checked: 37 popular models (0:45)
"We didn't just test our own examples. We ran ModelGate over 37 of the most-used custom-code models on Hugging Face: Phi, Qwen, DeepSeek, GLM, InternVL, Jina, Nomic and more. It checked all 37 in 107 seconds, about 2.9 seconds each, and ran 29 of them inside the trap. None of them tried to connect out, start a program or touch keys. We also caught six out of six attack imitations. Seven models crashed on the current transformers version, so we couldn't watch them run, and ModelGate doesn't let them load. That's failing closed on purpose."
(Data: `slides/verified_models.json`; rerun with `python scan_popular.py out.json`.)

## 8. Close (0:25)
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
- **"Can malware detect the sandbox and stay quiet?"** "Partly. The fake GPU, the real-looking host and the decoy keys defeat the usual checks. Code that probes the environment is flagged on its own, and payloads that wait hours are a limit we list."
- **"Why have an AI at all?"** "Only to explain. The verdict is computed before the AI runs, its output is validated, and nothing it says changes the result."
- **"What if the repo changes after the scan?"** "The scan is pinned to a commit, the load is forced to that same commit, and the cached code is re-hashed before it's imported. Approvals are signed and tied to the commit and code hash."

Extra material, not in the deck: `images/` has the full pipeline diagram, the eval table, dashboard screenshots and the import hook's terminal output.
