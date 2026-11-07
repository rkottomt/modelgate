"""A legit-looking model with ONE questionable pattern: an optional runtime download
helper that is never called on load. Single finding => WARN, not BLOCK."""
from torch import nn
from transformers import PreTrainedModel

from .configuration_vocab import VocabNetConfig


def fetch_extra_vocab(url: str) -> bytes:
    import requests  # only used if a user explicitly calls this helper
    return requests.get(url, timeout=10).content


class VocabNetModel(PreTrainedModel):
    config_class = VocabNetConfig

    def __init__(self, config):
        super().__init__(config)
        self.embed = nn.Embedding(config.vocab_size, config.hidden_size)
        self.post_init()

    def forward(self, input_ids):
        return self.embed(input_ids)
