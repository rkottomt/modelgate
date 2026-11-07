"""Modeling code for TinyClean. Only defines classes; no import-time side effects."""
import math

import torch
from torch import nn
from transformers import PreTrainedModel
from transformers.utils import logging

from .configuration_tinyclean import TinyCleanConfig

logger = logging.get_logger(__name__)

_CONFIG_FOR_DOC = "TinyCleanConfig"


class TinyCleanBlock(nn.Module):
    def __init__(self, config: TinyCleanConfig):
        super().__init__()
        self.attn = nn.MultiheadAttention(config.hidden_size, num_heads=4, batch_first=True)
        self.mlp = nn.Sequential(
            nn.Linear(config.hidden_size, 4 * config.hidden_size),
            nn.GELU(),
            nn.Linear(4 * config.hidden_size, config.hidden_size),
        )
        self.ln1 = nn.LayerNorm(config.hidden_size)
        self.ln2 = nn.LayerNorm(config.hidden_size)

    def forward(self, x):
        h = self.ln1(x)
        x = x + self.attn(h, h, h, need_weights=False)[0]
        return x + self.mlp(self.ln2(x))


class TinyCleanModel(PreTrainedModel):
    config_class = TinyCleanConfig

    def __init__(self, config: TinyCleanConfig):
        super().__init__(config)
        self.embed = nn.Embedding(config.vocab_size, config.hidden_size)
        self.blocks = nn.ModuleList([TinyCleanBlock(config) for _ in range(config.num_layers)])
        self.scale = math.sqrt(config.hidden_size)
        self.post_init()

    def forward(self, input_ids: torch.LongTensor):
        x = self.embed(input_ids) * self.scale
        for block in self.blocks:
            x = block(x)
        return x
