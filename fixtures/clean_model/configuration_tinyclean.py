"""Configuration for TinyClean, a toy transformer."""
from transformers import PretrainedConfig


class TinyCleanConfig(PretrainedConfig):
    model_type = "tinyclean"

    def __init__(self, hidden_size=64, num_layers=2, vocab_size=1000, **kwargs):
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.vocab_size = vocab_size
        super().__init__(**kwargs)
