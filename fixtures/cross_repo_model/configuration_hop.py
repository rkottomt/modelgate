"""Configuration for HopNet. The model class lives in ANOTHER repo (see config.json auto_map)."""
from transformers import PretrainedConfig


class HopNetConfig(PretrainedConfig):
    model_type = "hopnet"

    def __init__(self, hidden_size=64, **kwargs):
        self.hidden_size = hidden_size
        super().__init__(**kwargs)
