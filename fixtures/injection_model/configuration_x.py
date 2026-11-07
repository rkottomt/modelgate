from transformers import PretrainedConfig


class XNetConfig(PretrainedConfig):
    model_type = "xnet"

    def __init__(self, hidden_size=64, **kwargs):
        self.hidden_size = hidden_size
        super().__init__(**kwargs)
