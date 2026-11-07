from transformers import PretrainedConfig


class LazyNetConfig(PretrainedConfig):
    model_type = "lazynet"

    def __init__(self, hidden_size=64, num_hidden_layers=2, vocab_size=1000, **kwargs):
        self.hidden_size = hidden_size
        self.num_hidden_layers = num_hidden_layers
        self.vocab_size = vocab_size
        super().__init__(**kwargs)
