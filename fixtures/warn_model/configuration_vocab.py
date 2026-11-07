from transformers import PretrainedConfig


class VocabNetConfig(PretrainedConfig):
    model_type = "vocabnet"

    def __init__(self, hidden_size=64, vocab_size=1000, **kwargs):
        self.hidden_size = hidden_size
        self.vocab_size = vocab_size
        super().__init__(**kwargs)
