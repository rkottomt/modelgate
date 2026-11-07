"""Demo: load a model with trust_remote_code=True behind ModelGate."""
import sys

import modelgate.auto  # noqa: F401  <- one line installs the gate
from modelgate import ModelGateBlocked
from transformers import AutoModel

path = sys.argv[1] if len(sys.argv) > 1 else "fixtures/sneaky_model"
try:
    model = AutoModel.from_pretrained(path, trust_remote_code=True)
    print(f"Loaded {type(model).__name__} from {path}")
except OSError as e:
    if "no file named" in str(e):  # our fixtures ship code only, no weights
        print(f"\n\033[1;42m PASSED GATE \033[0m remote code for {path} was scanned and allowed (fixture has no weights to load)")
    else:
        raise
except ModelGateBlocked as e:
    print(f"\n\033[1;41m BLOCKED \033[0m {e}")
    sys.exit(2)
