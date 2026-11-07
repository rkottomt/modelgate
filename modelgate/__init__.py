"""ModelGate: a safety gate for Hugging Face trust_remote_code loads."""
from dotenv import load_dotenv

load_dotenv()  # loads OPENROUTER_API_KEY / OPENROUTER_MODEL from .env; never printed


class ModelGateBlocked(RuntimeError):
    """Raised when a remote-code load is blocked."""

    def __init__(self, message: str, report_path: str | None = None, report: dict | None = None):
        super().__init__(message)
        self.report_path = report_path
        self.report = report


class ModelGateWarn(ModelGateBlocked):
    """Raised on WARN unless MODELGATE_ALLOW_WARN=1."""


def install() -> None:
    from .hook import install as _install
    _install()


__all__ = ["ModelGateBlocked", "ModelGateWarn", "install"]
