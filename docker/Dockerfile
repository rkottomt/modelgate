FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
 && pip install --no-cache-dir "transformers>=4.44" einops sentencepiece safetensors numpy
RUN useradd -m -u 1000 sandbox
USER sandbox
WORKDIR /work
