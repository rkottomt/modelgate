FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
 && pip install --no-cache-dir "transformers>=4.44" einops sentencepiece safetensors numpy tiktoken protobuf
# The sandbox runs as uid 65534. Give it a plausible identity instead of "nobody".
RUN sed -i 's#^nobody:x:65534:65534:[^:]*:[^:]*:#mlops:x:65534:65534:ML Ops:/home/mlops:#' /etc/passwd \
 && mkdir -p /home/mlops && chown 65534:65534 /home/mlops
WORKDIR /tmp
