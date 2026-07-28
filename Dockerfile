FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libgl1 \
    libglib2.0-0 \
    libgomp1 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    tesseract-ocr \
    tesseract-ocr-eng \
    libzbar0 \
    libpoppler-cpp-dev \
    wget \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Hyperledger Fabric peer binary + config
RUN wget -q https://github.com/hyperledger/fabric/releases/download/v2.5.0/hyperledger-fabric-linux-amd64-2.5.0.tar.gz && \
    tar xzf hyperledger-fabric-linux-amd64-2.5.0.tar.gz && \
    mv bin/peer /usr/local/bin/peer && \
    mv config /app/fabric-config && \
    rm -rf hyperledger-fabric-linux-amd64-2.5.0.tar.gz bin

ENV FABRIC_BIN_PATH=/usr/local/bin
ENV FABRIC_CFG_PATH=/app/fabric-config

COPY requirements.txt .
COPY fabric-certs/ /app/fabric-certs/
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/uploads /app/data

EXPOSE 5000

ENV FLASK_ENV=production
ENV BGV_LEDGER_PATH=/app/data/bgv_ledger.ndjson

CMD ["python", "server.py"]
