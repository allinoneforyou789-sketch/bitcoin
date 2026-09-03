# syntax=docker/dockerfile:1
FROM python:3.11-slim

# keep container minimal but functional
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# install deps first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy the rest
COPY . .

# run the miner
CMD ["python", "-u", "miner.py"]