FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn cryptography

COPY main.py .

# Render injects $PORT; fall back to 8000 locally
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
