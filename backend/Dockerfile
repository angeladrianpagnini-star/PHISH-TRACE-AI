FROM python:3.13.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install --no-cache-dir -r requirements.txt

RUN groupadd --system phishtrace \
    && useradd --system --gid phishtrace phishtrace \
    && mkdir -p /app/data \
    && chown -R phishtrace:phishtrace /app

COPY --chown=phishtrace:phishtrace main.py .

USER phishtrace

EXPOSE 8000

CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
