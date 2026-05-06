FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt --no-cache-dir

COPY app.py bot_detection.py ./
COPY templates/ templates/
# data/ is NOT copied — it is mounted via PVC at runtime (SQLite + MaxMind DB)

ENV PORT=5000
EXPOSE 5000

CMD ["python", "app.py"]
