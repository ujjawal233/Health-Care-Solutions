FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install build deps and cleanup
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

ENV FLASK_ENV=production
EXPOSE 8000

CMD ["gunicorn", "-c", "gunicorn_config.py", "app:app"]
