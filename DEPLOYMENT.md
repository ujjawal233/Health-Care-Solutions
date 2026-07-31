# Deployment Guide

This guide covers Docker, Render, and Railway deployment options.

Prerequisites
- Create `.env` from `.env.example` and set secure `SECRET_KEY` and any email credentials.
- Ensure `healthcare.db` (SQLite) is available or configure `DATABASE_URL` to a managed DB.

Docker (recommended)

1. Build and run:

```bash
docker build -t healthcare-app .
docker run --rm -p 8000:8000 --env-file .env -v $(pwd)/healthcare.db:/app/healthcare.db healthcare-app
```

2. Or with docker-compose:

```bash
cp .env.example .env
# edit .env
docker-compose up --build
```

Render

1. Connect your Git repository to Render.
2. Add `render.yaml` to repo root (included).
3. In Render dashboard, add environment variables used in `.env`.

Railway

1. Create a new project and connect repository.
2. Set the start command to:

```
gunicorn -c gunicorn_config.py app:app
```
3. Provide env vars in Railway GUI.

Notes
- Run `python migrate_db.py` before switching to a normalized schema.
- For production, consider replacing SQLite with Postgres and updating `DATABASE_URL`.
