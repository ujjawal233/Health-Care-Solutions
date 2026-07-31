# Healthcare Flask App

Lightweight Flask application for booking and managing appointments.

Quickstart (Docker):

```bash
cp .env.example .env
# Edit .env with secure values
docker-compose build --no-cache
docker-compose up -d
```

Run locally (without Docker):

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -c "import app; print('IMPORT OK')"
```

Deployment:
- Docker + Docker Compose (recommended)
- Render: use `render.yaml` and set env vars
- Railway: use `railway.json` or set start command to `gunicorn -c gunicorn_config.py app:app`
## Welcome to our Health Care Solutions
URL https://health-care-solutions.onrender.com/
