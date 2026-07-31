# Gunicorn configuration for production
bind = '0.0.0.0:8000'
workers = 2
worker_class = 'sync'
accesslog = '-'
errorlog = '-'
loglevel = 'info'
timeout = 120
