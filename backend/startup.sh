#!/bin/bash
# Azure App Service startup script
# Packages are pre-installed in CI and deployed with the zip
export PYTHONPATH="/home/site/wwwroot/.python_packages/lib/site-packages:$PYTHONPATH"
gunicorn --bind 0.0.0.0:8000 --timeout 120 wsgi:app
