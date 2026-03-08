#!/bin/bash
cd /home/site/wwwroot
gunicorn --bind=0.0.0.0:$PORT --timeout 600 app:app