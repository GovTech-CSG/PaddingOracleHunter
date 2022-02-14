FROM python:3.10-slim as build-env
COPY . /app
WORKDIR /app
RUN groupadd -g 1000 testuser && useradd -r -u 1000 -g testuser testuser && \
    apt update && apt install patch && \
    pip install -r requirements.txt    
USER testuser
CMD ["/usr/local/bin/gunicorn", "--bind", "0.0.0.0:8000", "oracle:app"]