# open-ctem collector, self-contained. Built locally by the installer or `docker compose build`.
FROM python:3.13.18-slim-bookworm

RUN pip install --no-cache-dir --disable-pip-version-check ldap3==2.9.1 cryptography==50.0.2 boto3==1.43.120 \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin octem \
 && install -d -o octem -g octem -m 700 /data

COPY *.py /app/

ENV OCTEM_CONF_DIR=/data/config \
    STATE_DIRECTORY=/data/state \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER octem
WORKDIR /app
VOLUME ["/data"]
ENTRYPOINT ["python", "/app/ctem_collector.py"]
CMD ["daemon"]
