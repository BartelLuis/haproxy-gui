FROM haproxy:2.9-alpine

# python3: Web-Backend | lego: Let's Encrypt mit DNS-Validierung | socat: HAProxy Runtime-Socket
RUN apk add --no-cache python3 py3-pip lego socat bash curl \
    && python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    HG_DATA=/data \
    PYTHONUNBUFFERED=1

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app
COPY app ./app
COPY bootstrap /bootstrap
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080 80 443
VOLUME /data

ENTRYPOINT ["/entrypoint.sh"]
