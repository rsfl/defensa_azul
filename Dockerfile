FROM python:3.14-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY policies ./policies
RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 defensa && mkdir -p /app/data && chown -R defensa:defensa /app/data
USER defensa

ENV DEFENSA_GATEWAY_HOST=0.0.0.0
ENV DEFENSA_GATEWAY_PORT=8080
EXPOSE 8080

CMD ["defensa-gateway"]

