# keycensus image: the scanner + every collector dependency + SoftHSM for the demo.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# softhsm2: a software PKCS#11 token so the demo has an "HSM" without hardware.
# Replace/add your vendor's PKCS#11 client library for real appliances.
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends softhsm2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY keycensus ./keycensus
RUN pip install ".[all]"

COPY demo ./demo

RUN useradd --system --uid 10001 --create-home keycensus \
 && mkdir -p /out /config /var/lib/softhsm/tokens \
 && chown -R keycensus:keycensus /out /var/lib/softhsm /app/demo
USER keycensus

# SoftHSM keeps its tokens here; make it writable for the demo seed.
ENV SOFTHSM2_CONF=/app/demo/softhsm2.conf

EXPOSE 9742
ENTRYPOINT ["/app/demo/entrypoint.sh"]
CMD ["serve"]
