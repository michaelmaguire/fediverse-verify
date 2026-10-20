FROM python:3.12-slim

RUN useradd --create-home --uid 10001 verifier && mkdir /data && chown verifier /data
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache

# Commit the image was built from ("<sha>" or "<sha>-dirty"); shown in the page footer.
ARG GIT_COMMIT=unknown
ENV VERIFIER_GIT_COMMIT=${GIT_COMMIT}

USER verifier
ENV VERIFIER_DATA_DIR=/data
VOLUME /data
EXPOSE 8000
# --no-access-log: no per-request log lines (they would record IPs and proof IDs).
CMD ["uvicorn", "--factory", "fediverse_verify.app:main", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-access-log"]
