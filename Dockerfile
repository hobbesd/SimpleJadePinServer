# Python base image, pinned by digest so a rebuild always starts from the
# same, known image (python:3.12-alpine as of 2026-11-12). To pick up newer
# Python/Alpine fixes, look up the current digest of the tag and replace it:
#   docker pull python:3.12-alpine && docker image inspect --format '{{index .RepoDigests 0}}' python:3.12-alpine
FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89

# Set the working directory
WORKDIR /app

# Unbuffered stdout so event lines reach "docker logs" immediately; no
# bytecode files, so the image also runs with a read-only root filesystem
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Copy necessary files
COPY SimpleJadePinServer.py index.html oracle_qr.html jade-codec.js app.js oracle_qr.js qrcode.js html5-qrcode.min.js apple-touch-icon.png favicon.png requirements.txt LICENSE /app/
COPY LICENSES /app/LICENSES

# Install dependencies (version + SHA-256 hashes of all official PyPI artifacts pinned)
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Expose the required port
EXPOSE 4443

# Set the entrypoint to the main command, so additional args can be passed in docker-compose.yml
ENTRYPOINT ["python3", "/app/SimpleJadePinServer.py"]
