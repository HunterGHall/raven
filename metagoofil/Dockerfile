FROM docker.io/python:3.13.7-slim-bookworm

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Specify the GID and UID of the container user that will run metagoofil.
RUN addgroup --gid 1000 --system metagoofil \
    && adduser --uid 1000 --system --ingroup metagoofil metagoofil

RUN apt-get update && apt-get install --no-install-recommends -y \
    git \
    # Cleaning up unused files.
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/opsdisk/metagoofil /app

# Update pip and setuptools.
RUN pip install --upgrade pip setuptools

# Install Python dependencies.
RUN pip install --no-cache-dir -r requirements.txt

RUN chown -R metagoofil:metagoofil /app

USER metagoofil

ENTRYPOINT ["python", "metagoofil.py", "-o", "/app/data"]
