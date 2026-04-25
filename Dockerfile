FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VERSION=2.2.1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    HF_HUB_DISABLE_PROGRESS_BARS=1 \
    TOKENIZERS_PARALLELISM=false \
    TRANSFORMERS_VERBOSITY=error

WORKDIR /app

RUN pip install --upgrade pip && pip install "poetry==$POETRY_VERSION"

COPY pyproject.toml poetry.lock README.md ./
COPY d3fender ./d3fender

RUN poetry install --only main

ENTRYPOINT ["d3fender"]
CMD ["--help"]
