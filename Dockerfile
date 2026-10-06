FROM python@sha256:a2bc8c35469b6fe37735f7c4dae39049470b2ce068e73f799c02452de31d24c6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install --upgrade pip==26.2.0 setuptools==78.1.1 wheel==0.46.2 && \
    python -m pip install -r requirements.txt && \
    python -m pip uninstall -y wheel setuptools jaraco.context && \
    useradd --create-home --shell /usr/sbin/nologin appuser

COPY app ./app
COPY notify ./notify

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]



