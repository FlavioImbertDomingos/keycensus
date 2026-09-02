FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
RUN useradd --system --uid 10002 --no-create-home mock
USER mock
EXPOSE 8800 8443
CMD ["python", "app.py"]
