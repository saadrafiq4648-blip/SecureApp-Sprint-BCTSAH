FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash appuser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN make -C native clean all && chown -R appuser:appuser /app /tmp
USER appuser
EXPOSE 5000
CMD ["python3", "-m", "src.app"]
