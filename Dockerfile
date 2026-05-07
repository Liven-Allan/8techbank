FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Ensure data directory exists
RUN mkdir -p /app/data

EXPOSE 5000

ENV FLASK_ENV=development
ENV FLASK_DEBUG=1

ENTRYPOINT ["python", "app.py"]
