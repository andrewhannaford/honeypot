FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create directories for persistent data
RUN mkdir -p logs data

EXPOSE 22 21 23 80 8080

CMD ["python", "main.py"]
