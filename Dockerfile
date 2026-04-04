FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p logs data
# EXPOSE all service ports
EXPOSE 22 21 23 25 80 6379 8080
CMD ["python", "main.py"]
