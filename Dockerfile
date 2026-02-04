# Use a lightweight Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Expose port
EXPOSE 8000

# Run Gunicorn with Uvicorn workers
# -w 4: Spawns 4 workers (Adjust based on CPU cores)
# --forwarded-allow-ips: Essential when running behind Nginx/Load Balancer
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "app.main:app", "--bind", "0.0.0.0:8000", "--forwarded-allow-ips", "*"]