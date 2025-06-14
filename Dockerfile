# Build stage
FROM python:3.11-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev python3-dev make

# Copy and install requirements
COPY requirements.txt .
RUN pip3 install --user -r requirements.txt

# Final stage
FROM python:3.11-alpine

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY run.py .

ENTRYPOINT ["python3", "run.py"]
CMD ["poll"]