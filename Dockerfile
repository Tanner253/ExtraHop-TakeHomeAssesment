# Use official Node.js runtime as base image
FROM node:18-alpine

# Set working directory in container
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code and test client
COPY src/ ./src/
COPY test-client/ ./test-client/

# Copy environment configuration (after source code)
COPY .env* ./

# Create logs directory
RUN mkdir -p logs

# Expose ports
# Port 3000: Proxy server (main access point)
# Port 3001: Target server (backend)
EXPOSE 3000 3001

# Create startup script to run both servers
RUN echo '#!/bin/sh' > start.sh && \
    echo 'echo "Starting ExtraHop Proxy SIEM..."' >> start.sh && \
    echo 'echo "Target server starting on port 3001..."' >> start.sh && \
    echo 'node src/index.js &' >> start.sh && \
    echo 'echo "Proxy server starting on port 3000..."' >> start.sh && \
    echo 'sleep 2' >> start.sh && \
    echo 'node src/proxy.js' >> start.sh && \
    chmod +x start.sh

# Start both servers
CMD ["./start.sh"] 