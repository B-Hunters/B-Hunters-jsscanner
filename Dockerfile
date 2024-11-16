# Build Stage
FROM ubuntu:latest AS build

# Update and install necessary build tools
RUN apt update && apt install -y \
    curl unzip git wget python3 python3-pip build-essential \
    && wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz \
    && rm -f go1.23.2.linux-amd64.tar.gz \
    && apt clean && rm -rf /var/lib/apt/lists/*

# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

# Install Python dependencies without cache

# Install Go tools
RUN go install -v github.com/tomnomnom/anew@latest && go install github.com/i5nipe/nipejs@latest

# Runtime Stage (final smaller image using Python slim)
FROM python:3.12-slim
RUN apt update && apt install -y git && apt clean && rm -rf /var/lib/apt/lists/*
# Copy Go binaries and tools from the build stage
COPY --from=build /usr/local/go /usr/local/go
COPY --from=build /root/go/bin /root/go/bin

# Install git and unzip (required for Sublist3r and Findomain)
# RUN apt update && apt install -y git unzip \
#     && apt clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app/service/
RUN pip install --no-cache-dir b-hunters==1.1.0
RUN git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
RUN pip install  --no-cache-dir -r secretfinder/requirements.txt

# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

# Copy necessary files
COPY jsscanner jsscanner
# Default command
CMD ["python3", "-m", "jsscanner"]
