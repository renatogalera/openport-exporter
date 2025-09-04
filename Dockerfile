# Stage 1: Build the application
FROM golang:1.25-bookworm AS builder
ARG VERSION=""
ARG REVISION=""
ARG BRANCH=""
ARG DATE=""

# Install necessary packages including libpcap-dev
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the application source code
COPY . .

# Compile the binary
RUN go build -ldflags "-s -w \
    -X github.com/prometheus/common/version.Version=${VERSION} \
    -X github.com/prometheus/common/version.Revision=${REVISION} \
    -X github.com/prometheus/common/version.Branch=${BRANCH} \
    -X github.com/prometheus/common/version.BuildDate=${DATE}" \
    -o openport-exporter .

# Stage 2: Create the final image with the binary
FROM debian:bookworm-slim

# Install necessary packages including libpcap-dev
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev nmap libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PORT=9919

# Create a directory for the binary
WORKDIR /app/

# Copy the binary from the build stage
COPY --from=builder /app/openport-exporter .

# Create non-root user and grant only CAP_NET_RAW on the binary
RUN useradd -r -u 10001 -g root openport \
    && setcap cap_net_raw+eip /app/openport-exporter

USER openport

# Expose the port the application will use
EXPOSE $PORT

# Command to run the application
CMD ["/app/openport-exporter"]
