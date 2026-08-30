# Stage 1: Build the application
FROM golang:1.27.0-bookworm@sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452 AS builder
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
FROM debian:bookworm-20260824-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

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
