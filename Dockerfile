# Stage 1: Build the application
FROM golang:1.23-bookworm AS builder

# Install necessary packages including libpcap-dev
RUN apt-get update && apt-get install -y libpcap-dev

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the application source code
COPY . .

# Compile the binary
RUN go build -o openport-exporter .

# Stage 2: Create the final image with the binary
FROM debian:bookworm-slim

# Install necessary packages including libpcap-dev
RUN apt-get update && apt-get install -y libpcap-dev nmap

# Set environment variables
ENV PORT=9919

# Create a directory for the binary
WORKDIR /app/

# Copy the binary from the build stage
COPY --from=builder /app/openport-exporter .

# Expose the port the application will use
EXPOSE $PORT

# Command to run the application
CMD ["/app/openport-exporter"]