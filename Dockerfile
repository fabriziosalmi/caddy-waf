# Use a Go base image to build the Caddy binary
FROM golang:1.22.3-alpine AS builder

# Install git and xcaddy (required for cloning the repository and building Caddy)
RUN apk add --no-cache git wget && \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Set the working directory inside the container
WORKDIR /app

# Clone the caddy-waf repository
RUN git clone https://github.com/fabriziosalmi/caddy-waf.git

# Navigate into the caddy-waf directory
WORKDIR /app/caddy-waf

# Fetch and install the required Go modules (including Caddy v2)
RUN go get -v github.com/caddyserver/caddy/v2 github.com/caddyserver/caddy/v2/caddyconfig/caddyfile github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile github.com/caddyserver/caddy/v2 github.com/caddyserver/caddy/v2/modules/caddyhttp github.com/oschwald/maxminddb-golang github.com/fsnotify/fsnotify github.com/fabriziosalmi/caddy-waf

# Clean up and update the go.mod file
RUN go mod tidy

# Download the GeoLite2 Country database
RUN wget https://git.io/GeoLite2-Country.mmdb

# Clean up previous build artifacts
RUN rm -rf buildenv_*

# Build Caddy with the caddy-waf module
RUN xcaddy build --with github.com/fabriziosalmi/caddy-waf=./

# ---  Runtime Stage (smaller final image) ---
FROM alpine:latest

# Set the working directory
WORKDIR /app

# Copy the built Caddy binary from the builder stage
COPY --from=builder /app/caddy-waf/caddy /usr/bin/caddy

# Copy the GeoLite2 database, rules, blacklists, and Caddyfile
COPY --from=builder /app/caddy-waf/GeoLite2-Country.mmdb /app/
COPY --from=builder /app/caddy-waf/rules.json /app/
COPY --from=builder /app/caddy-waf/ip_blacklist.txt /app/
COPY --from=builder /app/caddy-waf/dns_blacklist.txt /app/
COPY Caddyfile /app/

# Set the user to caddy for security
RUN addgroup -S caddy && adduser -S -G caddy caddy

# Change ownership of the /app to the caddy user
RUN chown -R caddy:caddy /app

USER caddy

# Expose HTTP ports (adjust as needed)
EXPOSE 8080

# Run Caddy
CMD ["caddy", "run", "--config", "/app/Caddyfile"]
