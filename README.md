# proxy

Local Cache Proxy Server

## Setup

### macOS

```sh
# Install brotli
brew install brotli

# Install proxy
make install

# Setup config directory
mkdir -p ~/.proxy
cd !$
touch tunnels blacklists
mkdir cache

# Generate Self-signed ECDSA CA
openssl ecparam -name prime256v1 -genkey -out ca.key -noout
openssl req -new -x509 -key ca.key -out ca.crt -days 3650

# Run proxy
proxy \
    -port=18888 \
    -ca.key=$HOME/.proxy/ca.key -ca.crt=$HOME/.proxy/ca.crt \
    -cache.path=$HOME/.proxy/cache \
    -proxy.tunnel.file=$HOME/.proxy/tunnels \
    -proxy.tunnel.notbrowser \
    -proxy.blacklist.file=$HOME/.proxy/blacklists \
    -log
```
