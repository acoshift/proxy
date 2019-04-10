# proxy

Simple Proxy

## Generate Self-signed CA

### RSA

> Not support RSA yet

```sh
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -days 3650
```

### ECDSA

```sh
openssl ecparam -name prime256v1 -genkey -out ca.key -noout
openssl req -new -x509 -key ca.key -out ca.crt -days 3650
```

## TODO

- [ ] support websocket
