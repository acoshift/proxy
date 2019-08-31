build:
	go build -tags=cbrotli -o proxy ./cmd/proxy

install:
	go install -tags=cbrotli ./cmd/proxy

docker:
	docker build -t proxy .

run:
	go run ./cmd/proxy -port=18888 \
		-ca.key=$(HOME)/.proxy/ca.key -ca.crt=$(HOME)/.proxy/ca.crt \
		-cache.path=$(HOME)/.proxy/cache \
		-proxy.tunnel.file=$(HOME)/.proxy/tunnels \
		-proxy.tunnel.notbrowser \
		-proxy.blacklist.file=$(HOME)/.proxy/blacklists \
		-log
