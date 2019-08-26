build:
	go build -tags=cbrotli -o proxy ./cmd/proxy

install:
	go install -tags=cbrotli ./cmd/proxy
