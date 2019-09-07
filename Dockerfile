FROM gcr.io/moonrhythm-containers/golang:1.13.0-alpine3.10 as build

ENV GOPROXY=https://proxy.golang.org
WORKDIR /workspace

ADD go.mod go.sum /
RUN go mod download

ADD . .

RUN go build -o proxy -tags cbrotli -ldflags "-w -s" ./cmd/proxy

# ---

FROM gcr.io/moonrhythm-containers/alpine:3.10

RUN mkdir -p /app
WORKDIR /app

COPY --from=build /workspace/proxy ./
ENTRYPOINT ["/app/proxy"]
