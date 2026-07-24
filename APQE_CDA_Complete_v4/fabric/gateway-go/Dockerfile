FROM golang:1.25-alpine AS build

RUN apk add --no-cache ca-certificates git
WORKDIR /src

# Fetch directly from the pinned upstream repositories because some networks
# block Google's Go proxy/checksum endpoints.
ENV GOTOOLCHAIN=local \
    GOPROXY=direct \
    GOSUMDB=off

COPY go.mod ./
COPY *.go ./

RUN go mod tidy
RUN go test ./...
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /apqe-gateway .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /apqe-gateway /usr/local/bin/apqe-gateway
ENTRYPOINT ["/usr/local/bin/apqe-gateway"]
