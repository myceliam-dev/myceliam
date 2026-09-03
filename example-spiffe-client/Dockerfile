FROM golang:1.27 AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/example-spiffe-client .

FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/example-spiffe-client /usr/local/bin/example-spiffe-client

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/example-spiffe-client"]
