FROM golang:1.27 AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/myceliam-operator ./cmd

# distroless/static:nonroot's default user is already uid/gid 65532, matching
# pythonoperator's own `useradd --uid 65532`. No spire-agent binary to bundle
# here (unlike the Python image) — SPIFFE JWT-SVID fetches go through
# go-spiffe/v2's native Workload API gRPC client (internal/operatoridentity),
# not a shelled-out CLI, so there's no external binary dependency for
# MYCELIAM_OPERATOR_IDENTITY_SOURCE=spiffe to bundle at all.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/myceliam-operator /usr/local/bin/myceliam-operator

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/myceliam-operator"]
